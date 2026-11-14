// Evaluate version ranges and CEL using the same libraries and environment as OLM.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/blang/semver/v4"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

type Request struct {
	Op         string                     `json:"op"`
	Versions   []string                   `json:"versions"`
	Range      string                     `json:"range"`
	Rule       string                     `json:"rule"`
	Properties [][]map[string]interface{} `json:"properties"`
}

func evaluate(r Request) (interface{}, error) {
	if r.Op == "range" || r.Op == "sort" {
		versions := make([]semver.Version, len(r.Versions))
		for i, v := range r.Versions {
			parsed, err := semver.ParseTolerant(v)
			if err != nil {
				return nil, err
			}
			versions[i] = parsed
		}
		if r.Op == "sort" {
			order := make([]int, len(versions))
			for i := range order {
				order[i] = i
			}
			sort.SliceStable(order, func(i, j int) bool { return versions[order[i]].GT(versions[order[j]]) })
			return order, nil
		}
		check, err := semver.ParseRange(r.Range)
		if err != nil {
			return nil, err
		}
		result := make([]bool, len(versions))
		for i, v := range versions {
			result[i] = check(v)
		}
		return result, nil
	}
	if r.Op != "cel" {
		return nil, fmt.Errorf("unknown operation %q", r.Op)
	}
	env, err := cel.NewEnv(
		cel.Variable("properties", cel.ListType(cel.MapType(cel.StringType, cel.DynType))),
		cel.Function("semver_compare", cel.Overload("semver_compare", []*cel.Type{cel.DynType, cel.DynType}, cel.IntType,
			cel.BinaryBinding(func(a, b ref.Val) ref.Val {
				av, ae := semver.ParseTolerant(fmt.Sprint(a.Value()))
				bv, be := semver.ParseTolerant(fmt.Sprint(b.Value()))
				if ae != nil || be != nil {
					return types.NewErr("invalid semver_compare argument")
				}
				return types.Int(av.Compare(bv))
			}))),
	)
	if err != nil {
		return nil, err
	}
	ast, issues := env.Compile(r.Rule)
	if issues.Err() != nil {
		return nil, issues.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("CEL rule must return bool")
	}
	program, err := env.Program(ast, cel.CostLimit(1000000))
	if err != nil {
		return nil, err
	}
	result := make([]bool, len(r.Properties))
	for i, props := range r.Properties {
		value, _, evalErr := program.Eval(map[string]interface{}{"properties": props})
		// Like OLM, a rule that errors for a particular provider does not match it.
		result[i] = evalErr == nil && value == types.True
	}
	return result, nil
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 65536), 128*1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var req Request
		err := json.Unmarshal(scanner.Bytes(), &req)
		var value interface{}
		if err == nil {
			value, err = evaluate(req)
		}
		if err != nil {
			_ = encoder.Encode(map[string]string{"error": err.Error()})
		} else {
			_ = encoder.Encode(map[string]interface{}{"result": value})
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
