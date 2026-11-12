#!/usr/bin/env bash
# shellcheck disable=SC2034
# Fixed target verified against Red Hat release metadata on 2026-11-12.
OCP_RELEASE=5.0.1
OCP_MINOR=${OCP_RELEASE%.*}
OCP_ARCH=amd64
LOCAL_REPOSITORY=openshift${OCP_RELEASE//./}
STATE_ROOT=${STATE_ROOT:-/opt/ocp5}
BUNDLE_DIR=${BUNDLE_DIR:-/opt/ocp5-bundle}
MIRROR_DIR=$BUNDLE_DIR/images
IMAGESET_CONFIG=$BUNDLE_DIR/imagesetconfiguration.json
TOOLS_DIR=$BUNDLE_DIR/tools
BIN_DIR=$STATE_ROOT/bin
INSTALL_DIR=$STATE_ROOT/install
HTTP_ROOT=/var/www/html/ocp5
CLIENT_ARCHIVE=openshift-client-linux-amd64-rhel9-${OCP_RELEASE}.tar.gz
INSTALLER_ARCHIVE=${INSTALLER_ARCHIVE:-openshift-install-linux.tar.gz}
RELEASE_SOURCE=quay.io/openshift-release-dev/ocp-release
COMPONENT_SOURCE=quay.io/openshift-release-dev/ocp-v5.0-art-dev
HARBOR_ARCHIVE=${HARBOR_ARCHIVE:-/opt/harbor-offline-installer-v2.12.2.tgz}
DOCKER_ARCHIVE=${DOCKER_ARCHIVE:-/opt/docker-ce.tar.gz}
