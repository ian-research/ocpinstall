# ocpinstall
Use bash scripts for quick and easy install openshift

该脚本会配置镜像仓库，DNS域名解析，Haproxy，chronyd，openshift ignition启动文件

在使用该脚本前，您需要首先离线下载openshift安装包，离线下载方式参考
https://mp.weixin.qq.com/s/tptiCSCIa9JJj3aMDpUJow
将脚本内的imagesetconfigurtaion.yaml部分替换为离线下载openshift包时使用的yaml，确保两边内容一致。

脚本需运行在rhel9操作系统之上，请先最小化安装rhel9，确保opt目录有至少200G以上可用空间，mnt目录有100G以上可用空间。

脚本将通过hostname -i命令获取首个ip作为后续的配置使用的ip，因此在运行脚本时，请确保仅有一个ip

事先准备的离线包包括，请都存放在opt目录下：
  
  ["离线镜像包"]="/opt/mirror_000001.tar"
  
  ["Harbor安装包"]="/opt/harbor-offline-installer-v2.12.2.tgz"
  
  ["oc-mirror包"]="/opt/oc-mirror.rhel9.tar.gz"
  
  ["openshift-client包"]="/opt/openshift-client-linux-4.18.10.tar.gz"
  
  ["openshift-install包"]="/opt/openshift-install-linux-4.18.10.tar.gz"
  
  ["docker-ce安装包"]="/opt/docker-ce.tar.gz"  包内容包括 containerd.io-1.7.27-3.1.el9.x86_64.rpm docker-ce-28.0.4-1.el9.x86_64.rpm docker-ce-rootless-extras-28.0.4-1.el9.x86_64.rpm docker-buildx-plugin-0.22.0-1.el9.x86_64.rpm docker-ce-cli-28.0.4-1.el9.x86_64.rpm docker-compose-plugin-2.34.0-1.el9.x86_64.rpm
