## K8S Requirement

本文中使用的各组件为当前最新版本，存在版本特性差异，几处小问题还有待解决，仅为记录学习过程。

### Roles

|     IP     | Hostname | Roles   |
|   :---:   |   :---:  | :---   |
| 10.0.77.16 | repo.k8s.com | Harbor（私有镜像仓库）|
| 10.0.77.17 | n1.k8s.com | master node kube-apiserver kube-controller-manager kube-scheduler kubectl kubelet flannel etcd|
| 10.0.77.18 | n2.k8s.com | master node kube-apiserver kube-controller-manager kube-scheduler kubectl kubelet flannel etcd |
| 10.0.77.19 | n3.k8s.com | master node kube-apiserver kube-controller-manager kube-scheduler kubectl kubelet flannel etcd |

### 各组件版本

+ CentOS 7.3
+ etcd v3.3.0
+ kubernetes v1.9.3
+ Flannel v0.10.0
+ Docker v17.12.0-ce
+ go v1.9.4

### System Configuration

1. 禁用selinux
2. 关闭firewalld
3. 配置/etc/hosts文件中非lo端口IP
4. 关闭SWAP：swapoff -a & 注释 /etc/fstab 文件中 swap 的自动挂载 & free -m
4. 配置NTP校时服务
5. shell> cat /etc/sysctl.d/k8s.conf

```bash
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
vm.swappiness=0
   
shell> modprobe br_netfilter
shell> ls /proc/sys/net/bridge
shell> sysctl -p /etc/sysctl.d/k8s.conf
```

## [节点安装Docker](https://acquaai.github.io/2018/02/09/harbor/)

## Download Kubernetes Bundle

[CHANGELOG](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG.md)下载，kubernetes-server-linux-amd64.tar.gz包含了client(`kubectl`)二进制文件。

## k8s所需组件TLS证书和密匙

### 创建CA证书和私钥

继使用在创建 [Harbor](https://acquaai.github.io/2018/02/09/harbor/) 中的 CA 证书。

### 创建etcd证书和私钥

```json
shell > vi etcd-csr.json
{
    "CN": "kubernetes", 
    "hosts": [
        "127.0.0.1", 
        "10.0.77.17", 
        "10.0.77.18", 
        "10.0.77.19", 
        "n1.k8s.com", 
        "n2.k8s.com", 
        "n3.k8s.com"
    ], 
    "key": {
        "algo": "rsa", 
        "size": 2048
    }, 
    "names": [
        {
            "C": "CN", 
            "ST": "Shenzhen", 
            "L": "Shenzhen", 
            "O": "k8s", 
            "OU": "System"
        }
    ]
}
```

```bash
shell> cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes etcd-csr.json | cfssljson -bare etcd

ls etcd*
etcd.csr  etcd-csr.json  etcd-key.pem  etcd.pem
```

### 创建kube-apiserver证书和私钥

**创建apiserver证书签名请求配置**

```json
shell> vi apiserver-csr.json
{
    "CN": "kubernetes", 
    "hosts": [
        "127.0.0.1", 
        "10.0.77.16", 
        "10.0.77.17", 
        "10.0.77.18", 
        "10.0.77.19", 
        "10.7.252.61", 
        "10.254.0.1", 
        "kubernetes", 
        "kubernetes.default", 
        "kubernetes.default.svc", 
        "kubernetes.default.svc.cluster", 
        "kubernetes.default.svc.cluster.local"
    ], 
    "key": {
        "algo": "rsa", 
        "size": 2048
    }, 
    "names": [
        {
            "C": "CN", 
            "ST": "Shenzhen", 
            "L": "Shenzhen", 
            "O": "k8s", 
            "OU": "System"
        }
    ]
}
```

若有HAProxy代理，需要将VIP 10.7.252.61写入hosts。

**生成apiserver证书和私钥**

```bash
shell> cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json \
-profile=kubernetes apiserver-csr.json | cfssljson -bare apiserver
shell> ls apiserver*
apiserver.csr  apiserver-csr.json  apiserver-key.pem  apiserver.pem
```

### 创建kubernetes-admin证书和私钥

**创建admin证书签名请求**

```json
shell> vi admin-csr.json
{
    "CN": "admin", 
    "hosts": [], 
    "key": {
        "algo": "rsa", 
        "size": 2048
    }, 
    "names": [
        {
            "C": "CN", 
            "ST": "Shenzhen", 
            "L": "Shenzhen", 
            "O": "system:masters", 
            "OU": "System"
        }
    ]
}
```

**生成admin证书和私钥**

```bash
shell> cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin

shell> ls admin*
admin.csr  admin-csr.json  admin-key.pem  admin.pem
```

### 创建kube-proxy证书和私钥

**kube-proxy证书的签名请求配置**

```json
shell> vi kube-proxy-csr.json
{
    "CN": "system:kube-proxy", 
    "hosts": [], 
    "key": {
        "algo": "rsa", 
        "size": 2048
    }, 
    "names": [
        {
            "C": "CN", 
            "ST": "Shenzhen", 
            "L": "Shenzhen", 
            "O": "k8s", 
            "OU": "System"
        }
    ]
}
```

**生成kube-proxy客户端证书和私钥**

```bash
shell> cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy

shell> ls kube-proxy*
kube-proxy.csr  kube-proxy-csr.json  kube-proxy-key.pem  kube-proxy.pem
```

### 检验证书

以apiserver证书为例

**使用openssl命令**

```bash
shell> openssl x509 -noout -text -in apiserver.pem
```

**使用cfssl-certinfo命令**

```bash
shell> cfssl-certinfo -cert apiserver.pem
```

+ 确认 issuer 字段内容与ca-csr.json一致。
+ 确认 subject 字段内容与apiserver-csr.json一致。
+ 确认 X509v3 Subject Alternative Name 字段内容与apiserver-csr.json一致。
+ 确认 X509v3 Key Usage、Extended Key Usage 字段内容与ca-config.json中 kubernetes profile一致。

### 分发证书

将/root/cfssl下生成的证书和密钥(.pem)拷贝到所有节点的/etc/kubernetes/ssl目录下。

```bash
shell> mkdir -p /etc/kubernetes/ssl
shell> cp /root/cfssl/*.pem /etc/kubernetes/ssl/
n2/n3> scp root@n1.k8s.com:/etc/kubernetes/ssl/*.pem /etc/kubernetes/ssl/
```

## 部署ETCD集群

### 下载二进制文件

```bash
shell> wget https://github.com/coreos/etcd/releases/download/v3.3.0/etcd-v3.3.0-linux-amd64.tar.gz
shell> tar xzvf etcd-v3.3.0-linux-amd64.tar.gz 
shell> cp -p etcd-v3.3.0-linux-amd64/etcd* /usr/local/bin/
```

### 创建etcd的systemd unit文件

k8s所有节点都需要安装etcd，注意替换`ETCD_NAME和INTERNAL_IP`变量的值，指定etcd的工作目录和数据目录为`/var/lib/etcd`，需要在启动服务前创建。

```bash
shell> mkdir -p /var/lib/etcd
```

`shell> export ETCD_NAME=n1.k8s.com`
`shell> export INTERNAL_IP=10.0.77.17`

```bash
shell> cat > /usr/lib/systemd/system/etcd.service <<EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/coreos

[Service]
Type=notify
WorkingDirectory=/var/lib/etcd/
ExecStart=/usr/local/bin/etcd \
  --name ${ETCD_NAME} \
  --cert-file /etc/kubernetes/ssl/etcd.pem \
  --key-file /etc/kubernetes/ssl/etcd-key.pem \
  --peer-cert-file /etc/kubernetes/ssl/etcd.pem \
  --peer-key-file /etc/kubernetes/ssl/etcd-key.pem \
  --trusted-ca-file /etc/kubernetes/ssl/ca.pem \
  --peer-trusted-ca-file /etc/kubernetes/ssl/ca.pem \
  --initial-advertise-peer-urls https://${INTERNAL_IP}:2380 \
  --listen-peer-urls https://${INTERNAL_IP}:2380 \
  --listen-client-urls https://${INTERNAL_IP}:2379,https://127.0.0.1:2379 \
  --advertise-client-urls https://${INTERNAL_IP}:2379 \
  --initial-cluster-token etcd-cluster-0 \
  --initial-cluster n1.k8s.com=https://10.0.77.17:2380,n2.k8s.com=https://10.0.77.18:2380,n3.k8s.com=https://10.0.77.19:2380 \
  --initial-cluster-state new \
  --data-dir /var/lib/etcd
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

### 启动etcd服务

```bash
shell> systemctl daemon-reload
shell> systemctl start etcd
shell> systemctl status etcd -l --no-pager
shell> journalctl -f -u etcd
```

### 验证服务

```bash
shell> etcdctl \
  --endpoints=https://n1.k8s.com:2379,https://n2.k8s.com:2379,https://n3.k8s.com:2379 \
  --ca-file /etc/kubernetes/ssl/ca.pem \
  --cert-file /etc/kubernetes/ssl/etcd.pem \
  --key-file /etc/kubernetes/ssl/etcd-key.pem \
  cluster-health
member 4752126a8c57db3f is healthy: got healthy result from https://10.0.77.19:2379
member 820218dcd00198b0 is healthy: got healthy result from https://10.0.77.18:2379
member b4393c99729320b8 is healthy: got healthy result from https://10.0.77.17:2379
cluster is healthy

shell> systemctl enable etcd
```

## 创建kubeconfig文件

### k8s二进制文件

```bash
shell> tar xzvf kubernetes-server-linux-amd64.tar.gz
shell> cd kubernetes/server/bin/
shell> cp {kube-apiserver,kube-controller-manager,kube-scheduler,kubelet,kube-proxy,kubectl} /usr/local/bin/
```

### 创建kubeconfig文件

kubernetes 1.4 开始支持由 kube-apiserver 为客户端生成 TLS 证书的 TLS Bootstrapping 功能，因此不再需要为每个客户端生成证书。（目前仅支持为 kubelet 生成证书）

#### 创建 TLS Bootstrapping Token

Token可以是任意的包涵128bit的字符串，使用随机数生成器生成。

```bash
shell>  export BOOTSTRAP_TOKEN=$(head -c 16 /dev/urandom | od -An -t x | tr -d ' ')

shell> cat > token.csv <<EOF
${BOOTSTRAP_TOKEN},kubelet-bootstrap,10001,"system:kubelet-bootstrap"
EOF
```

将 token.csv 文件分发到所有节点的 /etc/kubernetes/ 下。

```bash
shell> scp root@n1.k8s.com:/etc/kubernetes/token.csv /etc/kubernetes/
```

#### 创建kubelet bootstrapping kubeconfig文件

```bash
shell> cd /etc/kubernetes/
shell> export KUBE_APISERVER="https://10.0.77.17:6443"

设置集群参数
shell> kubectl config set-cluster kubernetes \
     --certificate-authority=/etc/kubernetes/ssl/ca.pem \
     --embed-certs=true \
     --server=${KUBE_APISERVER} \
     --kubeconfig=bootstrap.kubeconfig
     
设置客户端认证参数
shell> kubectl config set-credentials kubelet-bootstrap \
     --token=${BOOTSTRAP_TOKEN} \
     --kubeconfig=bootstrap.kubeconfig
     
设置上下文参数
shell> kubectl config set-context default \
     --cluster=kubernetes \
     --user=kubelet-bootstrap \
     --kubeconfig=bootstrap.kubeconfig
     
设置默认上下文
shell> kubectl config use-context default --kubeconfig=bootstrap.kubeconfig
```

设置客户端认证参数时没有指定密钥和证书，后续由 kube-apiserver 自动生成。

#### 创建kube-proxy kubeconfig文件

```bash
shell> export KUBE_APISERVER="https://10.0.77.17:6443"

设置集群参数
shell> kubectl config set-cluster kubernetes \
     --certificate-authority=/etc/kubernetes/ssl/ca.pem \
     --embed-certs=true \
     --server=${KUBE_APISERVER} \
     --kubeconfig=kube-proxy.kubeconfig
     
设置客户端认证参数
shell> kubectl config set-credentials kube-proxy \
     --client-certificate=/etc/kubernetes/ssl/kube-proxy.pem \
     --client-key=/etc/kubernetes/ssl/kube-proxy-key.pem \
     --embed-certs=true \
     --kubeconfig=kube-proxy.kubeconfig
     
设置上下文参数
shell> kubectl config set-context default \
     --cluster=kubernetes \
     --user=kube-proxy \
     --kubeconfig=kube-proxy.kubeconfig

设置默认上下文
shell> kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
```

kube-proxy.pem 证书中 CN 为 system:kube-proxy，kube-apiserver 预定义的 RoleBinding cluster-admin 将 User system:kube-proxy 与 Role system:node-proxier绑定，该 Role 授予了调用 kube-apiserver Proxy相关API权限。

#### 分发kubeconfig文件

将 *.kubeconfig 文件分发到所有节点的 /etc/kubernetes/ 下。

```bash
shell> scp root@n1.k8s.com:/etc/kubernetes/*.kubeconfig /etc/kubernetes/
```

#### 创建kubectl kubeconfig文件

```bash
shell> export KUBE_APISERVER="https://10.0.77.17:6443" #注意节点IP

设置集群参数
shell> kubectl config set-cluster kubernetes \
     --certificate-authority=/etc/kubernetes/ssl/ca.pem \
     --embed-certs=true \
     --server=${KUBE_APISERVER}
     
设置客户端认证参数
shell> kubectl config set-credentials admin \
     --client-certificate=/etc/kubernetes/ssl/admin.pem \
     --client-key=/etc/kubernetes/ssl/admin-key.pem \
     --embed-certs=true
     
设置上下文参数
shell> kubectl config set-context kubernetes \
     --cluster=kubernetes \
     --user=admin

设置默认上下文
shell> kubectl config use-context kubernetes
```

生成的 kubeconfig 保存在~/.kube/config文件中。

## kubernetes Master部署

Master节点组件包含：

+ kube-apiserver
+ kube-controller-manager
+ kube-scheduler

### kube-apiserver部署

```bash

shell> vi /usr/lib/systemd/system/kube-apiserver.service
[Unit]
Description=Kubernetes API Service
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
After=etcd.service

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/apiserver
ExecStart=/usr/local/bin/kube-apiserver \
        $KUBE_LOGTOSTDERR \
        $KUBE_LOG_LEVEL \
        $KUBE_ETCD_SERVERS \
        $KUBE_API_ADDRESS \
        $KUBE_API_PORT \
        $KUBELET_PORT \
        $KUBE_ALLOW_PRIV \
        $KUBE_SERVICE_ADDRESSES \
        $KUBE_ADMISSION_CONTROL \
        $KUBE_API_ARGS
Restart=on-failure
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

**/etc/kubernetes/config 文件内容**

```bash
KUBE_LOGTOSTDERR="--logtostderr=true"
KUBE_LOG_LEVEL="--v=0"
KUBE_ALLOW_PRIV="--allow-privileged=true"
KUBE_MASTER="--master=http://10.0.77.17:8080"
```

该配置文件同时被kube-apiserver、kube-controller-manager、kube-scheduler、kubelet、kube-proxy使用。

**/etc/kubernetes/apiserver 文件内容**

```bash
KUBE_API_ADDRESS="--advertise-address=10.0.77.17 --bind-address=10.0.77.17 --insecure-bind-address=10.0.77.17"
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=10.254.0.0/16"
KUBE_ADMISSION_CONTROL="--admission-control=ServiceAccount,NamespaceLifecycle,NamespaceExists,LimitRanger,ResourceQuota"

KUBE_API_ARGS="--authorization-mode=RBAC --runtime-config=rbac.authorization.k8s.io/v1beta1 --kubelet-https=true --enable-bootstrap-token-auth --token-auth-file=/etc/kubernetes/token.csv --service-node-port-range=30000-32767 --tls-cert-file=/etc/kubernetes/ssl/apiserver.pem --tls-private-key-file=/etc/kubernetes/ssl/apiserver-key.pem --client-ca-file=/etc/kubernetes/ssl/ca.pem --service-account-key-file=/etc/kubernetes/ssl/ca-key.pem --etcd-servers=https://10.0.77.17:2379,https://10.0.77.18:2379,https://10.0.77.19:2379 --etcd-cafile=/etc/kubernetes/ssl/ca.pem --etcd-certfile=/etc/kubernetes/ssl/etcd.pem --etcd-keyfile=/etc/kubernetes/ssl/etcd-key.pem --enable-swagger-ui=true --apiserver-count=3 --audit-log-maxage=30 --audit-log-maxbackup=3 --audit-log-maxsize=100 --audit-log-path=/var/lib/audit.log --event-ttl=1h"
```

```bash
shell> systemctl daemon-reload
shell> systemctl start kube-apiserver
shell> systemctl status kube-apiserver
shell> systemctl enable kube-apiserver
```

### kube-controller-manager部署

```bash
shell> vi /usr/lib/systemd/system/kube-controller-manager.service

Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/controller-manager
ExecStart=/usr/local/bin/kube-controller-manager \
        $KUBE_LOGTOSTDERR \
        $KUBE_LOG_LEVEL \
        $KUBE_MASTER \
        $KUBE_CONTROLLER_MANAGER_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

**/etc/kubernetes/controller-manager 文件内容**

```bash
KUBE_CONTROLLER_MANAGER_ARGS="--address=127.0.0.1 --service-cluster-ip-range=10.254.0.0/16 --cluster-name=kubernetes --cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem --cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem  --service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem --root-ca-file=/etc/kubernetes/ssl/ca.pem --leader-elect=true"
```

```bash
shell> systemctl daemon-reload
shell> systemctl start kube-controller-manager
shell> systemctl status kube-controller-manager
shell> systemctl enable kube-controller-manager
```

### kube-scheduler部署

```bash
shell> vi /usr/lib/systemd/system/kube-scheduler.service

[Unit]
Description=Kubernetes Scheduler Plugin
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/scheduler
ExecStart=/usr/local/bin/kube-scheduler \
        $KUBE_LOGTOSTDERR \
        $KUBE_LOG_LEVEL \
        $KUBE_MASTER \
        $KUBE_SCHEDULER_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

**/etc/kubernetes/scheduler 文件内容**

```bash
KUBE_SCHEDULER_ARGS="--leader-elect=true --address=127.0.0.1"
```

```bash
shell> systemctl daemon-reload
shell> systemctl start kube-scheduler
shell> systemctl status kube-scheduler
shell> systemctl enable kube-scheduler
```

验证 Master 节点功能

```bash
shell> kubectl get componentstatuses
NAME                 STATUS    MESSAGE             ERROR
scheduler            Healthy   ok                  
controller-manager   Healthy   ok                  
etcd-2               Healthy   {"health":"true"}   
etcd-1               Healthy   {"health":"true"}   
etcd-0               Healthy   {"health":"true"} 
```

## kubernetes Node部署

Node节点组件包含：
+ kubelet
+ kube-proxy
+ Flanneld
+ Docker

> Kubernetes 1.9 依赖的cni升级到了0.6.0版本

```bash
shell> wget https://github.com/containernetworking/cni/releases/download/v0.6.0/cni-amd64-v0.6.0.tgz
shell> mkdir -p /opt/cni/bin
shell> tar xzvf cni-amd64-v0.6.0.tgz  -C /opt/cni/bin
shell> ls /opt/cni/bin/
cnitool  noop
```

### 安装 Flannel 插件

#### 在Etcd集群中写入Pod网络信息

`该操作只在第一次部署Flannel网络执行，在etcd集群三台服务器中任意一台操作，其他节点不用再写入。`

```bash

shell> etcdctl \
  --endpoints=https://n1.k8s.com:2379,https://n2.k8s.com:2379,https://n3.k8s.com:2379 \
  --ca-file /etc/kubernetes/ssl/ca.pem \
  --cert-file /etc/kubernetes/ssl/etcd.pem \
  --key-file /etc/kubernetes/ssl/etcd-key.pem \
  mkdir /kube-centos/network

shell> etcdctl \
  --endpoints=https://n1.k8s.com:2379,https://n2.k8s.com:2379,https://n3.k8s.com:2379 \
  --ca-file /etc/kubernetes/ssl/ca.pem \
  --cert-file /etc/kubernetes/ssl/etcd.pem \
  --key-file /etc/kubernetes/ssl/etcd-key.pem \
  mk /kube-centos/network/config "{ \"Network\": \"172.30.0.0/16\", \"SubnetLen\": 24, \"Backend\": { \"Type\": \"vxlan\" } }"
```

#### 在master和node上安装 Flannel

```bash
shell> wget https://github.com/coreos/flannel/releases/download/v0.10.0/flannel-v0.10.0-linux-amd64.tar.gz
shell> tar xzvf flannel-v0.10.0-linux-amd64.tar.gz
shell> mv {flanneld,mk-docker-opts.sh} /usr/local/bin
```

#### 配置flannel.service服务

```bash
shell> vi /usr/lib/systemd/system/flanneld.service
[Unit]
Description=Flanneld overlay address etcd agent
After=network.target
After=network-online.target
Wants=network-online.target
After=etcd.service
Before=docker.service

[Service]
Type=notify
ExecStart=/usr/local/bin/flanneld \
        -etcd-cafile=/etc/kubernetes/ssl/ca.pem \
        -etcd-certfile=/etc/kubernetes/ssl/etcd.pem \
        -etcd-keyfile=/etc/kubernetes/ssl/etcd-key.pem \
        -etcd-endpoints=https://n1.k8s.com:2379,https://n2.k8s.com:2379,https://n3.k8s.com:2379 \
        -etcd-prefix=/kube-centos/network \
        $FLANNEL_OPTIONS
ExecStartPost=/usr/local/bin/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=on-failure

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
```

#### 启动Flannel

```
shell> systemctl daemon-reload
shell> systemctl start flanneld
shell> systemctl status flanneld
shell> systemctl enable flanneld
```

#### 查看Flanneld服务

```bash
shell> ifconfig flannel.1
flannel.1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1450
        inet 172.30.48.0  netmask 255.255.255.255  broadcast 0.0.0.0
...
```

**# 检查分配给各 flanneld 的 Pod 网段信息**

```bash
shell> etcdctl \
  --endpoints=https://n1.k8s.com:2379,https://n2.k8s.com:2379,https://n3.k8s.com:2379 \
  --ca-file /etc/kubernetes/ssl/ca.pem \
  --cert-file /etc/kubernetes/ssl/etcd.pem \
  --key-file /etc/kubernetes/ssl/etcd-key.pem \
  ls /kube-centos/network/subnets
  
/kube-centos/network/subnets/172.30.13.0-24
/kube-centos/network/subnets/172.30.44.0-24
/kube-centos/network/subnets/172.30.48.0-24
```

**查看已分配的 Pod 子网段列表(/24)**

```bash
shell> etcdctl \
  --endpoints=https://n1.k8s.com:2379,https://n2.k8s.com:2379,https://n3.k8s.com:2379 \
  --ca-file /etc/kubernetes/ssl/ca.pem \
  --cert-file /etc/kubernetes/ssl/etcd.pem \
  --key-file /etc/kubernetes/ssl/etcd-key.pem \
  get /kube-centos/network/config
  
{ "Network": "172.30.0.0/16", "SubnetLen": 24, "Backend": { "Type": "vxlan" } }
```

**查看某一 Pod 网段对应的 flanneld 进程监听的 IP 和网络参数**

```bash
shell> etcdctl \
  --endpoints=https://n1.k8s.com:2379,https://n2.k8s.com:2379,https://n3.k8s.com:2379 \
  --ca-file /etc/kubernetes/ssl/ca.pem \
  --cert-file /etc/kubernetes/ssl/etcd.pem \
  --key-file /etc/kubernetes/ssl/etcd-key.pem \
  get /kube-centos/network/subnets/172.30.48.0-24
  
{"PublicIP":"10.0.77.17","BackendType":"vxlan","BackendData":{"VtepMAC":"8e:97:d5:fa:36:ef"}}
```

#### 配置Docker0

[Running flannel](https://github.com/coreos/flannel/blob/master/Documentation/running.md).
Generate Docker daemon options based on flannel env file.

```bash
shell> cd /usr/local/bin/
shell> ./mk-docker-opts.sh -i

shell> cat /run/flannel/subnet.env 
FLANNEL_NETWORK=172.30.0.0/16
FLANNEL_SUBNET=172.30.48.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=false

shell> cat /run/docker_opts.env 
DOCKER_OPT_BIP="--bip=172.30.48.1/24"
DOCKER_OPT_IPMASQ="--ip-masq=true"
DOCKER_OPT_MTU="--mtu=1450"
```

**设置docker0的IP**

```bash
shell> vi /usr/lib/systemd/system/docker.service
...
EnvironmentFile=-/run/docker_opts.env
ExecStart=/usr/bin/dockerd $DOCKER_OPT_BIP $DOCKER_OPT_IPMASQ $DOCKER_OPT_MTU
...
LimitNOFILE=1000000
...
```

```
shell> systemctl daemon-reload
shell> systemctl restart docker
shell> ifconfig -a
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.30.48.1  netmask 255.255.255.0  broadcast 172.30.48.255
...

flannel.1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1450
        inet 172.30.48.0  netmask 255.255.255.255  broadcast 0.0.0.0
...
```

### 配置kubelet

> Kubernetes 1.9 socat是kubelet的依赖包

```bash
shell> yum install ebtables socat util-linux conntrack-tools
```

kubelet 启动时向 kube-apiserver 发送 TLS bootstrapping 请求，需要先将 bootstrap token 文件中的 kubelet-bootstrap 用户赋予 system:node-bootstrapper cluster role，然后 kubelet 才能有权限创建认证请求（certificate signing requests）。

```bash
shell> kubectl create clusterrolebinding kubelet-bootstrap \
     --clusterrole=system:node-bootstrapper \
     --user=kubelet-bootstrap
```
--user=kubelet-bootstrap 是在 /etc/kubernetes/token.csv 文件中指定的用户名，同时也写入了 /etc/kubernetes/bootstrap.kubeconfig 文件。

```bash
shell> kubectl delete clusterrolebindings kubelet-bootstrap
```

#### 创建kubelet的service服务

```bash
shell> mkdir /var/lib/kubelet

shell> vi /usr/lib/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/kubelet
ExecStart=/usr/local/bin/kubelet \
        $KUBE_LOGTOSTDERR \
        $KUBE_LOG_LEVEL \
        $KUBELET_ADDRESS \
        $KUBELET_PORT \
        $KUBELET_HOSTNAME \
        $KUBE_ALLOW_PRIV \
        $KUBELET_POD_INFRA_CONTAINER \
        $KUBELET_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

#### kubelet的配置文件

注意替换Node的IP地址。

```bash
shell> vi /etc/kubernetes/kubelet
KUBELET_ADDRESS="--address=10.0.77.17"
KUBELET_HOSTNAME="--hostname-override=10.0.77.17"
KUBELET_POD_INFRA_CONTAINER="--pod-infra-container-image=10.0.77.16/acquaai/pause:3.1"

KUBELET_ARGS="--cgroup-driver=systemd --cluster-dns=10.254.0.2 --cluster-domain=cluster.local. --experimental-bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig --kubeconfig=/etc/kubernetes/kubelet.kubeconfig --cert-dir=/etc/kubernetes/ssl --hairpin-mode=promiscuous-bridge --serialize-image-pulls=false"
```

> GFW的问题无法下载 gcr.io/google_containers/pause，可以添加kubelet的启动参数使用私有镜像来解决：--pod-infra-container-image=10.0.77.16/acquaai/pause:3.1

`--cgroup-driver:`
kubelet[27248]: error: failed to run Kubelet: failed to create kubelet: misconfiguration: kubelet cgroup driver: `"systemd"` is different from docker cgroup driver: `"cgroupfs"`

**修改docker的 cgroup-driver**

```bash
shell> docker info |grep 'Cgroup Driver'
Cgroup Driver: cgroupfs

修改或创建/etc/docker/daemon.json

shell> vi /etc/docker/daemon.json
{
  "exec-opts": ["native.cgroupdriver=systemd"]
}

shell> systemctl restart docker
shell> docker info |grep 'Cgroup Driver'
Cgroup Driver: systemd
```

```bash
shell> systemctl daemon-reload
       systemctl start kubelet
       systemctl status kubelet
       systemctl enable kubelet
```

**kublet的TLS证书请求**

kubelet 首次启动时向 kube-apiserver 发送证书签名请求必须通过后，kubernetes系统才会将该 Node 加入到集群。

查看未授权的 CSR 请求

```bash
shell> kubectl get csr
NAME                                                   AGE       REQUESTOR           CONDITION
node-csr-zZhoaUsBAZk4CnQWvOseQBIZvUeyyI4lwWGaSX5gzmA   3m        kubelet-bootstrap   Pending

shell> kubectl get nodes
No resources found.
```   

通过 CSR 请求

```bash
shell> kubectl certificate approve node-csr-zZhoaUsBAZk4CnQWvOseQBIZvUeyyI4lwWGaSX5gzmA
certificatesigningrequest "node-csr-zZhoaUsBAZk4CnQWvOseQBIZvUeyyI4lwWGaSX5gzmA" approved

shell> kubectl get csr
NAME                                                   AGE       REQUESTOR           CONDITION
node-csr-zZhoaUsBAZk4CnQWvOseQBIZvUeyyI4lwWGaSX5gzmA   20m       kubelet-bootstrap   Approved,Issued

shell> kubectl get nodes
NAME         STATUS    ROLES     AGE       VERSION
10.0.77.17   Ready     <none>    1d        v1.9.3
10.0.77.18   Ready     <none>    31m       v1.9.3
10.0.77.19   Ready     <none>    31m       v1.9.3

shell> kubectl describe clusterrolebindings kubelet-bootstrap
Name:         kubelet-bootstrap
Labels:       <none>
Annotations:  <none>
Role:
  Kind:  ClusterRole
  Name:  system:node-bootstrapper
Subjects:
  Kind  Name               Namespace
  ----  ----               ---------
  User  kubelet-bootstrap  
```

自动生成 kubelet.kubeconfig 文件和公私钥

```bash
shell> ll /etc/kubernetes/kubelet*
-rw-r--r-- 1 root root  520 Feb 22 16:12 /etc/kubernetes/kubelet
-rw------- 1 root root 2217 Feb 22 16:15 /etc/kubernetes/kubelet.kubeconfig

shell> ll /etc/kubernetes/ssl/kubelet*
-rw-r--r-- 1 root root 1046 Feb 22 16:15 /etc/kubernetes/ssl/kubelet-client.crt
-rw------- 1 root root  227 Feb 22 16:09 /etc/kubernetes/ssl/kubelet-client.key
-rw-r--r-- 1 root root 1107 Feb 22 16:09 /etc/kubernetes/ssl/kubelet.crt
-rw------- 1 root root 1675 Feb 22 16:09 /etc/kubernetes/ssl/kubelet.key
```

**Error:**
Feb 23 11:10:09 n1 kubelet: I0223 11:10:09.526983    3451 kubelet_node_status.go:273] Setting node annotation to enable volume controller attach/detach
Feb 23 11:10:09 n1 kubelet: I0223 11:10:09.529556    3451 kubelet_node_status.go:82] Attempting to register node 10.0.77.17
Feb 23 11:10:09 n1 kubelet: E0223 11:10:09.530660    3451 kubelet_node_status.go:106] Unable to register node "10.0.77.17" with API server: nodes is forbidden: User "system:node:10.0.77.17" cannot create nodes at the cluster scope

```bash
shell> kubectl get clusterrolebinding system:node -o yaml 
...
subjects: null
```

> kubelet v.17+ ，RBAC: the `system:node` role is no longer automatically granted to the `system:nodes` group in new clusters. It is recommended that nodes be authorized using the `Node` authorization mode instead. Installations that wish to continue giving all members of the `system:nodes` group the `system:node` role (which grants broad read access, including all secrets and configmaps) must create an installation-specific `ClusterRoleBinding`.

```bash
shell> kubectl edit clusterrolebinding system:node
...
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:nodes
...

shell> kubectl get clusterrolebindings kubelet-bootstrap -o yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  creationTimestamp: 2018-02-23T10:18:56Z
  name: kubelet-bootstrap
  resourceVersion: "169997"
  selfLink: /apis/rbac.authorization.k8s.io/v1/clusterrolebindings/kubelet-bootstrap
  uid: f496689c-1882-11e8-bd44-0050568879ea
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:node-bootstrapper
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: kubelet-bootstrap
```

### 配置kube-proxy

**创建kube-proxy的service文件**

```bash
shell> vi /usr/lib/systemd/system/kube-proxy.service
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/proxy
ExecStart=/usr/local/bin/kube-proxy \
        $KUBE_LOGTOSTDERR \
        $KUBE_LOG_LEVEL \
        $KUBE_MASTER \
        $KUBE_PROXY_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

**kube-proxy配置文件**

```bash
shell> vi /etc/kubernetes/proxy
KUBE_PROXY_ARGS="--bind-address=10.0.77.17 --hostname-override=10.0.77.17 --kubeconfig=/etc/kubernetes/kube-proxy.kubeconfig --cluster-cidr=10.254.0.0/16"
```

```bash
shell> systemctl daemon-reload
       systemctl start kube-proxy
       systemctl status kube-proxy
       systemctl enable kube-proxy
```

### 测试验证

```bash
shell> kubectl run nginx --replicas=2 --labels="run=load-balancer-example" --image=10.0.77.16:443/acquaai/nginx:1.9  --port=80
deployment "nginx" created

shell> kubectl expose deployment nginx --type=NodePort --name=example-service
service "example-service" exposed

shell> kubectl get pods
NAME                     READY     STATUS    RESTARTS   AGE
nginx-65486cc689-lq9g4   1/1       Running   0          15m
nginx-65486cc689-t6f7b   1/1       Running   0          15m

shell> kubectl describe svc example-service
Name:                     example-service
Namespace:                default
Labels:                   run=load-balancer-example
Annotations:              <none>
Selector:                 run=load-balancer-example
Type:                     NodePort
IP:                       10.254.66.117
Port:                     <unset>  80/TCP
TargetPort:               80/TCP
NodePort:                 <unset>  31805/TCP
Endpoints:                172.30.44.2:80,172.30.48.2:80
Session Affinity:         None
External Traffic Policy:  Cluster
Events:                   <none>
```

```html
shell> curl "10.254.66.117:80"
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

浏览器: http://10.0.77.17:31805/、http://10.0.77.18:31805/、http://10.0.77.19:31805/

## 安装 CoreDNS 插件

最初是使用 KubeDNS 的，但用了4天的时间一直没有解决:
> kube-system   kube-dns-5d4569bcc4-z2zhw               2/3       `CrashLoopBackOff`   34         25m

因此改为[CoreDNS](https://coredns.io) 插件。

### 配置文件

```bash
shell> mkdir /etc/kubernetes/CoreDNS && cd /etc/kubernetes/CoreDNS
shell> wget https://raw.githubusercontent.com/coredns/deployment/master/kubernetes/coredns.yaml.sed
shell> mv coredns.yaml.sed coredns.yaml
```

修改 coredns.yaml 配置

```
#创建 svc 的 IP 段

apiVersion: v1
kind: ConfigMap
...
data:
  Corefile: |
    .:53 {
        ...
        kubernetes cluster.local 10.254.0.0/18 {
...

# clusterIP  为 指定 DNS 的 IP

apiVersion: v1
kind: Service
...
spec:
  selector:
    k8s-app: coredns
  clusterIP: 10.254.0.2
...
```

```bash
shell> kubectl apply -f coredns.yaml 
serviceaccount "coredns" created
clusterrole "system:coredns" created
clusterrolebinding "system:coredns" created
configmap "coredns" created
deployment "coredns" created
service "kube-dns" created
```

### 查看 CoreDNS 服务

```bash
shell> kubectl get pod,svc -n kube-system
NAME                                       READY     STATUS    RESTARTS   AGE
po/coredns-84594fccfc-l7zfl                1/1       Running   0          33s
po/coredns-84594fccfc-phz55                1/1       Running   0          33s
po/elasticsearch-logging-0                 1/1       Running   8          2d
po/elasticsearch-logging-1                 1/1       Running   8          2d
po/fluentd-es-v2.0.4-94fzd                 1/1       Running   9          2d
po/fluentd-es-v2.0.4-9dl6b                 1/1       Running   8          2d
po/fluentd-es-v2.0.4-sv6kr                 1/1       Running   2          1d
po/heapster-58c496c5f5-c2fxs               1/1       Running   10         3d
po/kibana-logging-d59bb958c-44hfp          1/1       Running   8          2d
po/kubernetes-dashboard-5879598f5f-nmdc8   1/1       Running   15         5d
po/monitoring-grafana-d8d7cfbb9-s6jtq      1/1       Running   11         4d
po/monitoring-influxdb-6bbc85db45-xbpxq    1/1       Running   11         4d

NAME                        TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)                         AGE
svc/elasticsearch-logging   ClusterIP   10.254.228.172   <none>        9200/TCP                        2d
svc/heapster                ClusterIP   10.254.86.30     <none>        80/TCP                          4d
svc/kibana-logging          ClusterIP   10.254.148.193   <none>        5601/TCP                        2d
svc/kube-dns                ClusterIP   10.254.0.2       <none>        53/UDP,53/TCP                   32s
svc/kubernetes-dashboard    NodePort    10.254.169.24   <none>        443:30869/TCP                   5d
svc/monitoring-grafana      ClusterIP   10.254.238.40    <none>        80/TCP                          4d
svc/monitoring-influxdb     NodePort    10.254.241.249   <none>        8086:31762/TCP,8083:32456/TCP   4d
```

### 查看 CoreDNS 日志

```bash
shell> kubectl logs -n kube-system coredns-84594fccfc-l7zfl 
.:53
CoreDNS-1.0.6
linux/amd64, go1.10, 83b5eadb
2018/03/05 06:34:30 [INFO] CoreDNS-1.0.6
2018/03/05 06:34:30 [INFO] linux/amd64, go1.10, 83b5eadb
```

### 验证 DNS 服务

> 在验证 dns 之前，在 dns 未部署之前创建的 pod 与 deployment 等，都必须删除，重新部署，否则无法解析。

```json
shell> cat busybox.yaml 
apiVersion: v1
kind: Pod
metadata:
  name: busybox
  namespace: default
spec:
  containers:
  - name: busybox
    image: busybox
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
  restartPolicy: Always
  
shell> kubectl apply -f busybox.yaml
```

```bash
shell> kubectl exec -it busybox nslookup my-nginx
Server:    10.254.0.2
Address 1: 10.254.0.2 kube-dns.kube-system.svc.cluster.local

Name:      my-nginx
Address 1: 10.254.23.60 my-nginx.default.svc.cluster.local

[root@n1 kube-dns]# kubectl exec -it busybox nslookup kubernetes
Server:    10.254.0.2
Address 1: 10.254.0.2 kube-dns.kube-system.svc.cluster.local

Name:      kubernetes
Address 1: 10.254.0.1 kubernetes.default.svc.cluster.local
```

CoreDNS正确解析。

## 安装 Dashboard 插件

[kubernetes/dashboard](https://github.com/kubernetes/dashboard)

下载官方配置文件：

```bash
shell> mkdir /etc/kubernetes/dashboard && cd /etc/kubernetes/dashboard
shell> wget https://raw.githubusercontent.com/kubernetes/dashboard/master/src/deploy/recommended/kubernetes-dashboard.yaml
```

```bash
修改其中的镜像地址为私有地址:

shell> vi kubernetes-dashboard.yaml

image: k8s.gcr.io/kubernetes-dashboard-amd64:v1.8.3
--->
image: 10.0.77.16/acquaai/kubernetes-dashboard-amd64:v1.8.3

将 service type 设置为 NodePort
type: NodePort
```

修改后的 [kubernetes-dashboard.yaml](https://github.com/acquaai/K8S/tree/master/docs/dashboard)文件

部署 dashboard

```bash
shell> kubectl apply -f kubernetes-dashboard.yaml
secret "kubernetes-dashboard-certs" created
serviceaccount "kubernetes-dashboard" created
role "kubernetes-dashboard-minimal" created
rolebinding "kubernetes-dashboard-minimal" created
deployment "kubernetes-dashboard" created
service "kubernetes-dashboard" created
```

若重新部署，需要删除dashboard资源：

```bash
shell> pwd
/etc/kubernetes

shell> kubectl delete -f dashboard/
secret "kubernetes-dashboard-certs" deleted
serviceaccount "kubernetes-dashboard" deleted
role "kubernetes-dashboard-minimal" deleted
rolebinding "kubernetes-dashboard-minimal" deleted
deployment "kubernetes-dashboard" deleted
service "kubernetes-dashboard" deleted
```

获取dashboard的外网访问端口：

```bash
shell> kubectl -n kube-system get svc kubernetes-dashboard
NAME                   TYPE       CLUSTER-IP       EXTERNAL-IP   PORT(S)         AGE
kubernetes-dashboard   NodePort   10.254.169.24   <none>        443:30869/TCP   6s
```

访问集群中的任何一个节点，即可打开Dashboard登陆页面，https://10.0.77.17:30869 ，支持使用kubeconfig和token两种的认证方式：

![](http://p564fpez5.bkt.clouddn.com/image/k8sdashlogin_1.png)

### admin 用户身份认证

登陆 Dashboard 的时候支持 kubeconfig 和 token 两种认证方式，kubeconfig 中也依赖 token 字段，所以生成 token 这一步是必不可少的。

在 Dashboard 登录页面上有两种登录方式，kubeconfig 文件和 token （令牌），使用 token 登录可以直接使用后文中获得的那个非常长的字符串作为 token 登录，即可以拥有管理员权限操作整个kubernetes集群中的对象。对于 kubeconfig 文件登录方式，不能直接使用之前给 kubectl 生成的 kubeconfig 文件(~/.kube/config) 需要给它加一个 token 字段，可以将这串 token 加到 admin 用户的kubeconfig文件中，继续使用kubeconfig登录，

#### 使用 kubeconfig

**`本学习使用admin 用户的kubeconfig文件登录 Dashboard`**。
kubeconfig 文件 (~/.kube/config) 前文已生成。

#### 生成集群管理员的token

以下是为集群最高权限的管理员（可以任意操作所有namespace中的所有资源）生成token的步骤。

> 注意：登陆dashboard的时候token值是必须的，而kubeconfig文件是kubectl命令所必须的，kubectl命令使用的kubeconfig文件中可以不包含token信息。

需要创建一个admin用户并授予admin角色绑定，使用下面的 admin-role.yaml 文件创建admin用户并赋予它管理员权限，然后可以通过token登陆Dashbaord。这种认证方式本质上是通过 Service Account 的身份认证加上 Bearer token 请求 API server 的方式实现，参考[Kubernetes 中的认证](https://kubernetes.io/docs/admin/authentication/)。

```bash
shell> vi /etc/kubernetes/dashboard/admin-role.yaml

kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: admin
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: admin
  namespace: kube-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin
  namespace: kube-system
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
```

然后执行下面的命令创建 serviceaccount 和角色绑定，**对于其他命名空间的其他用户只要修改上述 yaml 中的 name 和 namespace 字段即可：**

```bash
shell> kubectl create -f admin-role.yaml
```
    
**命令直接获取admin用户的token**

```bash
shell> kubectl -n kube-system describe secret `kubectl -n kube-system get secret|grep admin-token|cut -d " " -f1`|grep "token:"|tr -s " "|cut -d " " -f2
```

**手动获取admin用户的token**

```bash
# 获取admin-token的secret名字
shell> kubectl -n kube-system get secret|grep admin-token
admin-token-md6qv                  kubernetes.io/service-account-token   3         7m

# 获取token的值
shell> kubectl -n kube-system describe secret admin-token-md6qv
Name:         admin-token-md6qv
Namespace:    kube-system
Labels:       <none>
Annotations:  kubernetes.io/service-account.name=admin
              kubernetes.io/service-account.uid=1f3413da-1c35-11e8-bd44-0050568879ea

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1314 bytes
namespace:  11 bytes
token:      eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJhZG1pbi10b2tlbi1tZDZxdiIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJhZG1pbiIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjFmMzQxM2RhLTFjMzUtMTFlOC1iZDQ0LTAwNTA1Njg4NzllYSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDprdWJlLXN5c3RlbTphZG1pbiJ9.iSjqQZoxBnFkJpVZ6bdCoslkMy3rGNyHPrqNskdE_pSinosJitle0lQARI_JOMlaHTywVmzytn6PX2IJtHAf1HVACULwJ9vui4N48CrWwCC4YT3LRMPLmDWW_j1f-DwUQnmMB7KJBP1k6xJChSzrXgc9JOV2ItPvMWVMKpO8MRa4yKkpxbWhNWziryhhr8RLoZYnFmiOHJ63K81T7Hd5wNdyxMm4V8aMYrYpB-6T4G13gUF-qqYRH-GXGwRtOGv_ZiVF6BhOWoxhsO0NiDWPTD8skbozOZLFwcz_N2mq0QcCvAt50gWskEKI0Q3LORMBPAdHGNZT2UqY2J_KACrdmA
```

> 注意：通过 kubectl get secret xxx 输出中的 token 值需要进行 base64 解码，在线解码工具 base64decode，Linux 和 Mac 有自带的 base64 命令也可以直接使用，输入 base64 是进行编码，Linux 中base64 -d 表示解码，Mac 中使用 base64 -D；通过 kubectl describe secret xxx 输出中的 token 不需要 base64 解码。

> 也可以使用 jsonpath 的方式直接获取 token 的值，如：

> `kubectl -n kube-system get secret admin-token-nwphb -o jsonpath={.data.token}|base64 -d`

**增加 token 值到 kubeconfig 文件末**

关于如何给其它namespace的管理员生成token请参考[使用kubeconfig或token进行用户身份认证](https://jimmysong.io/kubernetes-handbook/guide/auth-with-kubeconfig-or-token.html)。

#### 设置界面的语言

Dashboard页面语言依赖浏览器的默认语言。如果要强制设置 Dashboard 显示的语言，需要在 Dahsboard 的 Deployment yaml 配置中增加如下配置：

env:
  - name: ACCEPT_LANGUAGE
    value: english

![](http://p564fpez5.bkt.clouddn.com/image/k8sdashlogin_2.png)

### 创建其它用户身份认证

**脚本创建 user 和 namespace**

> 使用 [jimmysong's create-user.sh](https://github.com/rootsongjc/kubernetes-handbook/blob/master/tools/create-user/create-user.sh)脚本创建namespace和用户（同名），并将该namespace的admin权限授予该用户。

> 使用该脚本需要满足以下前提：

> - 所有的证书文件都在`/etc/kubernetes/ssl`目录下
> - 执行该脚本的主机可以访问kubernetes集群，并用于最高管理员权限

> `./create-user.sh <api_server> <username>`

> 最后生成了`$username.kubeconfig`文件。

**手工创建 user 和 namespace**

+ 为`brand namespace`下的`brand`用户生成了名为 brand.kubeconfig 的 kubeconfig 文件。

1、创建 CA 证书和密钥

创建 brand-csr.json 文件

```json
shell> vi /root/cfssl/brand-csr.json
{
    "CN": "brand", 
    "key": {
        "algo": "rsa", 
        "size": 2048
    }, 
    "names": [
        {
            "C": "CN", 
            "ST": "Shenzhen", 
            "L": "Shenzhen", 
            "O": "k8s", 
            "OU": "System"
        }
    ]
}
```

2、生成 CA 证书和密钥

在`创建 TLS 证书和密钥`章节中，在 /root/cfssl 下生成了证书和密钥，然后拷贝到所有节点的 /etc/kubernetes/ssl 目录下。

```bash
shell> cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes brand-csr.json | cfssljson -bare brand

shell> ls brand*
brand.csr  brand-csr.json  brand-key.pem  brand.pem

shell> cp /root/cfssl/brand*.pem /etc/kubernetes/ssl/
shell> cp /root/cfssl/brand.csr /etc/kubernetes/ssl/

n2/n3> scp root@n1.k8s.com:/etc/kubernetes/ssl/brand.csr /etc/kubernetes/ssl/
n2/n3> scp root@n1.k8s.com:/etc/kubernetes/ssl/brand*.pem /etc/kubernetes/ssl/
```

3、创建 kubeconfig 文件

```bash
# 设置集群参数
export KUBE_APISERVER="https://10.0.77.17:6443" #注意替换节点IP

kubectl config set-cluster kubernetes \
--certificate-authority=/etc/kubernetes/ssl/ca.pem \
--embed-certs=true \
--server=${KUBE_APISERVER} \
--kubeconfig=brand.kubeconfig

# 设置客户端认证参数
kubectl config set-credentials brand \
--client-certificate=/etc/kubernetes/ssl/brand.pem \
--client-key=/etc/kubernetes/ssl/brand-key.pem \
--embed-certs=true \
--kubeconfig=brand.kubeconfig

# 设置上下文参数
kubectl config set-context kubernetes \
--cluster=kubernetes \
--user=brand \
--namespace=brand \
--kubeconfig=brand.kubeconfig

# 设置默认上下文
kubectl config use-context kubernetes --kubeconfig=brand.kubeconfig

# 创建 namespace
kubectl create ns brand
```

4、CIRoleBinding

若限制 brand 用户的行为，需要使用 RBAC 将该用户的行为限制在某个或某几个 namespace 空间范围内，例如：

```bash
shell> kubectl create rolebinding brand-admin-binding --clusterrole=admin --user=brand --namespace=brand --serviceaccount=brand:default
```

这样 brand 用户对 brand namespace 具有完全访问权限。

```bash
# 获取当前的 context
kubectl config get-contexts
CURRENT   NAME         CLUSTER      AUTHINFO   NAMESPACE
*         kubernetes   kubernetes   admin 

#显示的用户仍然是 admin，这是因为 kubectl 使用了 $HOME/.kube/config 文件作为了默认的 context 配置，只需将生成的 brand.kubeconfig 文件替换即可。

cp -f /root/cfssl/brand.kubeconfig /root/.kube/config

#现在 kubectl 命令默认使用的 context 就是 brand 了，且该用户只能操作 brand  namespace，并拥有完全的访问权限。
kubectl config get-contexts
CURRENT   NAME         CLUSTER      AUTHINFO   NAMESPACE
*         kubernetes   kubernetes   brand      brand

# 无法访问 default namespace
kubectl get pods --namespace default
Error from server (Forbidden): pods is forbidden: User "brand" cannot list pods in the namespace "default"
```

现在就可以使用brand.kubeconfig文件，与生成 brand 用户的token（参见 **生成集群管理员的token**方法）来登陆Dashboard了，且只能访问和操作brand命名空间下的对象。

### 访问Dashboard

+ kubernetes-dashboard 服务暴露了 NodePort，可以使用 http://NodeIP:nodePort 地址访问 dashboard (https://10.0.77.17:30869)
+ 通过 kubectl proxy 访问 dashboard
+ 通过 API server 访问 dashboard（https 6443端口和http 8080端口方式）


#### 通过 kubectl proxy 访问 Dashboard

启动代理

```bash
shell> kubectl proxy --address='10.0.77.17' --port=8086 --accept-hosts='^*$'
Starting to serve on 10.0.77.17:8086
```

浏览器访问 http://10.0.77.17:8086/ui
自动跳转到：
http://10.0.77.17:8086/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/#!/login

> 问题1: 打开页面后使用 kubeconfig 文件不能登录。

#### 通过 API server 访问Dashboard

获取集群服务地址列表

```bash
shell> kubectl cluster-info
Kubernetes master is running at https://10.0.77.17:6443
CoreDNS is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
```

**导入证书**

将生成的admin.pem证书转换格式

```bash
shell> cd /root/cfssl
shell> openssl pkcs12 -export -in admin.pem  -out admin.p12 -inkey admin-key.pem
Enter Export Password:
Verifying - Enter Export Password:
```

将生成的admin.p12证书导入的你的电脑。

再次访问 https://10.0.77.17:6443/api/v1/proxy/namespaces/kube-system/services/kubernetes-dashboard

> 问题2: 页面无法打开。

## 安装 Heapster 插件

下载最新版本的 [heapster](https://github.com/kubernetes/heapster/releases)。

```bash
shell> wget https://github.com/kubernetes/heapster/archive/v1.5.1.zip
shell> unzip v1.5.1.zip

#文件目录
shell> cd heapster-1.5.1/deploy/kube-config/influxdb/
shell> ls *.yaml
grafana.yaml  heapster.yaml  influxdb.yaml
```

为了顺利完成本学习，这里使用 jimmysong's修改好的 [yaml](https://github.com/rootsongjc/kubernetes-handbook/tree/master/manifests/heapster) 文件。

### 配置 grafana-deployment

gcr.io/google_containers/heapster-grafana-amd64:v4.4.3
--->
10.0.77.16/acquaai/heapster-grafana-amd64:v4.4.3

### 配置 heapster-deployment

gcr.io/google_containers/heapster-amd64:v1.5.1
--->
10.0.77.16/acquaai/heapster-amd64:v1.5.1

### 配置 influxdb-deployment

influxdb 官方建议使用命令行或 HTTP API 接口来查询数据库，从 v1.1.0 版本开始默认关闭 admin UI，将在后续版本中移除 admin UI 插件。

开启镜像中 admin UI的办法如下：先导出镜像中的 influxdb 配置文件，开启 admin 插件后，再将配置文件内容写入 ConfigMap，最后挂载到镜像中，达到覆盖原始配置的目的。

```bash
# 导出镜像中的 influxdb 配置文件
$ docker run --rm --entrypoint 'cat'  -ti 10.0.77.16/acquaai/heapster-influxdb-amd64:v1.3.3 /etc/config.toml >config.toml.orig
$ cp config.toml.orig config.toml

# 修改：启用 admin 接口
$ vim config.toml
enabled = true

$ diff config.toml.orig config.toml
<   enabled = false
---
>   enabled = true

# 将修改后的配置写入到 ConfigMap 对象中
$ kubectl create configmap influxdb-config --from-file=config.toml  -n kube-system
configmap "influxdb-config" created

# 将 ConfigMap 中的配置文件挂载到 Pod 中，达到覆盖原始配置的目的
$ diff influxdb-deployment.yaml.orig influxdb-deployment.yaml

<         image: gcr.io/google_containers/heapster-influxdb-amd64:v1.3.3
---
>         image: 10.0.77.16/acquaai/heapster-influxdb-amd64:v1.3.3

>         - mountPath: /etc/
>           name: influxdb-config

>       - name: influxdb-config
>         configMap:
>           name: influxdb-config
```

### 配置 monitoring-influxdb Service

定义端口类型为 NodePort，额外增加了 admin 端口映射，用于后续浏览器访问 influxdb 的 admin UI 界面。

### 执行定义文件

```bash
shell> cd /root/heapster-1.5.1/deploy/kube-config/influxdb
shell> ls *.yaml
grafana-deployment.yaml  grafana-service.yaml  heapster-deployment.yaml  heapster-rbac.yaml  heapster-service.yaml  influxdb-cm.yaml  influxdb-deployment.yaml  influxdb-service.yaml

shell> kubectl create -f .
deployment "monitoring-grafana" created
service "monitoring-grafana" created
deployment "heapster" created
serviceaccount "heapster" created
clusterrolebinding "heapster" created
service "heapster" created
configmap "influxdb-config" created
deployment "monitoring-influxdb" created
service "monitoring-influxdb" created
```

### 检查执行结果

```bash
#检查 Pods：
shell> kubectl get pods -n kube-system | grep -E 'heapster|monitoring'
heapster-58c496c5f5-tgmgr               1/1       Running            0          5m
monitoring-grafana-d8d7cfbb9-s6jtq      1/1       Running            1          5m
monitoring-influxdb-6bbc85db45-xbpxq    1/1       Running            1          6m

#检查 Deployment
shell> kubectl get deployments -n kube-system | grep -E 'heapster|monitoring'
heapster               1         1         1            1           5m
monitoring-grafana     1         1         1            1           5m
monitoring-influxdb    1         1         1            1           6m
```

检查 kubernets dashboard 界面，看是显示各 Nodes、Pods 的 CPU、内存、负载等利用率曲线图：

![](http://p564fpez5.bkt.clouddn.com/image/k8sdash_view.png)

### 访问 grafana

1、通过 kube-apiserver 访问：

获取 monitoring-grafana 服务 URL

```bash
shell> kubectl cluster-info
Kubernetes master is running at https://10.0.77.17:644
Heapster is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/heapster/proxy
CoreDNS is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
monitoring-grafana is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/monitoring-grafana/proxy
monitoring-influxdb is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/monitoring-influxdb:http/proxy

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
```

浏览器访问 URL： http://10.0.77.17:8080/api/v1/proxy/namespaces/kube-system/services/monitoring-grafana

![](http://p564fpez5.bkt.clouddn.com/image/k8sapi_grafana.png)

2、通过 kubectl proxy 访问：

创建代理

```bash
shell> kubectl proxy --address='10.0.77.17' --port=8086 --accept-hosts='^*$'
Starting to serve on 10.0.77.17:8086
```

浏览器访问 URL：http://10.0.77.17:8086/api/v1/proxy/namespaces/kube-system/services/monitoring-grafana

![](http://p564fpez5.bkt.clouddn.com/image/k8sproxy_grafana.png)

### 访问 influxdb admin UI

获取 influxdb http 8086 映射的 NodePort

```bash
shell> kubectl get svc -n kube-system|grep influxdb
monitoring-influxdb    NodePort    10.254.241.249   <none>        8086:31762/TCP,8083:32456/TCP   17h
```

通过 kube-apiserver 的非安全端口访问 influxdb 的 admin UI 界面： 
http://10.0.77.17:8080/api/v1/proxy/namespaces/kube-system/services/monitoring-influxdb:8083/

> 问题3: 页面无法打开。

在页面的 "Connection Settings" 的 Host 中输入 node IP， Port 中输入 8086 映射的 nodePort 如上面的 31762，点击 "Save"。

## 安装 EFK 插件

通过在每台node上部署一个以DaemonSet方式运行的fluentd来收集每台node上的日志。Fluentd将docker日志目录/var/lib/docker/containers和/var/log目录挂载到Pod中，然后Pod会在node节点的/var/log/pods目录中创建新的目录，可以区别不同的容器日志输出，该目录下有一个日志文件链接到/var/lib/docker/contianers目录下的容器日志输出。

官方文件目录: [kubernetes/cluster/addons/fluentd-elasticsearch/](https://github.com/kubernetes/kubernetes/tree/master/cluster/addons/fluentd-elasticsearch)

EFK服务也需要一个 efk-rbac.yaml 文件，配置serviceaccount为 efk 。
此处使用 [jimmysong](https://github.com/rootsongjc/kubernetes-handbook/tree/master/manifests/EFK) 修改好的 yaml 文件。

使用私有仓库镜像：

```
k8s.gcr.io/elasticsearch:v5.6.4 => 10.0.77.16/library/elasticsearch:v5.6.4
k8s.gcr.io/fluentd-elasticsearch:v2.0.4 => 10.0.77.16/library/fluentd-elasticsearch:v2.0.4
docker.elastic.co/kibana/kibana:5.6.4 => 10.0.77.16/library/kibana:5.6.4
```

### 给 Node 设置标签

定义 DaemonSet fluentd-es-v2.0.4 时设置了 nodeSelector beta.kubernetes.io/fluentd-ds-ready=true ，所以需要在期望运行 fluentd 的 Node 上设置该标签。

```bash
kubectl get nodes
NAME         STATUS    ROLES     AGE       VERSION
10.0.77.17   Ready     <none>    6d        v1.9.3
10.0.77.18   Ready     <none>    5d        v1.9.3
10.0.77.19   Ready     <none>    5d        v1.9.3

kubectl label nodes 10.0.77.17 beta.kubernetes.io/fluentd-ds-ready=true
node "10.0.77.17" labeled

kubectl label nodes 10.0.77.18 beta.kubernetes.io/fluentd-ds-ready=true
node "10.0.77.18" labeled

kubectl label nodes 10.0.77.19 beta.kubernetes.io/fluentd-ds-ready=true
node "10.0.77.19" labeled
```

### 执行定义文件

```bash
shell> pwd
/etc/kubernetes/efk

shell> kubectl create -f .
serviceaccount "efk" created
clusterrolebinding "efk" created
replicationcontroller "elasticsearch-logging-v1" created
service "elasticsearch-logging" created
daemonset "fluentd-es-v1.22" created
deployment "kibana-logging" created
service "kibana-logging" created
```

### 检查执行结果

```bash
kubectl get deployment -n kube-system|grep kibana
kibana-logging         1         1         1            1           1m

kubectl get pods -n kube-system|grep -E 'elasticsearch|fluentd|kibana'
elasticsearch-logging-0                 1/1       Running            0          2m
elasticsearch-logging-1                 1/1       Running            0          2m
fluentd-es-v2.0.4-94fzd                 1/1       Running            0          2m
fluentd-es-v2.0.4-9cwqp                 1/1       Running            0          2m
fluentd-es-v2.0.4-9dl6b                 1/1       Running            0          2m
kibana-logging-d59bb958c-44hfp          1/1       Running            0          2m

kubectl get service  -n kube-system|grep -E 'elasticsearch|kibana'
elasticsearch-logging   ClusterIP   10.254.228.172   <none>        9200/TCP                        3m
kibana-logging          ClusterIP   10.254.148.193   <none>        5601/TCP                        3m
```

kibana Pod 第一次启动时会用较长时间(10-20分钟)来优化和 Cache 状态页面，可以 tailf 该 Pod 的日志观察进度：

```bash
kubectl logs kibana-logging-d59bb958c-44hfp -n kube-system -f
...
{"type":"log","@timestamp":"2018-03-05T04:38:45Z","tags":["listening","info"],"pid":1,"message":"Server running at http://0:5601"}
{"type":"log","@timestamp":"2018-03-05T04:38:45Z","tags":["status","ui settings","error"],"pid":1,"state":"red","message":"Status changed from uninitialized to red - Elasticsearch plugin is red","prevState":"uninitialized","prevMsg":"uninitialized"}
{"type":"log","@timestamp":"2018-03-05T06:34:31Z","tags":["status","plugin:ml@5.6.4","info"],"pid":1,"state":"green","message":"Status changed from red to green - Ready","prevState":"red","prevMsg":"Request Timeout after 3000ms"}
{"type":"log","@timestamp":"2018-03-05T06:34:34Z","tags":["status","plugin:elasticsearch@5.6.4","info"],"pid":1,"state":"green","message":"Status changed from red to green - Kibana index ready","prevState":"red","prevMsg":"Request Timeout after 3000ms"}
{"type":"log","@timestamp":"2018-03-05T06:34:34Z","tags":["status","ui settings","info"],"pid":1,"state":"green","message":"Status changed from red to green - Ready","prevState":"red","prevMsg":"Elasticsearch plugin is red"}
{"type":"log","@timestamp":"2018-03-05T06:34:34Z","tags":["license","info","xpack"],"pid":1,"message":"Imported license information from Elasticsearch for [data] cluster: mode: trial | status: active | expiry date: 2018-04-01T06:45:53+00:00"}
```

### 访问 kibana

**通过 kube-apiserver 访问**

获取 monitoring-grafana 服务 URL

```bash
shell> kubectl cluster-info
Kubernetes master is running at https://10.0.77.17:6443
Elasticsearch is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/elasticsearch-logging/proxy
Heapster is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/heapster/proxy
Kibana is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/kibana-logging/proxy
CoreDNS is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
monitoring-grafana is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/monitoring-grafana/proxy
monitoring-influxdb is running at https://10.0.77.17:6443/api/v1/namespaces/kube-system/services/monitoring-influxdb:http/proxy

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
```

浏览器访问 URL： https://10.0.77.17:6443/api/v1/proxy/namespaces/kube-system/services/kibana-logging/app/kibana

**通过 kubectl proxy 访问**

创建代理

```bash
shell> kubectl proxy --address='10.0.77.17' --port=8086 --accept-hosts='^*$'
Starting to serve on 10.0.77.17:8086
```

浏览器访问 URL：http://10.0.77.17:8086/api/v1/proxy/namespaces/kube-system/services/kibana-logging

在 Settings -> Indices 页面创建一个 index（相当于 mysql 中的一个 database），选中 Index contains time-based events，使用默认的 logstash-* pattern，点击 Create。

如果发现Create按钮是灰色的无法点击，且Time-filed name中没有选项，fluentd要读取/var/log/containers/目录下的log日志，这些日志是从`/var/lib/docker/containers/${CONTAINER_ID}/${CONTAINER_ID}-json.log`链接过来的，查看你的docker配置，--log-dirver需要设置为json-file格式，默认的可能是journald，[参考](https://docs.docker.com/engine/admin/logging/overview/#examples)。

```bash
shell> docker info |grep 'Logging Driver'
Logging Driver: json-file
```

![](http://p564fpez5.bkt.clouddn.com/image/k8skibana1.png)

创建Index后，可以在 Discover 下看到 ElasticSearch logging 中汇聚的日志。

![](http://p564fpez5.bkt.clouddn.com/image/k8skibana2.png)

## `have fun......`


