## 安装 kube-dns 插件

Docker从1.13版本开始调整了默认的防火墙规则，禁用了iptables filter表中FOWARD链，这样会引起Kubernetes集群中跨Node的Pod无法通信，在各个Docker节点执行下面的命令：

iptables -P FORWARD ACCEPT
可在docker的systemd unit文件中以ExecStartPost加入上面的命令：

ExecStartPost=/usr/sbin/iptables -P FORWARD ACCEPT
systemctl daemon-reload
systemctl restart docker

K8S官方的yaml文件目录 [kubernetes/cluster/addons/dns/](https://github.com/kubernetes/kubernetes/tree/master/cluster/addons/dns)

该插件直接使用kubernetes部署，官方的配置文件中包含以下镜像：

> gcr.io/google_containers/k8s-dns-dnsmasq-nanny-amd64:1.14.8
  gcr.io/google_containers/k8s-dns-kube-dns-amd64:1.14.8
  gcr.io/google_containers/k8s-dns-sidecar-amd64:1.14.8

以下yaml配置文件中使用的是私有镜像仓库(10.0.77.16/acquaai)中的镜像。

```bash
shell> mkdir /etc/kubernetes/kube-dns
shell> ll kubedns-*
-rw-r--r-- 1 root root  731 Feb 25 09:28 kubedns-cm.yaml
-rw-r--r-- 1 root root 5402 Feb 25 09:28 kubedns-controller.yaml
-rw-r--r-- 1 root root  187 Feb 25 09:29 kubedns-sa.yaml
-rw-r--r-- 1 root root 1024 Feb 25 09:30 kubedns-svc.yaml
```

### 系统预定义的 RoleBinding

预定义的 RoleBinding system:kube-dns 将 kube-system 命名空间的 kube-dns ServiceAccount 与 system:kube-dns Role 绑定，该 Role 具有访问 kube-apiserver DNS 相关 API 的权限。

```yaml
shell> kubectl get clusterrolebindings system:kube-dns -o yaml

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  creationTimestamp: 2018-02-21T11:43:37Z
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:kube-dns
  resourceVersion: "85"
  selfLink: /apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system%3Akube-dns
  uid: 74a36125-16fc-11e8-a613-0050568879ea
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-dns
subjects:
- kind: ServiceAccount
  name: kube-dns
  namespace: kube-system
```

+ kubedns-controller.yaml 中定义的 Pods 时使用了 kubedns-sa.yaml 文件定义的 kube-dns ServiceAccount，所以具有访问 kube-apiserver DNS 相关 API 的权限。

### 配置 kube-dns ServiceAccount

无需修改。

### 配置 kube-dns 服务

```bash
shell> cat kubedns-svc.yaml
...
spec:
  selector:
    k8s-app: kube-dns
  clusterIP: 10.254.0.2
...
```

+ spec.clusterIP = 10.254.0.2，即明确指定了 kube-dns Service IP，这个 IP 需要和 kubelet 的 --cluster-dns 参数值一致。

### 配置 kube-dns Deployment

```bash
shell> cat kubedns-controller.yaml
...
image: 10.0.77.16/acquaai/k8s-dns-kube-dns-amd64:1.14.8
- --domain=cluster.local.

image: 10.0.77.16/acquaai/k8s-dns-dnsmasq-nanny-amd64:1.14.8
- --server=/cluster.local./127.0.0.1#10053

image: 10.0.77.16/acquaai/k8s-dns-sidecar-amd64:1.14.8
- --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local.,5,A
- --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local.,5,A
```

+ 使用系统已经做了 RoleBinding 的 kube-dns ServiceAccount，该账户具有访问 kube-apiserver DNS 相关 API 的权限。

修改后的 [*.yaml](https://github.com/acquaai/K8S/tree/master/docs/kube-dns) 文件

### 执行定义文件

```bash
shell> cd /etc/kubernetes/kube-dns
shell> kubectl create -f .
configmap "kube-dns" created
deployment "kube-dns" created
serviceaccount "kube-dns" created
service "kube-dns" created
```

### 检查 kubedns 功能

```bash
shell> vi my-nginx.yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: my-nginx
spec:
  replicas: 2
  template:
    metadata:
      labels:
        run: my-nginx
    spec:
      containers:
      - name: my-nginx
        image: 10.0.77.16/acquaai/nginx:1.9
        ports:
        - containerPort: 80

shell> kubectl create -f my-nginx.yaml
```

Export 该 Deployment, 生成 my-nginx 服务

```bash
shell> kubectl expose deploy my-nginx
shell> kubectl get services --all-namespaces |grep my-nginx
default       my-nginx          ClusterIP   10.254.23.60    <none>        80/TCP          18s
```

创建另一个Pod，查看 /etc/resolv.conf 是否包含 kubelet 配置的 --cluster-dns 和 --cluster-domain，是否能够将服务 my-nginx 解析到 Cluster IP 10.254.23.60。

```bash
shell> cat nginx-pod.yaml 
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: nginx-pod
spec:
  replicas: 2
  template:
    metadata:
      labels:
        run: nginx-pod
    spec:
      containers:
      - name: nginx-pod
        image: 10.0.77.16/acquaai/nginx:1.9
        ports:
        - containerPort: 80

shell> kubectl create -f nginx-pod.yaml

shell> kubectl exec  nginx-pod-66fd8579c5-qtd9k -i -t -- /bin/bash
root@nginx-pod-66fd8579c5-qtd9k:/# cat  /etc/resolv.conf 
nameserver 10.254.0.2
search default.svc.cluster.local. svc.cluster.local. cluster.local. k8s.com
options ndots:5

root@nginx-pod-66fd8579c5-qtd9k:/# ping my-nginx
ping: unknown host
root@nginx-pod-66fd8579c5-qtd9k:/# ping kubernetes
ping: unknown host
root@nginx-pod-66fd8579c5-qtd9k:/# ping kube-dns.kube-system.svc.cluster.local
ping: unknown host
```

从结果来看，service名称可以正常解析。
注意：直接ping ClusterIP是ping不通的，ClusterIP是根据IPtables路由到服务的endpoint上，只有结合ClusterIP加端口才能访问到对应的服务。


