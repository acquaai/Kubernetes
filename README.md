# Creating HA cluster 1.15 with kubeadm on Ubuntu 18.04 LTS

## Getting started

### Stacked control plane and etcd nodes HA topology

![Snip20190817_1](media/15650527433799/Snip20190817_1.png)


### HA Planning

<style>
table th:first-of-type {
    width: 140px;
}
</style>

| Role | IP | Components |
| :-: | :-: | :-: |
| cp-172-31-16-11 | 172.31.16.11 | etcd, apiserver, controller, scheduler |
| cp-172-31-16-12 | 172.31.16.12 | etcd, apiserver, controller, scheduler |
| cp-172-31-16-13 | 172.31.16.13 | etcd, apiserver, controller, scheduler |
| w-172-31-16-14 | 172.31.16.14 | |
| ...w-... | | |


### Installing Ubuntu 18.04 LTS Server OS

During installing, select and install software

 + [*] openssh-server
 + extend `/` filesystem or installing adjust(very very important)
 
```zsh
lsblk

NAME                      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
...
sda                         8:0    0  100G  0 disk
├─sda1                      8:1    0    1M  0 part
├─sda2                      8:2    0    1G  0 part /boot
└─sda3                      8:3    0   99G  0 part
  └─ubuntu--vg-ubuntu--lv 253:0    0   94G  0 lvm  /
...

sudo lvextend /dev/ubuntu-vg/ubuntu-lv /dev/sda3
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
df -h
```


#### Configuring interface bonding or not

```yaml
$ sudo lshw -class network
$ sudo vim /etc/netplan/50-cloud-init.yaml

network:
    bonds:
        bond0:
            addresses:
            - 172.31.16.14/24
            gateway4: 172.31.16.1
            interfaces:
            - eno1
            - eno2
            nameservers:
                addresses:
                - 114.114.114.114
                - 8.8.8.8
            parameters:
                mode: balance-rr
    ethernets:
        eno1: {}
        eno2: {}
    version: 2

$ sudo netplan [--debug] apply
$ systemd-resolve --status
```


#### Configuring hostname

```zsh
$ sudo hostnamectl set-hostname role-x-x-x-x
```


## Installing ansible control node

+ [Installation Guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#basics-what-will-be-installed)
+ debugging connection between ansible control node and k8s nodes
 + `ansible -i k8s-hosts -m ping -vvv`


## Initial k8s nodes with ansible-playbooks

### Inventory basics: hosts and groups

```yaml
#k8s-hosts

[cp]
cp-172-31-16-11 ansible_host=172.31.16.11 ansible_user=k8s
cp-172-31-16-12 ansible_host=172.31.16.12 ansible_user=k8s
cp-172-31-16-13 ansible_host=172.31.16.13 ansible_user=k8s

[cp-12-13]
cp-172-31-16-12 ansible_host=172.31.16.12 ansible_user=k8s
cp-172-31-16-13 ansible_host=172.31.16.13 ansible_user=k8s

[worker]
w-172-31-16-14 ansible_host=172.31.16.14 ansible_user=k8s
```


### Production environment

#### General level

```yaml
---
- name: General Configuration
  hosts: all
  become: yes

  tasks:
    - name: set authorized key taken from file
      become: no
      authorized_key:
        user: k8s
        key: "{{ lookup('file', '/root/.ssh/id_rsa.pub') }}"
        state: present
        manage_dir: yes

    - name: disable UFW
      ufw:
        state: disabled

    - name: add k8s user to the sudoers
      copy:
        content: 'k8s  ALL=(ALL)  NOPASSWD: ALL'
        dest: /etc/sudoers.d/k8s

    - name: update apt cache
      apt:
         update_cache=yes
         force_apt_get=yes

    - name: upgrade packages
      apt: upgrade=dist

    - name: install linux-image-generic
      apt:
        name: linux-image-generic

    - name: check if a reboot is required
      register: reboot_required_file
      stat: path=/var/run/reboot-required get_md5=no

    - name: restart machine
      shell: sleep 2 && shutdown -r now "Ansible updates triggered"
      async: 1
      poll: 0
      ignore_errors: true
      when: reboot_required_file.stat.exists == true

    - name: waiting for server to come back
      become: no
      wait_for:
        port=22
        host={{ inventory_hostname }}
        search_regex=OpenSSH
        delay=10
      connection: local

    - name: edit the localhost entry with our own
      blockinfile:
        dest: /etc/hosts
        block: |
          172.31.16.11 cp-172-31-16-11
          172.31.16.12 cp-172-31-16-12
          172.31.16.13 cp-172-31-16-13
          172.31.16.14 w-172-31-16-14
        backup: yes

    - name: disable SWAP (1/2)
      shell: |
        swapoff -a

    - name: disable SWAP in fstab (2/2)
      replace:
        path: /etc/fstab
        regexp: '^(.+?\sswap\s+sw\s+.*)$'
        replace: '# \1'

    - name: set timezone to Asia/Shanghai (1/9)
      timezone:
        name: Asia/Shanghai

    - name: install ntp/ntpdate (2/9)
      apt:
        name: "{{ packages }}"
        update_cache: yes
      vars:
        packages:
        - ntp
        - ntpdate

    - name: empty ntp.conf file (3/9)
      copy:
        dest: /etc/ntp.conf
        content: ''
        force: yes
        backup: yes

    - name: edit the localhost entry with our own (4/9)
      blockinfile:
        dest: /etc/ntp.conf
        block: |
          restrict 127.0.0.1
          server time.yubang168.cn
          server ntp1.aliyun.com
          restrict default kod nomodify notrap nopeer noquery
          restrict -6 default kod nomodify notrap nopeer noquery
          restrict -6 ::1
          driftfile /var/lib/ntp/drift
          keys /etc/ntp/keys

    - name: stop ntp (5/9)
      systemd:
        state: stopped
        name: ntp

    - name: sync time initialy (6/9)
      shell: ntpdate 10.0.88.118

    - name: start ntp (7/9)
      systemd:
        state: started
        name: ntp

    - name: enable ntp service start on boot (8/9)
      systemd:
        name: ntp
        state: started
        enabled: yes

    - name: sync hwclock (9/9)
      shell: hwclock -w
      
# ansible-playbook -i k8s-hosts initial-general.yml -k -K      
```


#### Kernel level

```yaml
- name: Kernel Configuration
  hosts: all
  become: yes

  tasks:
    - name: load nf_conntrack_ipv4 module
      modprobe:
        name: nf_conntrack_ipv4
        state: present

    - name: load network bridges module
      modprobe:
        name: br_netfilter
        state: present

    - name: load ip_vs module
      modprobe:
        name: ip_vs
        state: present

    - name: load ip_vs_rr module
      modprobe:
        name: ip_vs_rr
        state: present

    - name: load ip_vs_wrr module
      modprobe:
        name: ip_vs_wrr
        state: present

    - name: load ip_vs_sh module
      modprobe:
        name: ip_vs_sh
        state: present

    - name: load ipip module
      modprobe:
        name: ipip
        state: present

    - name: load modules after reboot
      blockinfile:
        dest: /etc/modules
        block: |
          ip_vs
          ip_vs_rr
          ip_vs_wrr
          ip_vs_sh
          nf_conntrack_ipv4
          br_netfilter
          ipip
        backup: yes

    - name: adjust kernel parameters
      blockinfile:
        dest: /etc/sysctl.d/k8s.conf
        block: |
          net.ipv4.ip_forward=1
          net.ipv6.conf.all.disable_ipv6=1
          net.bridge.bridge-nf-call-iptables=1
          net.bridge.bridge-nf-call-ip6tables=1
          net.netfilter.nf_conntrack_max=2310720
          vm.overcommit_memory=1
          vm.panic_on_oom=0
          vm.swappiness=0
          fs.inotify.max_user_watches=89100
          fs.file-max=52706963
          fs.nr_open=52706963
        create: yes
        validate: /sbin/sysctl -p %s

# ansible-playbook -i k8s-hosts initial-kernel.yml
```


### Installing Docker-CE

```yaml
- name: installing docker
  hosts: all
  become: yes

  tasks:
    - name: equivalent of apt-get update
      apt:
        update_cache=yes
      tags:
      - noproxy

    - name: install packages
      apt:
        name: "{{ packages }}"
        update_cache: yes
        state: present
      vars:
        packages:
        - ipset
        - ipvsadm
        - apt-transport-https
        - ca-certificates
        - curl
        - gnupg-agent
        - software-properties-common
      tags:
      - noproxy

    - name: install GPG key for docker with aliyum mirror
      apt_key:
        url: http://mirrors.aliyun.com/docker-ce/linux/ubuntu/gpg
        state: present
      tags:
      - noproxy

    - name: add docker repository with aliyum mirror
      apt_repository:
        repo: deb [arch=amd64] http://mirrors.aliyun.com/docker-ce/linux/ubuntu bionic stable
        state: present
        filename: docker-repo
        update_cache: yes
      tags:
      - noproxy

    - name: install docker-ce. list the versions by 'apt-cache madison docker-ce'
      apt:
        name: "{{ items }}"
        update_cache: yes
        state: present
      vars:
        items:
        - docker-ce=5:18.09.8~3-0~ubuntu-bionic
        - docker-ce-cli=5:18.09.8~3-0~ubuntu-bionic
        - containerd.io
      tags:
      - noproxy

    - name: manage docker as a non-root user
      user:
        name: k8s
        groups: docker
        append: yes
      tags:
      - noproxy

    - name: change docker cgroup driver from cgroupfs to systemd
      copy:
        dest: /etc/docker/daemon.json
        content: |
          {
            "exec-opts": ["native.cgroupdriver=systemd"],
            "log-driver": "json-file",
            "log-opts": {
            "max-size": "100m"
            },
            "storage-driver": "overlay2",
            "registry-mirrors": ["https://registry.cn-hangzhou.aliyuncs.com"]
          }
        force: yes
      tags:
      - noproxy

    - name: create docker.service.d directory
      file:
        path: /etc/systemd/system/docker.service.d
        state: directory
      tags:
      - noproxy

    - name: proxy for docker
      copy:
        dest: /etc/systemd/system/docker.service.d/proxy.conf
        content: |
          [Service]
          Environment="HTTP_PROXY=http://10.30.1.99:1080"
          Environment="HTTPS_PROXY=http://10.30.1.99:1080"
          Environment="NO_PROXY=localhost,127.0.0.1,172.31.18.12"
        force: yes
      tags:
      - proxy

    - name: recreate resolv.conf symlink
      file:
        src: /run/systemd/resolve/resolv.conf
        dest: /etc/resolv.conf
        owner: root
        group: root
        state: link
        mode: '1777'
        force: ye
      tags:
      - noproxy
    
    - name: Configure Pod DNS
      copy:
        dest: /etc/resolv.conf
        content: |
          nameserver 10.0.77.78
        force: yes
      tags:
      - noproxy  
    
    - name: restart docker
      systemd:
        state: restarted
        daemon_reload: yes
        name: docker
      tags:
      - noproxy

    - name: check docker is running
      systemd:
        name: docker
        state: started
        enabled: yes
      tags:
      - noproxy
```

+ "insecure-registries": [172.31.18.12],
+ "dns": ["114.114.114.114"],
+ "dns-opts": ["ndots:5","timeout:2","attempts:2"],
+ "dns-search": ["default.svc.cluster.local","svc.cluster.local","cluster.local"]

```zsh
# ansible-playbook -i k8s-hosts inst-docker.yml --tags "noproxy"
(Optional: proxy for docker)
# ansible-playbook -i k8s-hosts inst-docker.yml --tags "proxy"
```


## Customizing control plane configuration with kubeadm

### Using Nginx as load balancer reverse proxy apiserver

Deploy Nginx proxy for apiserver on control-plane nodes. Due to 6443 as apiserver default port, so using 8443 as Nginx proxy listening port.


#### Customizing Nginx configuration

```xml
# nginx.conf

error_log stderr notice;
worker_processes auto;

events {
  multi_accept on;
  use epoll;
  worker_connections 4096;
}

stream {
    upstream kube_apiserver {
        least_conn;
        server 172.31.16.11:6443;
        server 172.31.16.12:6443;
        server 172.31.16.13:6443;
    }

    server {
        listen        0.0.0.0:8443;
        proxy_pass    kube_apiserver;
        proxy_timeout 10m;
        proxy_connect_timeout 1s;
    }
}
```


#### Customizing Nginx service configuration

```xml
# lb.service

[Unit]
Description=kubernetes apiserver docker wrapper
Wants=docker.socket
After=docker.service

[Service]
User=root
PermissionsStartOnly=true
ExecStart=/usr/bin/docker run -p 127.0.0.1:8443:6443 \
                              -v /etc/nginx:/etc/nginx \
                              --name lb \
                              --network="host" \
                              --restart=on-failure:3 \
                              --memory=512M \
                              nginx
ExecStartPre=-/usr/bin/docker rm -f lb
ExecStop=/usr/bin/docker stop lb
Restart=always
RestartSec=15s
TimeoutStartSec=30s

[Install]
WantedBy=multi-user.target
```


#### Distributing configurations to all nodes

```yaml
- name: load balancer
  hosts: all
  become: yes

  tasks:
    - name: create a directory for nginx
      file:
        path: /etc/nginx
        state: directory

    - name: delivery nginx.conf
      copy:
        src: /etc/ansible/k8s/nginx.conf
        dest: /etc/nginx/nginx.conf
        owner: root
        group: root
        mode: '0644'

    - name: delivery lb service
      copy:
        src: /etc/ansible/k8s/lb.service
        dest: /etc/systemd/system/lb.service
        owner: root
        group: root
        mode: '0755'

    - name: restart lb service
      systemd:
        state: restarted
        daemon_reload: yes
        name: lb

    - name: check lb service is running
      systemd:
        name: lb
        state: started
        enabled: yes

# ansible-playbook -i k8s-hosts deploy-lb.yml
```


### Installing kubelet, kubeadm, kubectl on all nodes

*Due to the GFW is too high, so using aliyun mirrors*.

```yaml
- name: installing kubelet kubeadm kubectl
  hosts: all
  become: yes

  tasks:
    - name: add aliyun apt-key
      apt_key:
        url: https://mirrors.aliyun.com/kubernetes/apt/doc/apt-key.gpg
        state: present

    - name: add k8s repository
      apt_repository:
        repo: deb https://mirrors.aliyun.com/kubernetes/apt kubernetes-xenial main
        state: present
        filename: k8s-repo
        update_cache: yes

    - name: install kubelet kubeadm kubectl
      apt:
        name: "{{ items }}"
        state: present
      vars:
        items:
        - kubelet
        - kubeadm
        - kubectl

    - name: check kubelet is running
      systemd:
        name: kubelet
        state: started
        enabled: yes

# ansible-playbook -i k8s-hosts inst-kubeadm.yml
```


## Initialling cluster with kubeadm

### Configuring proxy for kubeadm

Kubeadm initial need to access google resources, you will see: **could not fetch a Kubernetes version from the internet: unable to get URL "https://dl.k8s.io/release/stable-1.txt"**

**Optional: proxy for kubeadm**

```yaml
- name: proxy
  hosts: all
  become: yes

  tasks:
    - name: proxy for kubeadm
      blockinfile:
        dest: /home/k8s/.bashrc
        block: |
          export http_proxy='http://10.30.1.99:1080'
          export https_proxy=$http_proxy
          export no_proxy='127.0.0.1, localhost, 172.31.16.11'
        backup: yes

    - name: enable proxy
      shell: source /home/k8s/.bashrc
      args:
        executable: /bin/bash

# ansible-playbook -i k8s-hosts -l control-plane proxy-kubeadm.yml
```


### Default configurations

```yaml
$ kubeadm config print init-defaults

apiVersion: kubeadm.k8s.io/v1beta2
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: abcdef.0123456789abcdef
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: 1.2.3.4
  bindPort: 6443
nodeRegistration:
  criSocket: /var/run/dockershim.sock
  name: control-plane01
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
---
apiServer:
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta2
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controllerManager: {}
dns:
  type: CoreDNS
etcd:
  local:
    dataDir: /var/lib/etcd
imageRepository: k8s.gcr.io
kind: ClusterConfiguration
kubernetesVersion: v1.14.0
networking:
  dnsDomain: cluster.local
  serviceSubnet: 10.96.0.0/12
scheduler: {}
```

### Customizing configuration file

```yaml
$ kubeadm config print init-defaults > defaults-kubeadm.yml
$ cat defaults-kubeadm.yml

apiVersion: kubeadm.k8s.io/v1beta2
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: abcdef.0123456789abcdef
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
 #advertiseAddress: 1.2.3.4
  advertiseAddress: 127.0.0.1
  bindPort: 6443
nodeRegistration:
  criSocket: /var/run/dockershim.sock
  name: control-plane01
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
---
apiServer:
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta2
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
#
controlPlaneEndpoint: 127.0.0.1:8443
controllerManager: {}
dns:
  type: CoreDNS
etcd:
  local:
    dataDir: /var/lib/etcd
#imageRepository: k8s.gcr.io
imageRepository: registry.cn-hangzhou.aliyuncs.com/google_containers
kind: ClusterConfiguration
#kubernetesVersion: v1.14.0
kubernetesVersion: v1.15.0
networking:
  dnsDomain: cluster.local
  #
  podSubnet: 10.244.0.0/16
  serviceSubnet: 10.96.0.0/12
scheduler: {}
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
```

> By default, your cluster will not schedule pods on the control-plane node for security reasons. If you want to be able to schedule pods on the control-plane node.

>```yaml
  taints:
  - effect: PreferNoSchedule
    key: node-role.kubernetes.io/master 
```

(Optional) Run kubeadm config images pull prior to kubeadm init to verify connectivity to gcr.io registries.

```zsh
kubeadm config images list
kubeadm config images pull
```


### Initialling kubernetes cluster

`Caution`: **ansible -i k8s-hosts all -m shell -a 'date'**

```zsh
$ sudo kubeadm init --config defaults-kubeadm.yml

... (log output of inital workflow) ...
Your Kubernetes control-plane has initialized successfully!

To start using your cluster, you need to run the following as a regular user:

  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

You can now join any number of control-plane nodes by copying certificate authorities
and service account keys on each node and then running the following as root:

  kubeadm join 127.0.0.1:8443 --token abcdef.0123456789abcdef \
    --discovery-token-ca-cert-hash sha256:620285ba02c4ff03f537ab1f1751c0baa538f84d7cfce4648d7f7e70b4f86f3e \
    --control-plane

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join 127.0.0.1:8443 --token abcdef.0123456789abcdef \
    --discovery-token-ca-cert-hash sha256:620285ba02c4ff03f537ab1f1751c0baa538f84d7cfce4648d7f7e70b4f86f3e
```

**To configure using cluster for a regular user**

```zsh
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/k8s/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

**Get Cluster Status**

```zsh
$ kubectl get cs
NAME                 STATUS    MESSAGE             ERROR
scheduler            Healthy   ok                  
controller-manager   Healthy   ok                  
etcd-0               Healthy   {"health":"true"}
```

**reset all kubeadm installed state if the initial was failed**

```zsh
$ sudo kubeadm reset
```


## Joining control-plane nodes

### Copy PKI to others

Create a directory for certificates on other control-plane nodes.

```zsh
$ ansible -i k8s-hosts cp-12-13 -m shell -a 'mkdir -p /etc/kubernetes/pki/etcd' --become
```

Sync files.

```yaml
---
- name: copy certificates
  hosts: all
  become: yes

  tasks:
    - name: Fetch the ca.crt file from control plane01 to ansible controller (1/2)
      synchronize:
        mode: pull
        src: /etc/kubernetes/pki/ca.crt
        dest: /etc/ansible/k8s/certs/
        group: yes
        owner: yes
        perms: yes
      tags:
      - pull

    - name: Fetch the ca.key file from control plane01 to ansible controller (2/2)
      synchronize:
        mode: pull
        src: /etc/kubernetes/pki/ca.key
        dest: /etc/ansible/k8s/certs/
        group: yes
        owner: yes
        perms: yes
      tags:
      - pull

    - name: Fetch the sa.key file from control plane01 to ansible controller (1/2)
      synchronize:
        mode: pull
        src: /etc/kubernetes/pki/sa.key
        dest: /etc/ansible/k8s/certs/
        group: yes
        owner: yes
        perms: yes
      tags:
      - pull

    - name: Fetch the sa.pub file from control plane01 to ansible controller (2/2)
      synchronize:
        mode: pull
        src: /etc/kubernetes/pki/sa.pub
        dest: /etc/ansible/k8s/certs/
        group: yes
        owner: yes
        perms: yes
      tags:
      - pull

    - name: Fetch the front proxy files from control plane01 to ansible controller (1/2)
      synchronize:
        mode: pull
        src: /etc/kubernetes/pki/front-proxy-ca.crt
        dest: /etc/ansible/k8s/certs/
        group: yes
        owner: yes
        perms: yes
      tags:
      - pull

    - name: Fetch the front proxy files from control plane01 to ansible controller (2/2)
      synchronize:
        mode: pull
        src: /etc/kubernetes/pki/front-proxy-ca.key
        dest: /etc/ansible/k8s/certs/
        group: yes
        owner: yes
        perms: yes
      tags:
      - pull

    - name: Fetch the etcd files from control plane01 to ansible controller (1/2)
      synchronize:
        mode: pull
        src: /etc/kubernetes/pki/etcd/ca.crt
        dest: /etc/ansible/k8s/certs/etcd/
        group: yes
        owner: yes
        perms: yes
      tags:
      - pull

    - name: Fetch the etcd files from control plane01 to ansible controller (2/2)
      synchronize:
        mode: pull
        src: /etc/kubernetes/pki/etcd/ca.key
        dest: /etc/ansible/k8s/certs/etcd/
        group: yes
        owner: yes
        perms: yes
      tags:
      - pull

    - name: Fetch the kubernetes file from control plane01 to ansible controller
      synchronize:
        mode: pull
        src: /etc/kubernetes/admin.conf
        dest: /etc/ansible/k8s/certs/
        group: yes
        owner: yes
        perms: yes
      tags:
      - pull

    - name: push the kubernetes file from ansible controller other control plane nodes
      synchronize:
        mode: push
        src: /etc/ansible/k8s/certs/admin.conf
        dest: /etc/kubernetes/
        group: yes
        owner: yes
        perms: yes
      tags:
      - push

    - name: push the rest files from ansible controller other control plane nodes
      synchronize:
        mode: push
        src: /etc/ansible/k8s/certs/
        dest: /etc/kubernetes/pki/
        group: yes
        owner: yes
        perms: yes
        dirs: yes
      tags:
      - push

    - name: delete admin.conf file
      file:
        path: /etc/kubernetes/pki/admin.conf
        state: absent
      tags:
      - push

# ansible-playbook -i k8s-hosts -l cp-172-31-16-11 cp-certs.yml --tags "pull"

# ansible-playbook -i k8s-hosts -l cp-12-13 cp-certs.yml --tags "push"
```


### Get token

Token is time sensitive, create a new token with `kubeadm token list/kubeadm token create –print-join-command` if token invalid.

If you don’t have the value of --discovery-token-ca-cert-hash, you can get it by running the following command chain on the control-plane node:

```zsh
openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | \
   openssl dgst -sha256 -hex | sed 's/^.* //'
```


### Join control-plane nodes
 
```zsh
sudo kubeadm join 127.0.0.1:8443 --token abcdef.0123456789abcdef \
    --discovery-token-ca-cert-hash sha256:620285ba02c4ff03f537ab1f1751c0baa538f84d7cfce4648d7f7e70b4f86f3e \
    --control-plane

... (log output of join workflow) ...
This node has joined the cluster and a new control plane instance was created:

* Certificate signing request was sent to apiserver and approval was received.
* The Kubelet was informed of the new secure connection details.
* Control plane (master) label and taint were applied to the new node.
* The Kubernetes control plane instances scaled up.
* A new etcd member was added to the local/stacked etcd cluster.

To start administering your cluster from this node, you need to run the following as a regular user:

	mkdir -p $HOME/.kube
	sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
	sudo chown $(id -u):$(id -g) $HOME/.kube/config

Run 'kubectl get nodes' to see this node join the cluster.
```


### Joining worker nodes

```zsh
k8s@w-172-31-16-14:~$ sudo kubeadm join 127.0.0.1:8443 --token abcdef.0123456789abcdef \
>     --discovery-token-ca-cert-hash sha256:620285ba02c4ff03f537ab1f1751c0baa538f84d7cfce4648d7f7e70b4f86f3e

... (log output of join workflow) ...
This node has joined the cluster:
* Certificate signing request was sent to apiserver and a response was received.
* The Kubelet was informed of the new secure connection details.

Run 'kubectl get nodes' on the control-plane to see this node join the cluster.

k8s@cp-172-31-16-11:~$ kubectl get nodes
NAME              STATUS     ROLES    AGE   VERSION
cp-172-31-16-11   NotReady   master   10h   v1.15.3
cp-172-31-16-12   NotReady   master   10h   v1.15.3
cp-172-31-16-13   NotReady   master   10h   v1.15.3
w-172-31-16-14    NotReady   <none>   10h   v1.15.3
w-172-31-16-15    NotReady   <none>   70s   v1.15.3
w-172-31-16-16    NotReady   <none>   30s   v1.15.3
```

(Optional) Controlling your cluster from machines other than the control-plane node

```zsh
scp root@<master ip>:/etc/kubernetes/admin.conf .
kubectl --kubeconfig ./admin.conf get nodes
```


### [Tear down](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/#tear-down)

Talking to the control-plane node with the appropriate credentials, run:

```zsh
kubectl drain <node name> --delete-local-data --force --ignore-daemonsets
kubectl delete node <node name>
kubeadm reset
```


### Installing a pod network add-on

`Caution`: This section contains important information about installation and deployment order. Read it carefully before proceeding.

You must install a pod network add-on so that your pods can communicate with each other.

**The network must be deployed before any applications. Also, CoreDNS will not start up before a network is installed. kubeadm only supports Container Network Interface (CNI) based networks (and does not support kubenet)**.

```zsh
k8s@cp-172-31-16-11:~$ kubectl get pod --all-namespaces | grep coredns
kube-system   coredns-6967fb4995-9zdlh    0/1     Pending   0          10h
kube-system   coredns-6967fb4995-sp62w    0/1     Pending   0          10h
```


#### K8s that meets the Calico system requirements

**Node requirements**

Calico must be able to manage `cali*` interfaces on the host. when IPIP is enabled(the default), Calico also needs to be able to manage `tunl*` interfaces.

```zsh
# ansible-playbook -i k8s-hosts cali-nm.yml
```


#### Installing with the Kubernetes API datastore—50 nodes or less

```zsh
k8s@cp-172-31-16-12:~$ curl https://docs.projectcalico.org/v3.8/manifests/calico.yaml -O

k8s@cp-172-31-16-12:~$ export POD_CIDR="10.244.0.0/16"
k8s@cp-172-31-16-12:~$ sed -i -e "s?192.168.0.0/16?$POD_CIDR?g" calico.yaml

k8s@cp-172-31-16-12:~$ kubectl apply -f calico.yaml

... (log output of install Calico workflow) ...
```

Type the following and watch the pods of the control plane components get started:

```zsh
k8s@cp-172-31-16-12:~$ kubectl get pods -n kube-system -w | grep calico
```


### Fetch cluster state

#### Nodes

```zsh
k8s@cp-172-31-16-12:~$ kubectl get nodes
NAME              STATUS   ROLES    AGE   VERSION
cp-172-31-16-11   Ready    master   11h   v1.15.3
cp-172-31-16-12   Ready    master   10h   v1.15.3
cp-172-31-16-13   Ready    master   10h   v1.15.3
w-172-31-16-14    Ready    <none>   10h   v1.15.3
w-172-31-16-15    Ready    <none>   37m   v1.15.3
w-172-31-16-16    Ready    <none>   36m   v1.15.3
```


#### Pods

```zsh
k8s@cp-172-31-16-11:~$ kubectl get pod --all-namespaces
NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE
kube-system   calico-kube-controllers-65b8787765-nnldc   1/1     Running   0          172m
kube-system   calico-node-7d6cr                          1/1     Running   0          172m
kube-system   calico-node-9jq2g                          1/1     Running   0          172m
kube-system   calico-node-p8cx8                          1/1     Running   0          172m
kube-system   calico-node-v5kgb                          1/1     Running   0          172m
kube-system   calico-node-vp4db                          1/1     Running   0          172m
kube-system   calico-node-wksf4                          1/1     Running   0          172m
kube-system   coredns-6967fb4995-9zdlh                   1/1     Running   0          14h
kube-system   coredns-6967fb4995-sp62w                   1/1     Running   0          14h
kube-system   etcd-cp-172-31-16-11                       1/1     Running   0          14h
kube-system   etcd-cp-172-31-16-12                       1/1     Running   0          13h
kube-system   etcd-cp-172-31-16-13                       1/1     Running   0          13h
kube-system   kube-apiserver-cp-172-31-16-11             1/1     Running   0          14h
kube-system   kube-apiserver-cp-172-31-16-12             1/1     Running   0          13h
kube-system   kube-apiserver-cp-172-31-16-13             1/1     Running   0          13h
kube-system   kube-controller-manager-cp-172-31-16-11    1/1     Running   1          14h
kube-system   kube-controller-manager-cp-172-31-16-12    1/1     Running   0          13h
kube-system   kube-controller-manager-cp-172-31-16-13    1/1     Running   0          13h
kube-system   kube-proxy-gfwzz                           1/1     Running   0          13h
kube-system   kube-proxy-mn47h                           1/1     Running   0          13h
kube-system   kube-proxy-pfpqs                           1/1     Running   0          3h25m
kube-system   kube-proxy-rv82v                           1/1     Running   0          14h
kube-system   kube-proxy-vzljr                           1/1     Running   0          3h25m
kube-system   kube-proxy-wfqqg                           1/1     Running   0          13h
kube-system   kube-scheduler-cp-172-31-16-11             1/1     Running   1          14h
kube-system   kube-scheduler-cp-172-31-16-12             1/1     Running   0          13h
kube-system   kube-scheduler-cp-172-31-16-13             1/1     Running   0          13h
```


#### SVC

```zsh
k8s@cp-172-31-16-11:~$ kubectl get svc --all-namespaces
NAMESPACE     NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)                  AGE
default       kubernetes   ClusterIP   10.96.0.1    <none>        443/TCP                  14h
kube-system   kube-dns     ClusterIP   10.96.0.10   <none>        53/UDP,53/TCP,9153/TCP   14h
```


#### IPVS

```zsh
k8s@cp-172-31-16-11:~$ sudo ipvsadm -L -n
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  10.96.0.1:443 rr
  -> 172.31.16.11:6443            Masq    1      1          0
  -> 172.31.16.12:6443            Masq    1      0          0
  -> 172.31.16.13:6443            Masq    1      1          0
TCP  10.96.0.10:53 rr
  -> 10.244.83.65:53              Masq    1      0          0
  -> 10.244.244.1:53              Masq    1      0          0
TCP  10.96.0.10:9153 rr
  -> 10.244.83.65:9153            Masq    1      0          0
  -> 10.244.244.1:9153            Masq    1      0          0
UDP  10.96.0.10:53 rr
  -> 10.244.83.65:53              Masq    1      0          0
  -> 10.244.244.1:53              Masq    1      0          0
```


### Testing Cluster DNS

```yaml
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
```

```zsh
kubectl create -f busybox.yaml
kubectl exec -ti busybox -- nslookup infoq.com
Server:		10.96.0.10
Address:	10.96.0.10:53

Non-authoritative answer:
Name:	infoq.com
Address: 199.119.126.68

*** Can't find infoq.com: No answer

k8s@cp-172-31-16-11:~/yaml$ kubectl get svc
NAME         TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.96.0.1       <none>        443/TCP   3d11h
nginx-svc    ClusterIP   10.107.164.84   <none>        80/TCP    119m

kubectl exec -ti busybox -- nslookup kubernetes
Server:		10.96.0.10
Address:	10.96.0.10:53

Name:	kubernetes.default.svc.cluster.local
Address: 10.96.0.1

kubectl exec -ti busybox -- nslookup nginx-svc
Server:		10.96.0.10
Address:	10.96.0.10:53

Non-authoritative answer:
Name:	nginx-svc.default.svc.cluster.local
Address: 10.107.164.84

kubectl exec -ti busybox -- cat /etc/resolv.conf
nameserver 10.96.0.10
search default.svc.cluster.local svc.cluster.local cluster.local
options ndots:5
```

## Deploy common components with Helm

### What's Helm

Helm is a tool for managing Kubernetes charts. Charts are packages of pre-configured Kubernetes resources.

Use Helm to:

 + Find and use popular software packaged as Helm charts to run in Kubernetes
 + Share your own applications as Helm charts
 + Create reproducible builds of your Kubernetes applications
 + Intelligently manage your Kubernetes manifest files
 + Manage releases of Helm packages

### Installing

`Caution`: Install Helm expect to meet kubectl tool and kubeconfig file.

```zsh
curl -O https://get.helm.sh/helm-v2.14.3-linux-amd64.tar.gz
tar xzvf helm-v2.14.3-linux-amd64.tar.gz
sudo cp linux-amd64/helm  /usr/bin/
```

[Role-based Access Control](https://helm.sh/docs/using_helm/#role-based-access-control)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tiller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: tiller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin   # too much power
subjects:
  - kind: ServiceAccount
    name: tiller
    namespace: kube-system    
```

```zsh
kubectl create -f helm-rbac.yml

serviceaccount/tiller created
clusterrolebinding.rbac.authorization.k8s.io/tiller created
```

**Tiller**

```zsh
helm init --service-account tiller --skip-refresh

Creating /home/k8s/.helm
Creating /home/k8s/.helm/repository
Creating /home/k8s/.helm/repository/cache
Creating /home/k8s/.helm/repository/local
Creating /home/k8s/.helm/plugins
Creating /home/k8s/.helm/starters
Creating /home/k8s/.helm/cache/archive
Creating /home/k8s/.helm/repository/repositories.yaml
Adding stable repo with URL: https://kubernetes-charts.storage.googleapis.com
Adding local repo with URL: http://127.0.0.1:8879/charts
$HELM_HOME has been configured at /home/k8s/.helm.

Tiller (the Helm server-side component) has been installed into your Kubernetes Cluster.

Please note: by default, Tiller is deployed with an insecure 'allow unauthenticated users' policy.
To prevent this, run `helm init` with the --tiller-tls-verify flag.
For more information on securing your installation see: https://docs.helm.sh/using_helm/#securing-your-helm-installation
```

`Caution GFW`:

 + gcr.io/kubernetes-helm/tiller
 + Adding stable repo with URL: https://kubernetes-charts.storage.googleapis.com

**Solution**

```zsh
kubectl get pod -n kube-system -l app=helm
NAME                             READY   STATUS         RESTARTS   AGE
tiller-deploy-767d9b9584-chsbs   0/1     ErrImagePull   0          115s

kubectl describe pod/tiller-deploy-767d9b9584-chsbs -n kube-system | grep 'Back-off pulling image'
......
Back-off pulling image "gcr.io/kubernetes-helm/tiller:v2.14.2"

docker pull xxx / docker tag xxx
helm reset
helm init --service-account tiller --tiller-image <registry>/tiller:v2.14.2 --skip-refresh

helm version
Client: &version.Version{SemVer:"v2.14.2", GitCommit:"a8b13cc5ab6a7dbef0a58f5061bcc7c0c61598e7", GitTreeState:"clean"}
Server: &version.Version{SemVer:"v2.14.2", GitCommit:"a8b13cc5ab6a7dbef0a58f5061bcc7c0c61598e7", GitTreeState:"clean"}
```

**Command auto completion**

```zsh
sourece <(helm completion zsh)
sourece <(helm completion bash)
```

### Change Helm chart repo

```zsh
helm repo add stable http://mirror.azure.cn/kubernetes/charts
helm repo list
NAME  	URL
stable	http://mirror.azure.cn/kubernetes/charts
local 	http://127.0.0.1:8879/charts

helm repo update
```


## Deploy Nginx Ingress with Helm

Ingress exposes HTTP and HTTPS routes from outside the cluster to services within the cluster. Traffic routing is controlled by rules defined on the Ingress resource.

An Ingress can be configured to give Services externally-reachable URLs, load balance traffice, terminate SSL/TLS, and offer name based virtual hosting. An Ingress controller is responsible for fulfilling the Ingress, usually with a load balancer, though it may also configure your edge router or additional frontends to help handle the traffic.

An Ingress does not expose arbitrary ports or protocols. Exposing services other than HTTP and HTTPS to the internet typically uses a service of type Service.Type=NodePort or Service.Type=LoadBalancer.

Pick `w-172-31-16-14` up as edge Node.

```zsh
kubectl label node w-172-31-16-14 node-role.kubernetes.io/edge=
node/w-172-31-16-14 labeled

kubectl get node
NAME              STATUS   ROLES    AGE     VERSION
cp-172-31-16-11   Ready    master   3d14h   v1.15.3
cp-172-31-16-12   Ready    master   3d13h   v1.15.3
cp-172-31-16-13   Ready    master   3d13h   v1.15.3
w-172-31-16-14    Ready    edge     3d13h   v1.15.3
w-172-31-16-15    Ready    <none>   3d3h    v1.15.3
w-172-31-16-16    Ready    <none>   3d3h    v1.15.3
```

`Caution`: here, you can use 2 edges and Keepalived VIP or VIPs to deploy.

**stable/nginx-ingress chart value file `ingress-nginx.yaml`**

```yaml
controller:
  replicaCount: 1 # or 2
  hostNetwork: true # bare metal host network
  nodeSelector:
    node-role.kubernetes.io/edge: '' #
  affinity:
    podAntiAffinity:
        requiredDuringSchedulingIgnoredDuringExecution:
        - labelSelector:
            matchExpressions:
            - key: app
              operator: In
              values:
              - nginx-ingress
            - key: component
              operator: In
              values:
              - controller
          topologyKey: kubernetes.io/hostname
  tolerations:
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: NoSchedule
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: PreferNoSchedule
defaultBackend:
  nodeSelector:
    node-role.kubernetes.io/edge: '' #
  tolerations:
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: NoSchedule
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: PreferNoSchedule
```

```zsh
helm repo update
helm install stable/nginx-ingress -n nginx-ingress --namespace ingress-nginx -f ingress-nginx.yaml

kubectl get pod -n ingress-nginx -o wide
NAME                                             READY   STATUS    RESTARTS   AGE     IP             NODE             NOMINATED NODE   READINESS GATES
nginx-ingress-controller-598c7fd878-twfwk        1/1     Running   0          2m34s   172.31.16.14   w-172-31-16-14   <none>           <none>
nginx-ingress-default-backend-7b8b45bd49-qsdcf   1/1     Running   0          2m34s   10.244.83.90   w-172-31-16-14   <none>           <none>
```

Chrome: http://172.31.16.14


## Deploy dashboard with Helm

**stable/kubernetes-dashboard chart value file `dashboard.yaml`**

```yaml
image:
  repository: k8s.gcr.io/kubernetes-dashboard-amd64
  tag: v1.10.1
ingress:
  enabled: true
  hosts:
    - k8s.acqua.com
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
  tls:
    - secretName: acqua-com-tls-secret
      hosts:
      - k8s.acqua.com
nodeSelector:
    node-role.kubernetes.io/edge: ''
tolerations:
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoSchedule
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: PreferNoSchedule
rbac:
  clusterAdminRole: true
```

```zsh
helm install stable/kubernetes-dashboard \
     -n kubernetes-dashboard \
     --namespace kube-system  \
     -f dashboard.yaml

kubectl get secret -n kube-system | grep dashboard-token
kubernetes-dashboard-token-l46hj                 kubernetes.io/service-account-token   3      77s

kubectl describe secret/kubernetes-dashboard-token-l46hj -n kube-system
Name:         kubernetes-dashboard-token-l46hj
Namespace:    kube-system
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: kubernetes-dashboard
              kubernetes.io/service-account.uid: fec3a854-aacf-4af5-861d-0d56e5f1e539

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1025 bytes
namespace:  11 bytes
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJrdWJlcm5ldGVzLWRhc2hib2FyZC10b2tlbi1sNDZoaiIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJrdWJlcm5ldGVzLWRhc2hib2FyZCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImZlYzNhODU0LWFhY2YtNGFmNS04NjFkLTBkNTZlNWYxZTUzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDprdWJlLXN5c3RlbTprdWJlcm5ldGVzLWRhc2hib2FyZCJ9.J0Xq4BqCjcq4NJv7dcfVV5W_ju5_b9LfVOF3tZ4A0GU4UQ9VQMaaiMOLSs5HOZRqc63rKioVGuOddjj-RuJvHUY90oD2MZtFDQTftauEIM54ae2ArbqgXSpF0531pCyAnH-FR0XQDe9TE_2F8lM0UKm2kvPcvZoPwSiQjsYZ3kwh0bTHi-1ViEhqiY5J45p62gfMHBA61tC5v2sO2t_oacv6EVqiiyGnayRHuvHJexw8WQsALzm0xFSoFzi-oknP6uu4vEOxfo2HcHa-VoFJWp2ijlHGEnHfAg3dlZzH-AiNKj2SkmscrFreLll2N8Ls_9JWTqo-t5sZ-dkeqB6dmA
```

https://k8s.acqua.com => 172.31.16.14

![dashboard](media/15650527433799/dashboard.png)


## Deploy metrics-server with Helm

[heapster](https://github.com/kubernetes/heapster) is substituted by [metrics-server](https://github.com/kubernetes-incubator/metrics-server).

```yaml
args:
- --logtostderr
- --kubelet-insecure-tls
- --kubelet-preferred-address-types=InternalIP
nodeSelector:
    node-role.kubernetes.io/edge: ''
tolerations:
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoSchedule
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: PreferNoSchedule
```

```zsh
helm install stable/metrics-server \
-n metrics-server \
--namespace kube-system \
-f metrics-server.yaml

kubectl get --raw "/apis/metrics.k8s.io/v1beta1/nodes"

kubectl top node
NAME              CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
cp-172-31-16-11   358m         8%     3129Mi          19%
cp-172-31-16-12   306m         7%     1972Mi          12%
cp-172-31-16-13   349m         8%     2011Mi          12%
w-172-31-16-14    217m         1%     1841Mi          0%
w-172-31-16-15    249m         1%     2325Mi          0%
w-172-31-16-16    161m         1%     1972Mi          0%

kubectl top pod -n kube-system
NAME                                       CPU(cores)   MEMORY(bytes)
calico-kube-controllers-65b8787765-s2vzg   5m           12Mi
calico-node-7d6cr                          34m          41Mi
calico-node-9jq2g                          42m          41Mi
calico-node-p8cx8                          30m          41Mi
calico-node-v5kgb                          29m          30Mi
calico-node-vp4db                          31m          31Mi
calico-node-wksf4                          31m          31Mi
coredns-6967fb4995-9zdlh                   4m           14Mi
coredns-6967fb4995-t99tz                   4m           12Mi
etcd-cp-172-31-16-11                       71m          71Mi
etcd-cp-172-31-16-12                       59m          68Mi
etcd-cp-172-31-16-13                       75m          66Mi
......
```

`Caution`: Unfortunately, the current version of Kubernetes [Dashboard](https://github.com/kubernetes/dashboard/issues/2986) doesn't support metrics-server.



+ **Ref**

 + [Creating Highly Available clusters with kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/)
 + [Docker Container networking](https://docs.docker.com/config/containers/container-networking/)
 + [Daemon CLI(dockerd)](https://docs.docker.com/engine/reference/commandline/dockerd/)
 + [Ansible Module](https://docs.ansible.com/ansible/latest/modules/modules_by_category.html)
 + [趣谈网络协议(容器技术中的网络)](https://time.geekbang.org/column/intro/85)
 + [Kubernetes Networking](https://www.slideshare.net/CJCullen/kubernetes-networking-55835829)
 + [Using Kubernete's Network Policies](https://www.slideshare.net/outlyer/christopher-liljenstolpe-cto-tigera-using-kubernetes-network-policies)
 + [Installing Calico for policy and networking](https://docs.projectcalico.org/v3.8/getting-started/kubernetes/installation/calico)
 + [Helm](https://helm.sh/docs/)
 + [netplan.io](https://netplan.io/examples)