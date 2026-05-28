# Nacos 集群 Raft 反序列化漏洞 CNVD-2023-45001

## 漏洞描述
该漏洞源于 Nacos 集群处理部分 Jraft 请求时，未限制使用 hessian 进行反 。序列化，攻击者可以通过发送特制的请求触发该漏洞，最终执行任意远程代码。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
exp：https://github.com/c0olw/NacosRce/
