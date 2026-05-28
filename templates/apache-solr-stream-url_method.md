# Apache Solr stream.url 任意文件读取漏洞

## 漏洞描述
Apache Solr 存在任意文件读取漏洞，攻击者可以在未授权的情况下获取目标服务器敏感文件。

参考链接：

- Apache Solr 组件安全概览 https://mp.weixin.qq.com/s/3WuWUGO61gM0dBpwqTfenQ 
- https://mp.weixin.qq.com/s/HMtAz6_unM1PrjfAzfwCUQ

## 危害等级
HIGH

## 参考链接
- https://mp.weixin.qq.com/s/HMtAz6_unM1PrjfAzfwCUQ

## 漏洞复现方法
访问 Solr Admin 管理员页面

![image-20220209120847764](images/202202091208853.png)

获取core的信息

```plain
http://xxx.xxx.xxx.xxx/solr/admin/cores?indexInfo=false&wt=json
```


## Payloads
```
![image-20220209120905965](images/202202091209053.png)

发送请求

![image-20220209120921295](images/202202091209396.png)

请求包如下
```
```
再进行文件读取

![image-20220209120956306](images/202202091209408.png)

请求包如下
```
```
![image-20220209121017516](images/202202091210638.png)

Curl请求为
```
