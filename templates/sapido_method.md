# Sapido 多款路由器 远程命令执行漏洞

## 漏洞描述
Sapido多款路由器在未授权的情况下，导致任意访问者可以以Root权限执行命令

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
固件中存在一个asp文件为 **syscmd.asp** 存在命令执行

![](images/202202162237726.png)

访问目标：

```plain
http://xxx.xxx.xxx.xxx/syscmd.asp
http://xxx.xxx.xxx.xxx/syscmd.htm
```
