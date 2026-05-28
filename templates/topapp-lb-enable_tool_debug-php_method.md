# 天融信 TopApp-LB enable_tool_debug.php 远程命令执行漏洞

## 漏洞描述
天融信 TopSec-LB enable_tool_debug.php文件存在 远程命令执行漏洞，通过命令拼接攻击者可以执行任意命令

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面如下



![](images/202202091923792.png)



漏洞文件为 **enable_tool_debug.php**


## Payloads
```
**commandWrapper.inc** 文件中的 **runTool**
```
```
这里设置 var=0，tool=1，再进行命令拼接造成远程命令执行
```
