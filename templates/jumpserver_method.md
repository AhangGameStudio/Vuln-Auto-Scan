# JumpServer 未授权接口 远程命令执行漏洞

## 漏洞描述
JumpServer 是全球首款完全开源的堡垒机, 使用GNU GPL v2.0 开源协议, 是符合4A 的专业运维审计系统。 JumpServer 使用Python / Django 进行开发。2021年1月15日，阿里云应急响应中心监控到开源堡垒机JumpServer发布更新，修复了一处远程命令执行漏洞。由于 JumpServer 某些接口未做授权限制，攻击者可构造恶意请求获取到日志文件获取敏感信息，或者执行相关API操作控制其中所有机器。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
进入后台添加配置

**资产管理 -->  系统用户**



![](images/202202101943889.png)




## Payloads
```
新版对用户进行了一个判断，可以使用 谷歌插件 WebSocket King 连接上这个websocket 进行日志读取



![](images/202202101943143.png)



比如send这里获取的 Task id ,这里是可以获得一些敏感的信息的



![](images/202202101944092.png)



查看一下连接Web终端的后端api代码



![](images/202202101944673.png)



可以看到这里调用时必须需要 **user asset system_user** 这三个值，再获取一个20秒的 **token**



访问web终端后查看日志的调用



![](images/202202101944023.png)
```
```
![](images/202202101944593.png)
```
