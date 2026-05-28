# JD-FreeFuck 后台命令执行漏洞

## 漏洞描述
JD-FreeFuck 存在后台命令执行漏洞，由于传参执行命令时没有对内容过滤，导致可以执行任意命令，控制服务器

项目地址： https://github.com/meselson/JD-FreeFuck

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
访问后登录页面如下

![](images/202202101952995.png)



默认账号密码为

**useradmin/supermanito**


## Payloads
```
其中 cmd 参数存在命令注入



![](images/202202101952947.png)



反弹shell
```
