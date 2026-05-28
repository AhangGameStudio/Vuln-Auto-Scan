# 金山 V8 终端安全系统 pdf_maker.php 命令执行漏洞

## 漏洞描述
金山 V8 终端安全系统 pdf_maker.php 存在命令执行漏洞，由于没有过滤危险字符，导致构造特殊字符即可进行命令拼接执行任意命令

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
存在漏洞的文件为



```plain
Kingsoft\Security Manager\SystemCenter\Console\inter\pdf_maker.php
```




## Payloads
```

```
```
![](images/202202091834810.png)



这里传入 base64加密的拼接命令即可执行任意命令
```
```

```
