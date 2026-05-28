# 汇文 图书馆书目检索系统 config.properties 信息泄漏漏洞

## 漏洞描述
汇文 图书馆书目检索系统 /include/config.properties 文件中包含敏感信息，攻击者可以直接访问获取信息

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
主页面

![image-20220525144642895](images/202205251446991.png)

验证POC

```
/include/config.properties
```


## Payloads
```
/include/config.properties
```
