# 飞鱼星 家用智能路由 cookie.cgi 权限绕过

## 漏洞描述
飞鱼星 家用智能路由存在权限绕过，通过Drop特定的请求包访问未授权的管理员页面

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202162236515.png)

访问 index.html 时会请求 cookie.cgi

```plain
http://xxx.xxx.xxx.xxx/index.html
```

