# ShowDoc 3.2.5 SQL 注入漏洞

## 漏洞描述
ShowDoc 是一个开源的在线共享文档工具。

ShowDoc <= 3.2.5 存在一处未授权 SQL 注入漏洞，攻击者可以利用该漏洞窃取保存在 SQLite 数据库中的用户密码和 Token。

参考链接：

- https://github.com/star7th/showdoc/commit/84fc28d07c5dfc894f5fbc6e8c42efd13c976fda

## 危害等级
HIGH

## 参考链接
- https://github.com/star7th/showdoc/commit/84fc28d07c5dfc894f5fbc6e8c42efd13c976fda

## 漏洞复现方法
当一个用户登录进 ShowDoc，其用户 token 将会被保存在 SQLite 数据库中。相比于获取 hash 后的用户密码，用户 token 是一个更好地选择。

在利用该漏洞前，需要安装验证码识别库 [ddddocr](https://github.com/sml2h3/ddddocr)，因为该漏洞需要每次请求前传入验证码：

```
pip install onnxruntime ddddocr requests
```

然后，执行 [这个POC](https://github.com/vulhub/vulhub/blob/master/showdoc/3.2.5-sqli/poc.py) 来获取 token：


## Payloads
```
pip install onnxruntime ddddocr requests
```
```
python poc.py -u http://your-ip:8080
```
```
Cookie: cookie_token=38f70784c511fe30f8686d5bf44bd0c5a830acd8e8c3efa9db63938f69e11f40
```
