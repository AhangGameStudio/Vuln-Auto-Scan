# YApi NoSQL注入导致远程命令执行漏洞

## 漏洞描述


## 危害等级
CRITICAL

## 参考链接
- https://github.com/YMFE/yapi/commit/59bade3a8a43e7db077d38a4b0c7c584f30ddf8c
- https://github.com/vulhub/vulhub/blob/master/yapi/mongodb-inj/poc.py

## 漏洞复现方法
本漏洞的利用需要YApi应用中至少存在一个项目与相关数据，否则无法利用。Vulhub环境中的YApi是一个即开即用、包含测试数据的服务器，所以可以直接进行漏洞复现。

使用[这个POC](https://github.com/vulhub/vulhub/blob/master/yapi/mongodb-inj/poc.py)来复现漏洞：

```
python poc.py --debug one4all -u http://your-ip:3000/
```

![image-20221125164438168](images/202211251644280.png)

## Payloads
```
python poc.py --debug one4all -u http://your-ip:3000/
```
