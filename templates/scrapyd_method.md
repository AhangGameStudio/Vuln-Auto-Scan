# Scrapyd 未授权访问漏洞

## 漏洞描述
scrapyd是爬虫框架scrapy提供的云服务，用户可以部署自己的scrapy包到云服务，默认监听在6800端口。如果攻击者能访问该端口，将可以部署恶意代码到服务器，进而获取服务器权限。

参考链接：

- https://www.leavesongs.com/PENETRATION/attack-scrapy.html

## 危害等级
HIGH

## 参考链接
- https://www.leavesongs.com/PENETRATION/attack-scrapy.html

## 漏洞复现方法
参考[攻击Scrapyd爬虫](https://www.leavesongs.com/PENETRATION/attack-scrapy.html)，构造一个恶意的scrapy包：

```
$ pip install scrapy scrapyd-client
$ scrapy startproject evil
$ cd evil
```

编辑 `evil/__init__.py`, 加入恶意代码：


## Payloads
```
$ pip install scrapy scrapyd-client
$ scrapy startproject evil
$ cd evil
```
```
进行部署：
```
```
向API接口发送恶意包：
```
```
成功执行命令`touch awesome_poc`：

![image-20220228225416938](images/202202282254990.png)

同样的方法实现反弹shell，编辑 `evil/__init__.py`, 加入恶意代码：
```
```

```
```
进行部署：
```
```
向API接口发送恶意包：
```
