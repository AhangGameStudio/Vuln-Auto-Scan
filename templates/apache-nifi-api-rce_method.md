# Apache NiFi Api 远程代码执行 RCE

## 漏洞描述
Apache NiFi是Apache Software Foundation的一个软件项目，旨在使软件系统之间的数据流自动化。

参考链接：

- https://twitter.com/chybeta/status/1333341820596568065
- https://github.com/imjdl/Apache-NiFi-Api-RCE
- https://forum.ywhack.com/thread-114763-1-3.html

## 危害等级
CRITICAL

## 参考链接
- https://twitter.com/chybeta/status/1333341820596568065
- https://github.com/imjdl/Apache-NiFi-Api-RCE
- https://forum.ywhack.com/thread-114763-1-3.html

## 漏洞复现方法
exp：

```python
import sys
import json
import requests as req


class Exp:
    def __init__(self, url):
