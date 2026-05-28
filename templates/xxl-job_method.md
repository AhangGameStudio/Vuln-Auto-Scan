# XXL-JOB 后台任意命令执行漏洞

## 漏洞描述
XXL-JOB 是一个分布式任务调度平台，其核心设计目标是开发迅速、学习简单、轻量级、易扩展。现已开放源代码并接入多家公司线上产品线，开箱即用。XXL-JOB 分为 admin 和 executor 两端，前者为后台管理页面，后者是任务执行的客户端。

若 XXL-JOB 后台管理页面存在弱口令，攻击者可在 GLUE 模式任务代码中写入攻击代码并推送到执行器执行，从而获取服务器权限。

参考链接：

- https://github.com/xuxueli/xxl-job/issues/2979
- https://mp.weixin.qq.com/s/jzXIVrEl0vbjZxI4xlUm-g

## 危害等级
CRITICAL

## 参考链接
- https://github.com/xuxueli/xxl-job/issues/2979
- https://mp.weixin.qq.com/s/jzXIVrEl0vbjZxI4xlUm-g

## 漏洞复现方法
弱口令 `admin/123456` 登录后台，新增一个 GLUE 模式任务：

```
运行模式 GLUE(Shell)
```

![](images/XXL-JOB%20后台任意命令执行漏洞/image-20241112144436276.png)

点击 GLUE IDE，编辑脚本：


## Payloads
```
运行模式 GLUE(Shell)
```
