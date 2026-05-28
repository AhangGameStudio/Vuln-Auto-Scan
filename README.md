# Vuln-Auto-Scan

POC 自动化漏洞扫描器 v2.3 - 支持批量扫描和 HTML 报告生成

## 功能特性

- **自动化 POC 扫描**：基于 Markdown 格式的 POC 文件自动执行漏洞检测
- **智能指纹识别**：自动识别目标技术栈，智能筛选 POC
- **批量扫描**：支持从文件加载多个目标 URL 进行批量扫描
- **HTML 报告**：生成美观的漏洞扫描报告
- **断点续扫**：支持中断后从断点处继续扫描
- **自定义模块**：支持自定义 payload、验证器和扫描 profile
- **内存保护**：自动监控系统内存，防止内存溢出
- **并发控制**：可配置的请求速率和并发数

## 快速开始

### 1. 环境要求

- Python 3.6+
- 依赖库：`requests`, `urllib3`（程序会自动检测并安装）

### 2. 运行

```bash
python poc.py
```

首次运行时会自动下载 POC 库（从 GitHub 仓库）。

### 3. 基本使用

```
> 目标 URL: http://example.com
> scan
```

## 命令说明

### 核心命令

| 命令 | 说明 |
|------|------|
| `scan` | 开始扫描（单目标或批量） |
| `targets <文件>` | 加载批量目标 URL 列表 |
| `report` | 查看历史扫描报告 |
| `help` | 显示帮助信息 |
| `exit` | 退出程序 |

### 模块管理命令

#### Payload 管理

添加自定义 payload：

```bash
payload add <名称> <路径 1,路径 2,...> --type 类型 --must 关键词 --ban 关键词
```

**参数说明：**
- `--type`：漏洞类型（默认：custom）
- `--must`：响应必须包含的关键词
- `--ban`：响应不能包含的关键词

**示例：**
```bash
payload add spring_actuator /actuator,/actuator/env --type info_leak --must spring --ban login,403
```

#### Verify 管理

添加自定义验证规则：

```bash
verify add <名称> <正则表达式> --level high/medium --confidence 0.8 --fp 误报词
```

**参数说明：**
- `--level`：漏洞级别（high/medium）
- `--confidence`：置信度（0.0-1.0）
- `--fp`：误报过滤词（出现则不算漏洞）

**示例：**
```bash
verify add java 泄露 javax\\.sql\\.DataSource --level high --confidence 0.8 --fp example.com
```

#### Profile 管理

添加扫描 profile（用于智能筛选 POC）：

```bash
profile add <名称> --title 标题关键词 --header 头部关键词 --skip 跳过标签 --prior 优先标签
```

**参数说明：**
- `--title`：页面标题匹配关键词
- `--header`：响应头匹配关键词
- `--skip`：跳过的 POC 标签
- `--prior`：优先的 POC 标签

**示例：**
```bash
profile add 宝塔面板 --title 宝塔 --header BT-Panel --skip iis,asp --prior php,nginx
```

#### 其他命令

```bash
# 查看所有模块
list

# 查看特定类型模块
list payloads
list verifiers
list profiles

# 删除模块
remove <payload|verify|profile> <名称>
```

## 批量扫描

### 1. 创建目标文件

创建 `targets.txt` 文件，每行一个 URL：

```txt
# 注释行会被忽略
http://target1.com
http://target2.com
http://target3.com
```

### 2. 加载并扫描

```bash
> targets targets.txt
已加载 3 个目标

> scan
批量模式：3 个目标
```

## 配置文件

程序会自动读取/保存 `scanner_config.json` 配置文件：

```json
{
  "payload_interval": 2.0,
  "max_workers": 3,
  "request_timeout": 15,
  "max_retries": 2,
  "baseline_variance": 200,
  "min_confidence": 0.6,
  "max_memory_percent": 80.0,
  "response_truncate": 2000,
  "enable_checkpoint": true,
  "enable_prefilter": true,
  "report_dir": "scan_reports",
  "log_level": "INFO",
  "poc_folder": "POC"
}
```

**配置项说明：**

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `payload_interval` | Payload 请求间隔（秒） | 2.0 |
| `max_workers` | 最大并发数 | 3 |
| `request_timeout` | 请求超时时间（秒） | 15 |
| `max_retries` | 最大重试次数 | 2 |
| `baseline_variance` | 基线响应长度方差阈值 | 200 |
| `min_confidence` | 最小置信度阈值 | 0.6 |
| `max_memory_percent` | 最大内存使用百分比 | 80.0 |
| `response_truncate` | 响应截断长度 | 2000 |
| `enable_checkpoint` | 启用断点续扫 | true |
| `enable_prefilter` | 启用 POC 预筛选 | true |
| `report_dir` | 报告保存目录 | scan_reports |
| `log_level` | 日志级别 | INFO |
| `poc_folder` | POC 文件目录 | POC |

## 扫描报告

扫描完成后会自动生成 HTML 和 JSON 格式的报告：

- **HTML 报告**：`scan_reports/scan_<目标>_<时间戳>.html`
- **JSON 报告**：`scan_reports/scan_<目标>_<时间戳>.json`

**报告内容：**
- 扫描基本信息（目标、时间、耗时）
- 指纹识别结果
- 漏洞汇总统计
- 漏洞详情（POC 名称、请求方法、URL、状态码、置信度、Payload）
- 批量扫描结果（如适用）

## POC 文件格式

POC 文件使用 Markdown 格式，示例：

```markdown
# 漏洞名称

漏洞描述...

```plain
GET /vulnerable-endpoint HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0
```

```bash
GET /test?payload=<script>alert(1)</script> HTTP/1.1
```
```

支持的代码块格式：
- `plain`：纯文本请求
- `http`：HTTP 请求
- `bash`：命令行请求

## 模块目录结构

```
modules/
├── payloads/      # 自定义 payload 模块
├── verifiers/     # 自定义验证规则模块
└── profiles/      # 扫描 profile 模块
```

## 工作原理

1. **指纹识别**：访问目标网站，收集 Server、X-Powered-By、Title 等指纹信息
2. **技术栈分析**：根据指纹信息判断目标技术栈（Windows/Linux/Java/Node 等）
3. **POC 筛选**：智能筛选与目标技术栈匹配的 POC
4. **Payload 生成**：结合内置 payload 和自定义 payload 生成测试用例
5. **漏洞验证**：发送请求并使用正则表达式、关键词匹配等方式验证漏洞
6. **结果输出**：生成 HTML 报告并记录日志

## 高级特性

### 断点续扫

扫描中断后会自动保存进度，下次运行时可选择从断点处继续。

### 内存保护

当系统内存使用率超过阈值时自动暂停，等待内存恢复后继续。

### 智能预筛选

根据目标指纹信息自动跳过不相关的 POC，提高扫描效率。

### 自定义验证规则

支持多级置信度评估和误报过滤机制。

## 注意事项

1. **合法使用**：仅用于授权的安全测试，请勿用于非法用途
2. **网络环境**：自动下载 POC 库时需要访问 GitHub
3. **性能调优**：根据目标数量和网络状况调整并发参数
4. **误报处理**：高置信度漏洞建议人工复核

## 更新日志

### v2.3
- 支持批量扫描多个目标
- 新增 HTML 报告生成功能
- 优化 POC 预筛选机制
- 改进内存管理

## 许可证

MIT License

## 致谢

POC 库来源于：[PocStore](https://github.com/helloclw/PocStore)
