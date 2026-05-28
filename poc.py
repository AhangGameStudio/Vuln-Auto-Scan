import subprocess
import sys
import os
import json
import logging
import re
import time
import random
import hashlib
import socket
import threading
import queue
import base64
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple, Set, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Event
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import urllib3
from http.server import HTTPServer, BaseHTTPRequestHandler
from functools import lru_cache

from enum import Enum

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ScanPhase(Enum):
    RECON = "侦察"
    PROBE = "探测"
    ATTACK = "攻击"
    VERIFY = "验证"
    REPORT = "报告"

class VulnSeverity(Enum):
    CRITICAL = "严重"
    HIGH = "高危"
    MEDIUM = "中危"
    LOW = "低危"
    INFO = "信息"

class ToolDangerLevel(Enum):
    SAFE = 0
    CONFIRM = 1
    DANGEROUS = 2

REQUIRED_PACKAGES = ["requests", "urllib3"]

def check_and_install_packages():
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[依赖] 检测到缺失依赖：{', '.join(missing)}，正在安装...")
        python = sys.executable
        for pkg in missing:
            try:
                subprocess.check_call([python, "-m", "pip", "install", "--user", pkg])
                print(f"[依赖] 已安装：{pkg}")
            except subprocess.CalledProcessError:
                print(f"[依赖] 安装失败：{pkg}，请手动 pip install {pkg}")
                sys.exit(1)
    else:
        print(f"[依赖] 所有依赖已满足：{', '.join(REQUIRED_PACKAGES)}")

check_and_install_packages()

import requests

@dataclass
class Vulnerability:
    id: str
    type: str
    severity: VulnSeverity
    target: str
    endpoint: str
    payload: str
    confidence: float
    evidence: str
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    verified: bool = False
    cve_id: Optional[str] = None
    description: str = ""

@dataclass
class ScanConfig:
    payload_interval: float = 2.0
    max_workers: int = 5
    request_timeout: int = 10
    max_retries: int = 2
    retry_delay: float = 1.0
    baseline_variance: int = 200
    min_confidence: float = 0.6
    response_truncate: int = 0
    max_memory_percent: float = 90.0
    memory_check_interval: int = 50
    checkpoint_file: str = "scan_checkpoint.json"
    enable_checkpoint: bool = True
    enable_prefilter: bool = True
    probe_all_pages: bool = True
    max_attack_depth: int = 3
    report_dir: str = "scan_reports"
    log_level: str = "INFO"
    log_file: str = ""
    target_url: str = ""
    poc_folder: str = ""
    module_dir: str = "modules"
    kb_dir: str = "knowledge_base"
    poc_repo_url: str = "https://github.com/helloclw/PocStore"
    enable_attack_surface: bool = True
    attack_surface_threads: int = 10
    
    reverse_platform_host: str = "127.0.0.1"
    reverse_platform_http_port: int = 8888
    reverse_platform_dns_port: int = 5353
    reverse_platform_domain: str = "pocscan.local"
    
    template_dir: str = "templates"
    
    enable_advanced_crawler: bool = True
    crawler_headless: bool = False
    crawler_timeout: int = 30
    
    adaptive_concurrency_min: int = 1
    adaptive_concurrency_max: int = 50
    adaptive_concurrency_target_response_time: int = 2000
    adaptive_concurrency_error_threshold: float = 0.1
    
    verification_stages: int = 3
    
    nuclei_bulk_size: int = 25
    nuclei_template_threads: int = 25
    nuclei_rate_limit: int = 150
    nuclei_timeout: int = 10
    nuclei_retries: int = 2
    nuclei_max_redirects: int = 5
    nuclei_output_format: str = "jsonl"
    nuclei_workflow_dir: str = "workflows"
    nuclei_payload_dir: str = "payloads"
    nuclei_host_error_cache_ttl: int = 300
    nuclei_enable_dsl: bool = True
    nuclei_enable_workflows: bool = True

    def save(self, path: str = "scanner_config.json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.__dict__, f, indent=2, ensure_ascii=False)

    @classmethod
    def from_file(cls, path: str = "scanner_config.json") -> "ScanConfig":
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            known_fields = {f.name for f in cls.__dataclass_fields__.values()}
            filtered = {k: v for k, v in data.items() if k in known_fields}
            return cls(**filtered)
        return cls()

@dataclass
class Tool:
    name: str
    description: str
    func: Callable
    danger_level: int = 0
    pattern: str = ""

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, name: str, description: str, func: Callable,
                 danger_level: int = 0, pattern: str = ""):
        self._tools[name] = Tool(name=name, description=description,
                                 func=func, danger_level=danger_level, pattern=pattern)

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        return [{"name": t.name, "description": t.description, "danger": t.danger_level}
                for t in self._tools.values()]

    def execute(self, name: str, **kwargs) -> Any:
        tool = self.get(name)
        if not tool:
            return f"错误：工具 '{name}' 未注册"
        if tool.danger_level >= 2:
            return f"拒绝：工具 '{name}' 为危险工具，禁止自动执行"
        if tool.danger_level >= 1:
            confirm = input(f"工具 '{name}' 需要确认，是否执行？(y/n): ")
            if confirm.lower() != "y":
                return "已取消"
        try:
            return tool.func(**kwargs)
        except Exception as e:
            return f"工具执行失败：{e}"

    def match_from_text(self, text: str) -> List[Tool]:
        matched = []
        for tool in self._tools.values():
            if tool.pattern and re.search(tool.pattern, text, re.IGNORECASE):
                matched.append(tool)
        return matched

class IntentRouter:
    @staticmethod
    def route(user_input: str) -> str:
        text = user_input.lower().strip()
        if any(w in text for w in ["scan", "扫描", "扫", "开始扫描"]):
            return "scan"
        if any(w in text for w in ["recon", "侦察", "信息收集", "指纹"]):
            return "recon"
        if any(w in text for w in ["defend", "防御", "修复", "建议"]):
            return "defend"
        if any(w in text for w in ["learn", "学习", "日志", "log"]):
            return "learn"
        if any(w in text for w in ["diff", "对比", "比较", "差异"]):
            return "diff"
        if any(w in text for w in ["kb", "知识库", "knowledge"]):
            return "kb"
        if any(w in text for w in ["watch", "监控", "持续"]):
            return "watch"
        if any(w in text for w in ["help", "帮助", "命令", "command"]):
            return "help"
        if any(w in text for w in ["quit", "exit", "退出", "bye"]):
            return "quit"
        return "scan"

class KnowledgeBase:
    def __init__(self, kb_dir: str, logger: logging.Logger):
        self.kb_dir = kb_dir
        self.logger = logger
        os.makedirs(kb_dir, exist_ok=True)
        self.attack_patterns: List[Dict] = self._load("attack_patterns.json")
        self.defense_rules: List[Dict] = self._load("defense_rules.json")
        self.recon_history: List[Dict] = self._load("recon_history.json")

    def _load(self, filename: str) -> List[Dict]:
        path = os.path.join(self.kb_dir, filename)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save(self, filename: str, data):
        path = os.path.join(self.kb_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def add_attack_pattern(self, pattern: Dict):
        pattern["added"] = datetime.now().isoformat()
        self.attack_patterns.append(pattern)
        self._save("attack_patterns.json", self.attack_patterns)

    def add_defense_rule(self, rule: Dict):
        rule["added"] = datetime.now().isoformat()
        self.defense_rules.append(rule)
        self._save("defense_rules.json", self.defense_rules)

    def add_recon_record(self, record: Dict):
        record["timestamp"] = datetime.now().isoformat()
        self.recon_history.append(record)
        if len(self.recon_history) > 500:
            self.recon_history = self.recon_history[-500:]
        self._save("recon_history.json", self.recon_history)

    def stats(self) -> str:
        lines = [
            f"知识库统计:",
            f"  攻击模式：{len(self.attack_patterns)} 条",
            f"  防御规则：{len(self.defense_rules)} 条",
            f"  侦察记录：{len(self.recon_history)} 条",
        ]
        if self.attack_patterns:
            lines.append("  最近攻击模式:")
            for p in self.attack_patterns[-5:]:
                lines.append(f"    - [{p.get('type','?')}] {p.get('description','')[:50]}")
        return "\n".join(lines)

    def export_all(self) -> str:
        export = {
            "export_time": datetime.now().isoformat(),
            "attack_patterns": self.attack_patterns,
            "defense_rules": self.defense_rules,
            "recon_history": self.recon_history[-100:],
        }
        path = os.path.join(
            self.kb_dir,
            f"kb_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(path, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, ensure_ascii=False)
        return path

    def clear(self):
        self.attack_patterns.clear()
        self.defense_rules.clear()
        self.recon_history.clear()
        for f in ["attack_patterns.json", "defense_rules.json", "recon_history.json"]:
            path = os.path.join(self.kb_dir, f)
            if os.path.exists(path):
                os.remove(path)

class ReconModule:
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "ES", 27017: "MongoDB",
    }

    TECH_SIGNATURES = {
        "server": {"apache": "Apache", "nginx": "Nginx", "iis": "IIS",
                   "tomcat": "Tomcat", "express": "Express", "lighttpd": "Lighttpd"},
        "x_powered_by": {"php": "PHP", "asp.net": "ASP.NET", "express": "Express",
                         "next.js": "Next.js", "django": "Django"},
        "headers": {"x-aspnet-version": "ASP.NET", "x-drupal-cache": "Drupal",
                    "x-generator": "CMS", "x-rack-cache": "Ruby/Rack",
                    "x-varnish": "Varnish", "x-squid-error": "Squid"},
        "body": {"wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
                 "thinkphp": "ThinkPHP", "laravel": "Laravel", "django": "Django",
                 "spring": "Spring", "vue": "Vue.js", "react": "React"},
    }

    def __init__(self, config: ScanConfig, session: requests.Session,
                 logger: logging.Logger, kb: KnowledgeBase):
        self.config = config
        self.session = session
        self.logger = logger
        self.kb = kb

    def recon(self, url: str) -> Dict[str, Any]:
        self.logger.info(f"侦察开始：{url}")
        result = {"url": url, "timestamp": datetime.now().isoformat()}
        result["dns"] = self._dns_lookup(url)
        result["http"] = self._http_fingerprint(url)
        result["tech_stack"] = self._identify_tech(result.get("http", {}))
        host = result["dns"].get("ip", "")
        if host:
            result["ports"] = self._port_scan(host)
        if result.get("http"):
            result["security_headers"] = self._check_security_headers(result["http"])
        domain = self._extract_domain(url)
        if domain:
            result["subdomains"] = self._subdomain_enum(domain)
        result["risk_assessment"] = self._assess_risk(result)
        self.kb.add_recon_record(result)
        return result

    def _dns_lookup(self, url: str) -> Dict:
        domain = self._extract_domain(url)
        if not domain:
            return {"error": "无法解析域名"}
        result = {"domain": domain}
        try:
            ips = socket.getaddrinfo(domain, None, socket.AF_INET)
            ip_list = list(set(addr[4][0] for addr in ips))
            result["ip"] = ip_list[0] if ip_list else ""
            result["ips"] = ip_list
            if result["ip"]:
                try:
                    hostname, _, _ = socket.gethostbyaddr(result["ip"])
                    result["reverse_dns"] = hostname
                except:
                    pass
        except socket.gaierror:
            result["error"] = "DNS 解析失败"
        return result

    def _http_fingerprint(self, url: str) -> Dict:
        try:
            resp = self.session.get(url, timeout=self.config.request_timeout,
                                    allow_redirects=True, verify=False)
            headers = dict(resp.headers)
            return {
                "status_code": resp.status_code, "headers": headers,
                "server": headers.get("Server", ""),
                "x_powered_by": headers.get("X-Powered-By", ""),
                "content_type": headers.get("Content-Type", ""),
                "content_length": len(resp.text),
                "title": self._extract_title(resp.text),
                "redirects": [r.url for r in resp.history],
                "cookies": dict(resp.cookies),
            }
        except Exception as e:
            return {"error": str(e)}

    def _identify_tech(self, http_info: Dict) -> List[str]:
        techs = set()
        server = http_info.get("server", "").lower()
        for sig, name in self.TECH_SIGNATURES["server"].items():
            if sig in server:
                techs.add(name)
        xpb = http_info.get("x_powered_by", "").lower()
        for sig, name in self.TECH_SIGNATURES["x_powered_by"].items():
            if sig in xpb:
                techs.add(name)
        headers = http_info.get("headers", {})
        for header_name, sigs in self.TECH_SIGNATURES["headers"].items():
            if header_name in {k.lower() for k in headers.keys()}:
                for sig, name in sigs.items():
                    techs.add(name)
        return sorted(techs)

    def _port_scan(self, host: str) -> List[Dict]:
        open_ports = []
        for port in sorted(self.COMMON_PORTS.keys()):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "service": self.COMMON_PORTS.get(port, "Unknown"),
                        "banner": self._grab_banner(host, port)[:100] or "",
                    })
                sock.close()
            except:
                continue
        return open_ports

    def _grab_banner(self, host: str, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            if port in (80, 443, 8080, 8443):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            else:
                sock.send(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            return banner.strip()
        except:
            return ""

    def _check_security_headers(self, http_info: Dict) -> Dict:
        headers = {k.lower(): v for k, v in http_info.get("headers", {}).items()}
        checks = {}
        for hdr, desc in {
            "x-frame-options": "点击劫持",
            "x-content-type-options": "MIME 嗅探",
            "strict-transport-security": "降级攻击",
            "content-security-policy": "XSS",
            "x-xss-protection": "XSS",
        }.items():
            checks[hdr] = {
                "present": hdr in headers,
                "value": headers.get(hdr, "缺失")[:80],
                "risk": "正常" if hdr in headers else f"{desc}风险",
            }
        return checks

    def _subdomain_enum(self, domain: str) -> List[str]:
        prefixes = ["www", "mail", "ftp", "admin", "test", "dev", "api",
                     "staging", "blog", "shop", "portal", "vpn", "remote",
                     "git", "ci", "jenkins", "db", "mysql", "redis"]
        found = []
        for prefix in prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                socket.getaddrinfo(subdomain, None, socket.AF_INET)
                found.append(subdomain)
            except socket.gaierror:
                continue
        return found

    def _assess_risk(self, recon_data: Dict) -> Dict:
        risks = []
        score = 0
        high_risk_ports = [21, 23, 445, 3389, 6379, 27017, 9200]
        for p in recon_data.get("ports", []):
            if p["port"] in high_risk_ports:
                risks.append(f"高危端口：{p['port']}/{p['service']}")
                score += 15
        for name, check in recon_data.get("security_headers", {}).items():
            if not check["present"]:
                risks.append(f"安全头缺失：{name}")
                score += 5
        subdomains = recon_data.get("subdomains", [])
        if len(subdomains) > 5:
            risks.append(f"子域暴露较多：{len(subdomains)} 个")
            score += 10
        http_info = recon_data.get("http", {})
        if http_info.get("server"):
            risks.append(f"Server 头泄露：{http_info['server']}")
            score += 5
        score = min(score, 100)
        level = "低" if score < 30 else "中" if score < 60 else "高"
        return {"score": score, "level": level, "risks": risks}

    @staticmethod
    def _extract_domain(url: str) -> str:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url if "://" in url else f"http://{url}")
            return parsed.hostname or ""
        except:
            return ""

    @staticmethod
    def _extract_title(html: str) -> str:
        m = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def format_recon(self, data: Dict) -> str:
        lines = [f"\n{'='*60}", f"  侦察报告：{data['url']}", f"{'='*60}"]
        dns = data.get("dns", {})
        if dns.get("ip"):
            lines.append(f"\n  [DNS] {dns.get('domain','')} -> {dns.get('ip','')}")
            if dns.get("reverse_dns"):
                lines.append(f"    反向：{dns['reverse_dns']}")
        techs = data.get("tech_stack", [])
        if techs:
            lines.append(f"\n  [技术栈] {', '.join(techs)}")
        ports = data.get("ports", [])
        if ports:
            lines.append(f"\n  [开放端口] {len(ports)} 个")
            for p in ports:
                lines.append(f"    {p['port']}/{p['service']} {p.get('banner','')[:40]}")
        for name, check in data.get("security_headers", {}).items():
            status = "OK" if check["present"] else "MISS"
            lines.append(f"  [安全头] {name}: {status}")
        subdomains = data.get("subdomains", [])
        if subdomains:
            lines.append(f"\n  [子域] {len(subdomains)} 个：{', '.join(subdomains)}")
        risk = data.get("risk_assessment", {})
        lines.append(f"\n  [风险评估] {risk.get('level','?')} (评分：{risk.get('score',0)})")
        for r in risk.get("risks", []):
            lines.append(f"    - {r}")
        return "\n".join(lines)

class CallbackServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8888, logger: logging.Logger = None):
        self.host = host
        self.port = port
        self.logger = logger
        self.callbacks: Dict[str, List[Dict]] = {}
        self.dns_callbacks: Dict[str, List[Dict]] = {}
        self._lock = Lock()
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        if self._running:
            return
        handler = self._create_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._running = True
        if self.logger:
            self.logger.info(f"[CallbackServer] 启动于 {self.host}:{self.port}")

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._running = False
            if self.logger:
                self.logger.info("[CallbackServer] 已停止")

    def _create_handler(self):
        server = self
        logger = self.logger

        class CallbackHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                if logger:
                    logger.debug(f"[Callback] {args[0]}")

            def do_GET(self):
                parsed = urlparse(self.path)
                query = parse_qs(parsed.query)
                callback_data = {
                    "type": "http",
                    "path": parsed.path,
                    "query": query,
                    "headers": dict(self.headers),
                    "client_ip": self.client_address[0],
                    "timestamp": datetime.now().isoformat(),
                }
                token = self._extract_token(parsed.path)
                with server._lock:
                    if token not in server.callbacks:
                        server.callbacks[token] = []
                    server.callbacks[token].append(callback_data)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")

            def do_POST(self):
                parsed = urlparse(self.path)
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
                callback_data = {
                    "type": "http_post",
                    "path": parsed.path,
                    "body": body,
                    "headers": dict(self.headers),
                    "client_ip": self.client_address[0],
                    "timestamp": datetime.now().isoformat(),
                }
                token = self._extract_token(parsed.path)
                with server._lock:
                    if token not in server.callbacks:
                        server.callbacks[token] = []
                    server.callbacks[token].append(callback_data)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")

            def _extract_token(self, path: str) -> str:
                parts = path.strip("/").split("/")
                for part in parts:
                    if re.match(r"^[a-f0-9]{8,}$", part):
                        return part
                return "default"

        return CallbackHandler

    def check_callback(self, token: str, timeout: float = 5.0) -> Optional[Dict]:
        start = time.time()
        while time.time() - start < timeout:
            with self._lock:
                if token in self.callbacks and self.callbacks[token]:
                    return self.callbacks[token][-1]
            time.sleep(0.2)
        return None

    def get_all_callbacks(self, token: str) -> List[Dict]:
        with self._lock:
            return self.callbacks.get(token, []).copy()

    def generate_callback_url(self, token: str, path: str = "") -> str:
        return f"http://{self.host}:{self.port}/{token}/{path.lstrip('/')}"


@dataclass
class TemplateRequest:
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    matchers: List[Dict] = field(default_factory=list)
    extractors: List[Dict] = field(default_factory=list)
    payload: str = ""
    vuln_type: str = ""
    severity: str = "中危"
    description: str = ""
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, yaml_content: str) -> List["TemplateRequest"]:
        import re
        templates = []
        blocks = re.split(r"^---+\s*$", yaml_content, flags=re.MULTILINE)
        for block in blocks:
            block = block.strip()
            if not block or block.startswith("#"):
                continue
            template = cls._parse_block(block)
            if template:
                templates.append(template)
        return templates

    @classmethod
    def from_markdown(cls, md_content: str) -> List["TemplateRequest"]:
        import re
        templates = []
        pattern = r'```(?:template|yaml)?\s*\n(.*?)```'
        matches = re.findall(pattern, md_content, re.DOTALL)
        for match in matches:
            template = cls._parse_block(match.strip())
            if template:
                templates.append(template)
        if not matches:
            blocks = re.split(r'^#{1,3}\s+', md_content, flags=re.MULTILINE)
            for block in blocks:
                block = block.strip()
                if not block:
                    continue
                template = cls._parse_block(block)
                if template:
                    templates.append(template)
        return templates

    @classmethod
    def _parse_block(cls, block: str) -> Optional["TemplateRequest"]:
        req = cls()
        lines = block.split("\n")
        in_matchers = False
        in_extractors = False

        for line in lines:
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("id:"):
                req.vuln_type = line.split(":", 1)[1].strip()
            elif line.startswith("name:"):
                req.description = line.split(":", 1)[1].strip()
            elif line.startswith("severity:"):
                req.severity = line.split(":", 1)[1].strip()
            elif line.startswith("method:"):
                req.method = line.split(":", 1)[1].strip().upper()
            elif line.startswith("path:"):
                req.path = line.split(":", 1)[1].strip()
            elif line.startswith("payload:"):
                req.payload = line.split(":", 1)[1].strip().strip('"\'')
            elif line.startswith("matchers:"):
                in_matchers = True
                in_extractors = False
            elif line.startswith("extractors:"):
                in_matchers = False
                in_extractors = True
            elif in_matchers and line.startswith("  -"):
                matcher = cls._parse_matcher(line)
                if matcher:
                    req.matchers.append(matcher)
            elif in_extractors and line.startswith("  -"):
                extractor = cls._parse_extractor(line)
                if extractor:
                    req.extractors.append(extractor)

        return req

    @staticmethod
    def _parse_matcher(line: str) -> Optional[Dict]:
        line = line.strip(" -")
        if ":" not in line:
            return None
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"\'')

        if key == "type":
            return {"type": value}
        elif key in ("status", "status_code"):
            return {"type": "status", "value": int(value)}
        elif key == "body":
            return {"type": "body", "pattern": value}
        elif key == "header":
            return {"type": "header", "key": value}
        elif key == "word":
            return {"type": "word", "pattern": value}
        elif key == "regex":
            return {"type": "regex", "pattern": value}
        return None

    @staticmethod
    def _parse_extractor(line: str) -> Optional[Dict]:
        line = line.strip(" -")
        if ":" not in line:
            return None
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"\'')

        if key == "type":
            return {"type": value}
        elif key == "regex":
            return {"type": "regex", "pattern": value, "group": 1}
        elif key == "json":
            return {"type": "json", "path": value}
        return None


class TemplateEngine:
    def __init__(self, logger: logging.Logger = None):
        self.logger = logger
        self.templates: List[TemplateRequest] = []
        self.template_dir = "templates"
        self._cache: Dict[str, List[TemplateRequest]] = {}

    def load_template(self, template_path: str) -> List[TemplateRequest]:
        if template_path in self._cache:
            return self._cache[template_path]

        if not os.path.exists(template_path):
            if self.logger:
                self.logger.warning(f"模板文件不存在：{template_path}")
            return []

        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()

        if template_path.endswith((".yaml", ".yml")):
            templates = TemplateRequest.from_yaml(content)
        elif template_path.endswith(".md"):
            templates = TemplateRequest.from_markdown(content)
        elif template_path.endswith(".json"):
            templates = self._parse_json_template(content)
        else:
            if self.logger:
                self.logger.warning(f"不支持的模板格式：{template_path}")
            return []

        self._cache[template_path] = templates
        if self.logger:
            self.logger.info(f"[TemplateEngine] 加载 {len(templates)} 个模板：{template_path}")
        return templates

    def _parse_json_template(self, content: str) -> List[TemplateRequest]:
        try:
            data = json.loads(content)
            templates = []
            if isinstance(data, list):
                for item in data:
                    t = self._convert_json_to_template(item)
                    if t:
                        templates.append(t)
            elif isinstance(data, dict):
                t = self._convert_json_to_template(data)
                if t:
                    templates.append(t)
            return templates
        except Exception as e:
            if self.logger:
                self.logger.error(f"解析 JSON 模板失败：{e}")
            return []

    def _convert_json_to_template(self, data: Dict) -> Optional[TemplateRequest]:
        req = TemplateRequest()
        info = data.get("info", {})
        req.vuln_type = data.get("id", info.get("name", ""))
        req.description = info.get("description", "")
        req.severity = info.get("severity", "中危")
        req.tags = info.get("tags", [])

        http_req = data.get("http", [{}])[0] if data.get("http") else {}
        req.method = http_req.get("method", "GET")
        req.path = http_req.get("path", "/")
        req.headers = http_req.get("headers", {})
        req.body = http_req.get("body", "")

        for matcher in http_req.get("matchers", []):
            req.matchers.append(matcher)

        for extractor in http_req.get("extractors", []):
            req.extractors.append(extractor)

        return req

    def load_directory(self, dir_path: str) -> int:
        if not os.path.isdir(dir_path):
            if self.logger:
                self.logger.warning(f"模板目录不存在：{dir_path}")
            return 0

        count = 0
        for root, _, files in os.walk(dir_path):
            for fname in files:
                if fname.endswith((".yaml", ".yml", ".json", ".md")):
                    full_path = os.path.join(root, fname)
                    templates = self.load_template(full_path)
                    count += len(templates)
                    self.templates.extend(templates)
        if self.logger:
            self.logger.info(f"[TemplateEngine] 从目录加载 {count} 个模板：{dir_path}")
        return count

    def execute(self, template: TemplateRequest, base_url: str,
                session: requests.Session, timeout: int = 10) -> Optional[Dict]:
        try:
            url = base_url.rstrip("/") + "/" + template.path.lstrip("/")
            if template.payload:
                if "?" in url:
                    url += f"&{template.payload}"
                else:
                    url += f"?{template.payload}"

            headers = template.headers.copy()
            headers.setdefault("User-Agent", "Mozilla/5.0 (Template-Scanner)")

            if template.method == "GET":
                resp = session.get(url, headers=headers, timeout=timeout, verify=False)
            elif template.method == "POST":
                resp = session.post(url, data=template.body, headers=headers, timeout=timeout, verify=False)
            else:
                resp = session.request(template.method, url, headers=headers, timeout=timeout, verify=False)

            if self._match(template, resp):
                return {
                    "type": template.vuln_type,
                    "severity": template.severity,
                    "url": url,
                    "template": template.description,
                    "matchers_matched": len(template.matchers),
                }
        except Exception as e:
            if self.logger:
                self.logger.debug(f"模板执行失败 {template.vuln_type}: {e}")
        return None

    def _match(self, template: TemplateRequest, resp: requests.Response) -> bool:
        if not template.matchers:
            return resp.status_code == 200

        for matcher in template.matchers:
            mtype = matcher.get("type", "status")

            if mtype == "status":
                expected = matcher.get("value", 200)
                if isinstance(expected, list):
                    if resp.status_code not in expected:
                        return False
                elif resp.status_code != expected:
                    return False

            elif mtype == "body":
                pattern = matcher.get("pattern", "")
                if pattern and pattern not in resp.text:
                    return False

            elif mtype == "word":
                pattern = matcher.get("pattern", "")
                if pattern and pattern not in resp.text:
                    return False

            elif mtype == "regex":
                pattern = matcher.get("pattern", "")
                if pattern and not re.search(pattern, resp.text, re.IGNORECASE):
                    return False

            elif mtype == "header":
                key = matcher.get("key", "").lower()
                value = matcher.get("value", "")
                header_found = False
                for k, v in resp.headers.items():
                    if key in k.lower():
                        if not value or value in v:
                            header_found = True
                            break
                if not header_found:
                    return False

        return True

    def batch_execute(self, base_url: str, session: requests.Session,
                      max_workers: int = 5, timeout: int = 10) -> List[Dict]:
        results = []
        if max_workers > 1:
            with ThreadPoolExecutor(max_workers) as executor:
                futures = {
                    executor.submit(self.execute, t, base_url, session, timeout): t
                    for t in self.templates
                }
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                    except Exception as e:
                        template = futures[future]
                        if self.logger:
                            self.logger.error(f"模板执行失败 {template.vuln_type}: {e}")
        else:
            for template in self.templates:
                result = self.execute(template, base_url, session, timeout)
                if result:
                    results.append(result)
        return results


class NucleiStyleTemplateEngine:
    def __init__(self, config: ScanConfig, logger: logging.Logger = None):
        self.config = config
        self.logger = logger
        self.template_dir = config.template_dir
        self.templates: Dict[str, Dict] = {}
        self._templates_lock = Lock()
        os.makedirs(self.template_dir, exist_ok=True)

    def load_templates(self, directory: str = None) -> int:
        import yaml
        directory = directory or self.template_dir
        count = 0
        for root, _, files in os.walk(directory):
            for fname in files:
                if fname.endswith((".yaml", ".yml")):
                    path = os.path.join(root, fname)
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            content = f.read()
                        
                        # 处理多文档 YAML 文件
                        templates = list(yaml.safe_load_all(content))
                        for template in templates:
                            if template and "id" in template:
                                template_id = template.get("id", fname)
                                with self._templates_lock:
                                    self.templates[template_id] = {
                                        "path": path,
                                        "data": template,
                                        "loaded_at": datetime.now().isoformat(),
                                    }
                                count += 1
                                if self.logger:
                                    self.logger.debug(f"[NucleiEngine] 加载模板：{template_id}")
                    except Exception as e:
                        if self.logger:
                            self.logger.warning(f"[NucleiEngine] 加载失败 {path}: {e}")
        if self.logger:
            self.logger.info(f"[NucleiEngine] 共加载 {count} 个模板")
        return count

    def execute_template(self, template_id: str, target_url: str,
                         session: requests.Session) -> Optional[Dict]:
        with self._templates_lock:
            entry = self.templates.get(template_id)
        if not entry:
            return None

        template = entry["data"]
        info = template.get("info", {})
        requests_list = template.get("requests", [])

        for req in requests_list:
            method = req.get("method", "GET").upper()
            paths = req.get("path", ["/"])
            if isinstance(paths, str):
                paths = [paths]

            headers = req.get("headers", {})
            body = req.get("body", "")
            matchers = req.get("matchers", [])
            extractors = req.get("extractors", [])

            for path_template in paths:
                path = self._replace_variables(path_template, target_url)
                url = target_url.rstrip("/") + "/" + path.lstrip("/")

                try:
                    if method == "GET":
                        resp = session.get(url, headers=headers, timeout=self.config.nuclei_timeout,
                                          verify=False, allow_redirects=True)
                    elif method == "POST":
                        resp = session.post(url, data=body, headers=headers,
                                           timeout=self.config.nuclei_timeout, verify=False,
                                           allow_redirects=True)
                    else:
                        resp = session.request(method, url, headers=headers,
                                              timeout=self.config.nuclei_timeout, verify=False)

                    if self._match_response(matchers, resp):
                        extracted = self._extract_data(extractors, resp)
                        return {
                            "template-id": template_id,
                            "name": info.get("name", template_id),
                            "severity": info.get("severity", "info"),
                            "url": url,
                            "matched": True,
                            "extracted": extracted,
                            "timestamp": datetime.now().isoformat(),
                        }
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[NucleiEngine] 执行失败 {template_id}: {e}")

        return None

    def _replace_variables(self, template: str, base_url: str) -> str:
        parsed = urlparse(base_url)
        variables = {
            "BaseURL": base_url,
            "RootURL": f"{parsed.scheme}://{parsed.hostname}",
            "Host": parsed.hostname or "",
            "Path": parsed.path or "/",
            "Scheme": parsed.scheme,
        }
        result = template
        for key, value in variables.items():
            result = result.replace(f"{{{{{key}}}}}", str(value))
            result = result.replace(f"{{{{{key.lower()}}}}}", str(value))
        return result

    def _match_response(self, matchers: List[Dict], resp: requests.Response) -> bool:
        if not matchers:
            return resp.status_code == 200

        for matcher in matchers:
            mtype = matcher.get("type", "status")

            if mtype == "status":
                status_list = matcher.get("status", [])
                if isinstance(status_list, int):
                    status_list = [status_list]
                if resp.status_code not in status_list:
                    return False

            elif mtype == "word":
                words = matcher.get("words", [])
                if isinstance(words, str):
                    words = [words]
                if not any(word in resp.text for word in words):
                    return False

            elif mtype == "regex":
                patterns = matcher.get("regex", [])
                if isinstance(patterns, str):
                    patterns = [patterns]
                if not any(re.search(p, resp.text, re.IGNORECASE) for p in patterns):
                    return False

            elif mtype == "header":
                header_name = matcher.get("name", "").lower()
                header_values = matcher.get("value", [])
                if isinstance(header_values, str):
                    header_values = [header_values]
                header_found = False
                for k, v in resp.headers.items():
                    if header_name in k.lower():
                        if not header_values or any(val in v for val in header_values):
                            header_found = True
                            break
                if not header_found:
                    return False

        return True

    def _extract_data(self, extractors: List[Dict], resp: requests.Response) -> Dict[str, Any]:
        extracted = {}
        for extractor in extractors:
            etype = extractor.get("type", "regex")
            name = extractor.get("name", "extracted")

            if etype == "regex":
                patterns = extractor.get("regex", [])
                if isinstance(patterns, str):
                    patterns = [patterns]
                for pattern in patterns:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        extracted[name] = match.group(1) if match.groups() else match.group(0)
                        break

        return extracted

    def batch_execute(self, target_url: str, session: requests.Session,
                      max_workers: int = None) -> List[Dict]:
        max_workers = max_workers or self.config.nuclei_template_threads
        results = []

        with ThreadPoolExecutor(max_workers) as executor:
            futures = {
                executor.submit(self.execute_template, tid, target_url, session): tid
                for tid in list(self.templates.keys())[:self.config.nuclei_bulk_size]
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"[NucleiEngine] 执行失败：{e}")

        return results

    def list_templates(self) -> List[Dict]:
        with self._templates_lock:
            return [
                {
                    "id": tid,
                    "name": t["data"].get("info", {}).get("name", tid),
                    "severity": t["data"].get("info", {}).get("severity", "info"),
                    "tags": t["data"].get("info", {}).get("tags", []),
                    "path": t["path"],
                }
                for tid, t in self.templates.items()
            ]


class RateLimiter:
    def __init__(self, interval: float = 2.0):
        self.interval = interval
        self._last_time = 0.0
        self._lock = Lock()
        self._request_count = 0

    def acquire(self, timeout: float = 60.0) -> bool:
        deadline = time.time() + timeout
        while True:
            with self._lock:
                now = time.time()
                if now - self._last_time >= self.interval:
                    self._last_time = now
                    self._request_count += 1
                    return True
                wait_time = self.interval - (now - self._last_time)
            if time.time() + wait_time > deadline:
                return False
            time.sleep(min(wait_time, 0.1))

    @property
    def request_count(self) -> int:
        return self._request_count


class AdaptiveRateLimiter:
    def __init__(self, initial_interval: float = 1.0, min_interval: float = 0.1,
                 max_interval: float = 10.0, logger: logging.Logger = None):
        self.current_interval = initial_interval
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.logger = logger
        self._lock = Lock()
        self._last_time = 0.0
        self._consecutive_timeouts = 0
        self._consecutive_successes = 0

    def acquire(self) -> bool:
        with self._lock:
            now = time.time()
            wait_time = max(0, self.current_interval - (now - self._last_time))
        if wait_time > 0:
            time.sleep(wait_time)
        with self._lock:
            self._last_time = time.time()
        return True

    def record_success(self):
        with self._lock:
            self._consecutive_successes += 1
            self._consecutive_timeouts = 0
            if self._consecutive_successes >= 5:
                self.current_interval = max(self.min_interval, self.current_interval * 0.8)
                self._consecutive_successes = 0
                if self.logger:
                    self.logger.debug(f"[AdaptiveRate] 加速：{self.current_interval:.2f}s")

    def record_timeout(self):
        with self._lock:
            self._consecutive_timeouts += 1
            self._consecutive_successes = 0
            if self._consecutive_timeouts >= 3:
                self.current_interval = min(self.max_interval, self.current_interval * 1.5)
                self._consecutive_timeouts = 0
                if self.logger:
                    self.logger.debug(f"[AdaptiveRate] 减速：{self.current_interval:.2f}s")

    @property
    def current_rate(self) -> float:
        return 1.0 / self.current_interval if self.current_interval > 0 else 0


class AdvancedCrawler:
    def __init__(self, session: requests.Session, config: ScanConfig,
                 logger: logging.Logger, max_depth: int = 3, max_pages: int = 100):
        self.session = session
        self.config = config
        self.logger = logger
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.to_visit: queue.Queue = queue.Queue()
        self.found_urls: List[str] = []
        self.forms: List[Dict] = []
        self.js_endpoints: Set[str] = set()
        self._lock = Lock()
        self._stop_event = Event()
        
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

    def crawl(self, start_url: str) -> Dict[str, Any]:
        self.logger.info(f"[Crawler] 开始爬取：{start_url}")
        parsed = urlparse(start_url)
        self.allowed_domains = {parsed.hostname or ""}
        
        self.to_visit.put((start_url, 0))
        self.visited.add(start_url)
        
        threads = []
        worker_count = min(3, self.config.max_workers)
        for i in range(worker_count):
            t = threading.Thread(target=self._worker, daemon=True, name=f"Crawler-{i}")
            t.start()
            threads.append(t)
        
        while True:
            remaining = self.to_visit.qsize()
            if remaining == 0 and not any(t.is_alive() for t in threads):
                break
            try:
                self.to_visit.join()
                break
            except KeyboardInterrupt:
                break
        
        self._stop_event.set()
        
        for t in threads:
            t.join(timeout=0.5)
        
        result = {
            "urls": self.found_urls,
            "forms": self.forms,
            "js_endpoints": list(self.js_endpoints),
            "total_pages": len(self.visited),
        }
        self.logger.info(f"[Crawler] 完成：{len(self.found_urls)} 个 URL, {len(self.forms)} 个表单，访问 {len(self.visited)} 个页面")
        return result

    def _worker(self):
        while True:
            if self._stop_event.is_set():
                break
                
            try:
                url, depth = self.to_visit.get(timeout=3.0)
            except queue.Empty:
                if self._stop_event.is_set():
                    break
                continue
            
            try:
                if self.logger:
                    self.logger.info(f"[Crawler] 访问 [{depth}/{self.max_depth}]: {url[:80]}")
                
                if depth > self.max_depth or len(self.visited) >= self.max_pages:
                    if self.logger:
                        self.logger.debug(f"[Crawler] 跳过 {url}: 超出限制")
                    continue
                
                resp = self.session.get(url, timeout=self.config.request_timeout, verify=False)
                if not resp:
                    if self.logger:
                        self.logger.warning(f"[Crawler] 无响应：{url}")
                    continue
                
                status = resp.status_code
                html_length = len(resp.text)
                
                if self.logger:
                    self.logger.info(f"[Crawler] 状态码：{status}, 页面大小：{html_length} bytes")
                
                if status == 200 and html_length > 0:
                    with self._lock:
                        self.found_urls.append(url)
                    
                    self._extract_links(resp.text, url, depth)
                    self._extract_forms(resp.text, url)
                    self._extract_js_endpoints(resp.text)
                else:
                    if self.logger:
                        self.logger.warning(f"[Crawler] 无效响应：{url} (状态:{status}, 大小:{html_length})")
                
            except requests.Timeout as e:
                if self.logger:
                    self.logger.warning(f"[Crawler] 请求超时 {url}: {e}")
            except requests.ConnectionError as e:
                if self.logger:
                    self.logger.warning(f"[Crawler] 连接失败 {url}: {e}")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"[Crawler] 错误 {url}: {e}")
            finally:
                self.to_visit.task_done()

    def _extract_links(self, html: str, base_url: str, depth: int):
        from urllib.parse import urljoin
        patterns = [
            r'href=["\'](.*?)["\']',
            r'src=["\'](.*?)["\']',
        ]
        
        added_count = 0
        total_found = 0
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            total_found += len(matches)
            
            for match in matches:
                if not match or match.startswith('#') or match.startswith('javascript:') or match.startswith('data:'):
                    continue
                    
                try:
                    full_url = urljoin(base_url, match)
                    parsed = urlparse(full_url)
                    
                    if parsed.scheme not in ("http", "https"):
                        continue
                    if not parsed.hostname:
                        continue
                    if parsed.hostname not in self.allowed_domains:
                        continue
                    if full_url in self.visited:
                        continue
                    
                    with self._lock:
                        self.visited.add(full_url)
                        self.to_visit.put((full_url, depth + 1))
                        added_count += 1
                        
                except Exception as e:
                    pass
        
        if self.logger:
            if total_found > 0:
                self.logger.debug(f"[Crawler] 页面 {base_url[:60]} 找到 {total_found} 个链接，添加 {added_count} 个新链接")
            if added_count > 0:
                self.logger.info(f"[Crawler] 发现 {added_count} 个新 URL")

    def _extract_forms(self, html: str, base_url: str):
        from urllib.parse import urljoin
        for form_match in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)
            action_match = re.search(r'action=["\'](.*?)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\'](.*?)["\']', form_html, re.IGNORECASE)
            action = urljoin(base_url, action_match.group(1) if action_match else "")
            method = method_match.group(1).upper() if method_match else "GET"
            
            inputs = []
            for inp in re.finditer(r"<input[^>]*>", form_html, re.IGNORECASE):
                inp_tag = inp.group(0)
                name_match = re.search(r'name=["\'](.*?)["\']', inp_tag, re.IGNORECASE)
                type_match = re.search(r'type=["\'](.*?)["\']', inp_tag, re.IGNORECASE)
                if name_match:
                    inputs.append({
                        "name": name_match.group(1),
                        "type": type_match.group(1) if type_match else "text",
                    })
            
            with self._lock:
                self.forms.append({"action": action, "method": method, "inputs": inputs})

    def _extract_js_endpoints(self, html: str):
        patterns = [
            r'fetch\(["\'](.*?)["\']',
            r'axios\.(get|post|put|delete)\(["\'](.*?)["\']',
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.findall(pattern, html, re.IGNORECASE):
                endpoint = match if isinstance(match, str) else match[-1]
                if endpoint.startswith(("http", "/")):
                    with self._lock:
                        self.js_endpoints.add(endpoint)

def setup_logger(name: str, level: str = "INFO", log_file: str = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if logger.handlers:
        return logger
    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger

class ResponseAnalyzer:
    SENSITIVE_PATTERNS = {
        "error_stack": [
            r"Traceback \(most recent call last\)",
            r"Fatal error: .+ on line \d+",
            r"SyntaxError:",
            r"Exception in thread",
            r"\.java:\d+\)",
            r"at org\.apache\.",
            r"at com\.",
            r"at javax\.",
            r"ORA-\d+",
            r"mysql_fetch_assoc",
            r"pg_query",
        ],
        "internal_ip": [
            r"192\.168\.\d+\.\d+",
            r"10\.\d+\.\d+\.\d+",
            r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
            r"127\.0\.0\.1",
        ],
        "debug_info": [
            r"DEBUG\s*=\s*True",
            r"APP_DEBUG.*true",
            r"development.*mode",
            r"X-Debug-Token",
            r"X-Debug-Token-Link",
        ],
        "credentials_leak": [
            r"password.*=.*['\"].+['\"]",
            r"api[_-]?key.*=.*['\"].+['\"]",
            r"secret.*=.*['\"].+['\"]",
            r"access[_-]?token.*=.*['\"].+['\"]",
        ],
    }

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.analysis_cache: Dict[str, Dict] = {}

    def analyze(self, url: str, response: requests.Response) -> Dict[str, Any]:
        cache_key = hashlib.md5((url + str(response.status_code)).encode()).hexdigest()
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        result = {
            "url": url,
            "status_code": response.status_code,
            "content_length": len(response.text),
            "content_type": response.headers.get("Content-Type", ""),
            "server": response.headers.get("Server", ""),
            "x_powered_by": response.headers.get("X-Powered-By", ""),
            "set_cookie": response.headers.get("Set-Cookie", ""),
            "urls_found": self._extract_urls(response.text, url),
            "forms": self._extract_forms(response.text, url),
            "api_endpoints": self._extract_api_endpoints(response.text),
            "sensitive_info": self._detect_sensitive_info(response.text),
            "tech_fingerprint": self._fingerprint_from_response(response),
            "headers": dict(response.headers),
        }

        self.analysis_cache[cache_key] = result
        return result

    def _extract_urls(self, html: str, base_url: str) -> List[str]:
        from urllib.parse import urljoin, urlparse
        urls = set()
        patterns = [
            r'href=["\'](.*?)["\']',
            r'src=["\'](.*?)["\']',
            r'action=["\'](.*?)["\']',
            r'location\.href\s*=\s*["\'](.*?)["\']',
            r'window\.open\(["\'](.*?)["\']',
            r'url\(["\']?(.*?)["\']?\)',
        ]
        for pattern in patterns:
            for match in re.findall(pattern, html, re.IGNORECASE):
                if match and not match.startswith("#"):
                    try:
                        full_url = urljoin(base_url, match)
                        parsed = urlparse(full_url)
                        if parsed.scheme in ("http", "https"):
                            urls.add(full_url)
                    except:
                        pass
        return sorted(urls)

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        from urllib.parse import urljoin
        forms = []
        for form_match in re.finditer(
            r"<form[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL
        ):
            form_html = form_match.group(0)
            action_match = re.search(r'action=["\'](.*?)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\'](.*?)["\']', form_html, re.IGNORECASE)
            action = urljoin(base_url, action_match.group(1) if action_match else "")
            method = method_match.group(1).upper() if method_match else "GET"
            inputs = []
            for inp in re.finditer(
                r"<input[^>]*>", form_html, re.IGNORECASE
            ):
                inp_tag = inp.group(0)
                name_match = re.search(r'name=["\'](.*?)["\']', inp_tag, re.IGNORECASE)
                type_match = re.search(r'type=["\'](.*?)["\']', inp_tag, re.IGNORECASE)
                if name_match:
                    inputs.append({
                        "name": name_match.group(1),
                        "type": type_match.group(1) if type_match else "text",
                    })
            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    def _extract_api_endpoints(self, html: str) -> List[str]:
        endpoints = set()
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
            r'fetch\(["\'](.*?)["\']',
            r'axios\.(get|post|put|delete)\(["\'](.*?)["\']',
            r'\.ajax\(\{.*?url:\s*["\'](.*?)["\']',
        ]
        for pattern in patterns:
            for match in re.findall(pattern, html, re.IGNORECASE):
                endpoint = match if isinstance(match, str) else match[-1]
                if endpoint.startswith(("http", "/")):
                    endpoints.add(endpoint)
        return sorted(endpoints)

    def _detect_sensitive_info(self, text: str) -> Dict[str, List[str]]:
        findings = {}
        for category, patterns in self.SENSITIVE_PATTERNS.items():
            matches = []
            for pattern in patterns:
                for m in re.findall(pattern, text, re.IGNORECASE | re.MULTILINE):
                    match_str = m if isinstance(m, str) else m.group(0)
                    if match_str not in matches:
                        matches.append(match_str[:200])
            if matches:
                findings[category] = matches[:5]
        return findings

    def _fingerprint_from_response(self, response: requests.Response) -> Dict[str, str]:
        fp = {}
        server = response.headers.get("Server", "").lower()
        if "apache" in server:
            fp["web_server"] = "Apache"
        elif "nginx" in server:
            fp["web_server"] = "Nginx"
        elif "iis" in server:
            fp["web_server"] = "IIS"
        xpb = response.headers.get("X-Powered-By", "").lower()
        if "php" in xpb:
            fp["backend"] = "PHP"
        elif "asp.net" in xpb:
            fp["backend"] = "ASP.NET"
        elif "express" in xpb:
            fp["backend"] = "Node.js/Express"
        return fp

class AttackProber:
    SENSITIVE_PATHS = [
        "/", "/admin", "/admin.php", "/login", "/login.php",
        "/wp-admin", "/phpmyadmin", "/config", "/config.json",
        "/.env", "/.git/config", "/backup", "/backup.zip",
        "/db.sql", "/.DS_Store", "/web.config", "/robots.txt",
        "/sitemap.xml", "/.well-known/", "/api/", "/api/v1/",
        "/actuator", "/actuator/env", "/debug", "/_cat/indices",
        "/console", "/manager/html", "/solr/admin", "/jenkins",
    ]

    ERROR_PAYLOADS = [
        "'", "\"", ";", "{{7*7}}", "${7*7}", "<%=7*7%>",
        "{{config}}", "' OR '1'='1", "<script>alert(1)</script>",
        "../../../../etc/passwd", "file:///etc/passwd",
    ]

    def __init__(self, config: ScanConfig, session: requests.Session,
                 logger: logging.Logger, analyzer: ResponseAnalyzer):
        self.config = config
        self.session = session
        self.logger = logger
        self.analyzer = analyzer
        self.rate_limiter = RateLimiter(config.payload_interval)

    def probe(self, base_url: str) -> Dict[str, Any]:
        self.logger.info(f"[Prober] 开始探测：{base_url}")
        result = {
            "base_url": base_url,
            "sensitive_paths": [],
            "injection_points": [],
            "error_findings": [],
            "discovered_urls": set(),
            "tech_info": {},
        }

        self.logger.info("[Prober] 阶段 1: 敏感路径探测")
        for path in self.SENSITIVE_PATHS:
            if not self.rate_limiter.acquire():
                break
            url = base_url.rstrip("/") + path
            resp = self.session.get(
                url, timeout=self.config.request_timeout, verify=False
            )
            if resp and resp.status_code in (200, 301, 302, 403):
                analysis = self.analyzer.analyze(url, resp)
                result["sensitive_paths"].append({
                    "path": path,
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "urls": analysis["urls_found"][:10],
                })
                result["discovered_urls"].update(analysis["urls_found"])
                if analysis["sensitive_info"]:
                    result["tech_info"].setdefault("sensitive_in_response", []).append({
                        "url": url, "info": analysis["sensitive_info"]
                    })

        self.logger.info("[Prober] 阶段 2: 参数注入探测")
        test_params = ["id", "q", "search", "query", "name", "user", "email", "file"]
        for param in test_params:
            if not self.rate_limiter.acquire():
                break
            for payload in self.ERROR_PAYLOADS[:3]:
                test_url = f"{base_url}?{param}={requests.utils.quote(payload)}"
                resp = self.session.get(
                    test_url, timeout=self.config.request_timeout, verify=False
                )
                if resp:
                    analysis = self.analyzer.analyze(test_url, resp)
                    if analysis["sensitive_info"] or resp.status_code == 500:
                        result["injection_points"].append({
                            "param": param,
                            "payload": payload,
                            "status": resp.status_code,
                            "sensitive": analysis["sensitive_info"],
                        })

        self.logger.info("[Prober] 阶段 3: 错误触发探测")
        for payload in self.ERROR_PAYLOADS:
            if not self.rate_limiter.acquire():
                break
            url = base_url.rstrip("/") + "/" + requests.utils.quote(payload)
            resp = self.session.get(
                url, timeout=self.config.request_timeout, verify=False
            )
            if resp and resp.status_code in (500, 403):
                analysis = self.analyzer.analyze(url, resp)
                result["error_findings"].append({
                    "payload": payload,
                    "status": resp.status_code,
                    "sensitive": analysis["sensitive_info"],
                })

        result["discovered_urls"] = list(result["discovered_urls"])
        self.logger.info(
            f"[Prober] 完成：路径{len(result['sensitive_paths'])}个，"
            f"注入点{len(result['injection_points'])}个"
        )
        return result

class AdaptivePayloadGenerator:
    PAYLOAD_TEMPLATES = {
        "sql_injection": [
            "' OR '1'='1", "' OR '1'='1' --", "admin' --",
            "1' AND '1'='1", "1' AND SLEEP(5) --",
            "1' UNION SELECT 1,2,3 --",
        ],
        "xss": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "javascript:alert(1)", "<svg onload=alert(1)>",
        ],
        "ssti": [
            "{{7*7}}", "${7*7}", "<%=7*7%>",
            "{{config}}", "{{self}}",
        ],
        "ssrf": [
            "http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
        ],
        "path_traversal": [
            "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
            "....//....//etc/passwd",
        ],
        "command_injection": [
            ";id", "|whoami", "`ping -c 3 127.0.0.1`",
            "$(sleep 5)", "&& cat /etc/passwd",
        ],
    }

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.generation_count = 0

    def generate(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        payloads = []
        tech_fp = attack_surface.get("tech_fingerprint", {})
        
        if isinstance(tech_fp, list):
            tech_dict = {}
            for item in tech_fp:
                if isinstance(item, str):
                    if "php" in item.lower():
                        tech_dict["backend"] = "PHP"
                    elif "apache" in item.lower():
                        tech_dict["web_server"] = "Apache"
                    elif "nginx" in item.lower():
                        tech_dict["web_server"] = "Nginx"
                    elif "iis" in item.lower():
                        tech_dict["web_server"] = "IIS"
                    elif "tomcat" in item.lower() or "spring" in item.lower():
                        tech_dict["backend"] = "Java"
                    elif "express" in item.lower() or "node" in item.lower():
                        tech_dict["backend"] = "Node.js/Express"
            tech = tech_dict
        else:
            tech = tech_fp

        if tech.get("backend") == "PHP":
            payloads += self._build("sql_injection", "param", ["id", "user", "search"])
            payloads += self._build("path_traversal", "path", ["../../../etc/passwd"])

        if tech.get("web_server") == "Nginx" or tech.get("backend", "").startswith("Node"):
            payloads += self._build("ssti", "param", ["name", "q", "template"])
            payloads += self._build("command_injection", "param", ["cmd", "exec"])

        if tech.get("backend", "") in ("ASP.NET", "Java"):
            payloads += self._build("sql_injection", "param", ["id", "query", "search"])
            payloads += self._build("path_traversal", "path", ["..\\..\\web.config"])

        if not tech:
            payloads += self._build("sql_injection", "param", ["id", "user", "search", "page"])
            payloads += self._build("xss", "param", ["q", "search", "keyword", "name"])
            payloads += self._build("path_traversal", "path", ["file", "path", "dir"])

        for form in attack_surface.get("forms", []):
            for inp in form.get("inputs", [])[:3]:
                payloads += self._build("xss", inp["name"],
                                        ["<img src=x onerror=alert(1)>"])

        for endpoint in attack_surface.get("api_endpoints", [])[:5]:
            payloads += self._build("ssrf", "url", [endpoint])

        if not attack_surface.get("forms") and not attack_surface.get("api_endpoints"):
            payloads += self._build("sql_injection", "param", ["id", "page", "type"])
            payloads += self._build("xss", "param", ["q", "search", "keyword"])
            payloads += self._build("ssti", "param", ["name", "template", "view"])

        self.generation_count += len(payloads)
        self.logger.debug(f"生成 {len(payloads)} 个自适应 Payload")
        return payloads

    def _build(self, vuln_type: str, target: str,
               sample_payloads: List[str]) -> List[Dict[str, Any]]:
        templates = self.PAYLOAD_TEMPLATES.get(vuln_type, sample_payloads)
        return [
            {
                "vuln_type": vuln_type,
                "target": target,
                "payload": p,
                "confidence": 0.5 + random.random() * 0.3,
            }
            for p in templates[:4]
        ]

class CheckpointManager:
    def __init__(self, checkpoint_file: str, logger: logging.Logger):
        self.checkpoint_file = checkpoint_file
        self.logger = logger
        self.completed: Set[str] = set()
        self.in_progress: Dict[str, Dict] = {}
        self.results: List[Dict] = []
        self._lock = Lock()
        self._checkpoint_interval = 20
        self._counter = 0
        self._load()

    def _load(self):
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.completed = set(data.get("completed", []))
                self.results = data.get("results", [])
                self.logger.info(
                    f"[Checkpoint] 恢复 {len(self.completed)} 个已完成任务，"
                    f"{len(self.results)} 个已有结果"
                )
            except Exception as e:
                self.logger.warning(f"检查点加载失败：{e}")

    def _save(self):
        with self._lock:
            data = {
                "completed": list(self.completed),
                "results": self.results,
                "last_saved": datetime.now().isoformat(),
            }
            try:
                with open(self.checkpoint_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                self.logger.warning(f"检查点保存失败：{e}")

    def mark_complete(self, task_id: str, result: Optional[Dict] = None):
        with self._lock:
            self.completed.add(task_id)
            if result:
                self.results.append(result)
            self._counter += 1
            if self._counter >= self._checkpoint_interval:
                self._save()
                self._counter = 0

    def is_complete(self, task_id: str) -> bool:
        return task_id in self.completed

    def finalize(self):
        self._save()
        self.logger.info(f"[Checkpoint] 最终保存：{len(self.completed)} 个任务")

@dataclass
class MemoryGuard:
    max_memory_percent: float = 90.0
    check_interval: int = 50

    def __post_init__(self):
        self._counter = 0
        self._warning_issued = False
        try:
            import psutil
            self._proc = psutil.Process(os.getpid())
            self._psutil = psutil
        except ImportError:
            self._proc = None
            self._psutil = None

    def check(self) -> bool:
        self._counter += 1
        if self._counter % self.check_interval != 0:
            return True
        if not self._proc:
            return True
        try:
            mem = self._proc.memory_percent()
            if mem > self.max_memory_percent:
                if not self._warning_issued:
                    logging.warning(
                        f"[MemoryGuard] 内存占用 {mem:.1f}% 超阈值 {self.max_memory_percent}%"
                    )
                    self._warning_issued = True
                return False
            self._warning_issued = False
            return True
        except Exception:
            return True

    @property
    def current_memory(self) -> float:
        if self._proc:
            try:
                return self._proc.memory_percent()
            except Exception:
                return -1
        return -1

class VulnVerifier:
    BUILTIN_RULES = {
        "sql_injection": {
            "patterns": [
                r"SQL syntax.*MySQL",
                r"Warning: mysql_",
                r"PostgreSQL.*ERROR",
                r"ORA-\d+",
                r"Microsoft.*ODBC.*SQL Server",
                r"SQLite3::query",
            ],
            "severity": "高危",
        },
        "xss": {
            "patterns": [
                r"<script>alert\(1\)</script>",
                r"<img src=x onerror=",
                r"javascript:alert",
            ],
            "severity": "中危",
        },
        "ssti": {
            "patterns": [
                r"49",
                r"SyntaxError.*template",
                r"jinja2\.exceptions",
            ],
            "severity": "高危",
        },
        "ssrf": {
            "patterns": [
                r"169\.254\.169\.254",
                r"localhost",
                r"127\.0\.0\.1",
                r"root:.*:0:0:",
            ],
            "severity": "中危",
        },
        "path_traversal": {
            "patterns": [
                r"root:.*:0:0:",
                r"\[boot loader\]",
                r"# /etc/fstab",
            ],
            "severity": "高危",
        },
        "command_injection": {
            "patterns": [
                r"uid=\d+\(.*\)",
                r"root:.*:0:0:",
                r"Volume Serial Number",
            ],
            "severity": "高危",
        },
    }

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.custom_rules: Dict[str, Dict] = {}

    def verify(self, vuln_type: str, response: requests.Response) -> Dict[str, Any]:
        rules = self.custom_rules.get(vuln_type) or self.BUILTIN_RULES.get(vuln_type)
        if not rules:
            return {"verified": False, "reason": "无对应验证规则"}

        text = response.text[:5000]
        for pattern in rules["patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                return {
                    "verified": True,
                    "severity": rules["severity"],
                    "evidence": pattern[:100],
                    "type": vuln_type,
                }

        return {"verified": False, "reason": "未匹配到特征"}

    def add_custom_rule(self, vuln_type: str, patterns: List[str], severity: str):
        self.custom_rules[vuln_type] = {
            "patterns": patterns,
            "severity": severity,
        }
        self.logger.info(f"[VulnVerifier] 添加自定义规则：{vuln_type}")

class POCPrefilter:
    PLATFORM_RULES = {
        "WordPress": ["wp_", "wordpress"],
        "Drupal": ["drupal"],
        "Joomla": ["joomla"],
        "ThinkPHP": ["thinkphp", "tp5", "tp6"],
        "Laravel": ["laravel"],
        "Spring": ["spring", "springboot"],
        "Struts": ["struts2", "struts"],
        "Apache": ["apache"],
        "Nginx": ["nginx"],
        "IIS": ["iis", "asp.net"],
    }

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def filter(self, pocs: List[Dict], fingerprint: Dict[str, str],
               min_confidence: float = 0.6) -> List[Dict]:
        if not fingerprint:
            return [p for p in pocs if p.get("confidence", 1.0) >= min_confidence]

        filtered = []
        for poc in pocs:
            confidence = poc.get("confidence", 1.0)
            if confidence < min_confidence:
                continue
            platform = fingerprint.get("web_server", "") + " " + fingerprint.get("backend", "")
            for plat, keywords in self.PLATFORM_RULES.items():
                if plat.lower() in platform.lower():
                    for kw in keywords:
                        if kw in poc.get("name", "").lower():
                            confidence += 0.2
            poc["_adjusted_confidence"] = min(confidence, 1.0)
            if confidence >= min_confidence:
                filtered.append(poc)

        self.logger.info(f"[Prefilter] {len(pocs)} -> {len(filtered)} 个 POC 通过过滤")
        return filtered

class POCParser:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        pocs = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            if file_path.endswith(".json"):
                data = json.loads(content)
                pocs = data if isinstance(data, list) else [data]
            elif file_path.endswith((".yaml", ".yml")):
                try:
                    import yaml
                    data = yaml.safe_load(content)
                    pocs = data if isinstance(data, list) else [data]
                except ImportError:
                    self.logger.warning("未安装 PyYAML，跳过 YAML POC")
            elif file_path.endswith(".py"):
                pocs = self._parse_python_poc(content, file_path)
            else:
                self.logger.warning(f"不支持的 POC 格式：{file_path}")
        except Exception as e:
            self.logger.error(f"解析 POC 失败 {file_path}: {e}")
        return pocs

    def _parse_python_poc(self, content: str, file_path: str) -> List[Dict]:
        pocs = []
        name = os.path.basename(file_path)
        desc_match = re.search(r'"""(.*?)"""', content, re.DOTALL)
        desc = desc_match.group(1).strip()[:200] if desc_match else name
        url_match = re.search(r'requests\.(get|post)\(["\'](.*?)["\']', content)
        url = url_match.group(2) if url_match else ""
        vuln_match = re.search(r'(CVE-\d+-\d+|CNVD-\d+|漏洞)', content, re.IGNORECASE)
        vuln_id = vuln_match.group(1) if vuln_match else "unknown"
        pocs.append({
            "name": name,
            "description": desc,
            "template": url or "/",
            "vuln_id": vuln_id,
            "confidence": 0.7,
            "source_file": file_path,
        })
        return pocs

    def load_poc_folder(self, folder_path: str) -> List[Dict[str, Any]]:
        all_pocs = []
        if not os.path.isdir(folder_path):
            self.logger.warning(f"POC 文件夹不存在：{folder_path}")
            return all_pocs
        for root, _, files in os.walk(folder_path):
            for fname in files:
                if fname.endswith((".json", ".yaml", ".yml", ".py")):
                    full = os.path.join(root, fname)
                    all_pocs += self.parse_file(full)
        self.logger.info(f"[POCParser] 加载 {len(all_pocs)} 个 POC")
        return all_pocs

class DefenseAdvisor:
    FIX_MAP = {
        "sql_injection": {
            "fix": "使用参数化查询/预编译语句，禁止字符串拼接 SQL。",
            "reference": "OWASP SQL Injection Prevention",
        },
        "xss": {
            "fix": "对所有用户输入进行 HTML 实体编码，使用 CSP 头，启用 X-XSS-Protection。",
            "reference": "OWASP XSS Prevention",
        },
        "ssti": {
            "fix": "禁止用户输入直接传入模板引擎，使用沙箱隔离，升级模板引擎版本。",
            "reference": "PortSwigger SSTI",
        },
        "ssrf": {
            "fix": "禁止访问内网地址，使用白名单 URL 校验，禁用 file:// 协议。",
            "reference": "OWASP SSRF Prevention",
        },
        "path_traversal": {
            "fix": "禁止目录穿越字符，使用 basename() 过滤，配置 Web 根目录限制。",
            "reference": "OWASP Path Traversal",
        },
        "command_injection": {
            "fix": "禁止用户输入直接传入系统命令，使用白名单参数校验，避免 shell=True。",
            "reference": "OWASP Command Injection",
        },
        "file_inclusion": {
            "fix": "禁止动态包含用户输入文件，使用白名单机制，关闭 allow_url_include。",
            "reference": "OWASP LFI/RFI",
        },
        "info_leak": {
            "fix": "关闭调试模式，移除错误栈显示，统一错误页面，禁用 Server 头泄露。",
            "reference": "OWASP Information Disclosure",
        },
    }

    WAF_RULES = {
        "modsecurity": {
            "sql_injection": [
                'SecRule ARGS "@detectSQLi" "id:1001,deny,status:403,msg:\'SQLi\'"',
                'SecRule ARGS "@detectXSS" "id:1002,deny,status:403,msg:\'XSS\'"',
            ],
            "xss": [
                'SecRule ARGS "@detectXSS" "id:1003,deny,status:403,msg:\'XSS\'"',
            ],
            "path_traversal": [
                'SecRule ARGS "@contains .." "id:1004,deny,status:403,msg:\'Path Traversal\'"',
            ],
        },
        "nginx": {
            "sql_injection": [
                'if ($args ~* "union.*select|insert.*into|drop.*table") { return 403; }',
            ],
            "xss": [
                'if ($args ~* "<script|javascript:|onerror=") { return 403; }',
            ],
        },
    }

    def __init__(self, logger: logging.Logger, kb: KnowledgeBase):
        self.logger = logger
        self.kb = kb

    def advise(self, vuln_type: str, details: Dict) -> Dict[str, Any]:
        fix_info = self.FIX_MAP.get(vuln_type, {
            "fix": "请人工分析该漏洞类型，参考 OWASP Top 10。",
            "reference": "OWASP Top 10",
        })
        modsec_rules = self.WAF_RULES.get("modsecurity", {}).get(vuln_type, [])
        nginx_rules = self.WAF_RULES.get("nginx", {}).get(vuln_type, [])
        result = {
            "vuln_type": vuln_type,
            "fix": fix_info["fix"],
            "reference": fix_info["reference"],
            "modsecurity_rules": modsec_rules,
            "nginx_rules": nginx_rules,
            "details": details,
        }
        self.kb.add_defense_rule({
            "vuln_type": vuln_type,
            "waf_rule": modsec_rules[0] if modsec_rules else "",
            "fix": fix_info["fix"][:100],
        })
        return result

    def advise_from_scan(self, scan_result: Dict[str, Any]) -> List[Dict]:
        advices = []
        for vuln in scan_result.get("vulnerabilities", []):
            adv = self.advise(vuln.get("type", "info_leak"), vuln)
            advices.append(adv)
        return advices

class ThreatLearner:
    COMMON_ATTACK_PATTERNS = {
        "sql_injection": [
            r"union.*select", r"'.*or.*1=1", r"sleep\s*\(",
        ],
        "xss": [
            r"<script>", r"javascript:", r"onerror\s*=",
        ],
        "path_traversal": [
            r"\.\./", r"\.\.\\", r"/etc/passwd",
        ],
        "command_injection": [
            r";\s*cat\s+", r"\|.*whoami", r"`.*`",
        ],
    }

    def __init__(self, logger: logging.Logger, kb: KnowledgeBase):
        self.logger = logger
        self.kb = kb

    def learn_from_log(self, log_path: str) -> List[Dict]:
        if not os.path.exists(log_path):
            self.logger.warning(f"日志文件不存在：{log_path}")
            return []
        generated = []
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    for vuln_type, patterns in self.COMMON_ATTACK_PATTERNS.items():
                        for pattern in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                poc = self._generate_poc(vuln_type, line)
                                if poc:
                                    generated.append(poc)
                                    self.kb.add_attack_pattern({
                                        "type": vuln_type,
                                        "description": f"从日志学习：{line[:80]}",
                                        "poc": poc,
                                    })
        except Exception as e:
            self.logger.error(f"日志学习失败：{e}")
        self.logger.info(f"[ThreatLearner] 从日志生成 {len(generated)} 个 POC")
        return generated

    def _generate_poc(self, vuln_type: str, log_line: str) -> Optional[Dict]:
        url_match = re.search(r"(GET|POST)\s+(\S+)\s+HTTP", log_line)
        if not url_match:
            return None
        path = url_match.group(2)
        return {
            "name": f"learned_{vuln_type}_{hashlib.md5(log_line.encode()).hexdigest()[:8]}",
            "template": path,
            "vuln_type": vuln_type,
            "source": "threat_learner",
            "confidence": 0.6,
            "log_line": log_line[:200],
        }

    def learn_from_hfish(self, log_path: str) -> List[Dict]:
        self.logger.info(f"[ThreatLearner] 学习 HFish 日志：{log_path}")
        return self.learn_from_log(log_path)

class ReportGenerator:
    def __init__(self, config: ScanConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        os.makedirs(config.report_dir, exist_ok=True)

    def generate(self, scan_results: List[Dict], output_prefix: str = "scan_report"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(
            self.config.report_dir, f"{output_prefix}_{timestamp}.json"
        )
        html_path = os.path.join(
            self.config.report_dir, f"{output_prefix}_{timestamp}.html"
        )

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "scan_time": timestamp,
                    "target_count": len(scan_results),
                    "results": scan_results,
                },
                f, indent=2, ensure_ascii=False
            )

        html_content = self._build_html(scan_results, timestamp)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        self.logger.info(f"[Report] 报告已生成：{json_path}, {html_path}")
        return [json_path, html_path]

    def _build_html(self, results: List[Dict], timestamp: str) -> str:
        vuln_count = sum(len(r.get("vulnerabilities", [])) for r in results)
        rows = ""
        for r in results:
            url = r.get("url", "")
            vulns = r.get("vulnerabilities", [])
            for v in vulns:
                rows += (
                    f"<tr>"
                    f"<td>{url}</td>"
                    f"<td>{v.get('type','?')}</td>"
                    f"<td>{v.get('severity','?')}</td>"
                    f"<td>{v.get('evidence','')[:100]}</td>"
                    f"</tr>"
                )
        if not rows:
            rows = "<tr><td colspan='4'>未发现漏洞</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>扫描报告 {timestamp}</title>
<style>
  body {{ font-family: sans-serif; margin: 20px; }}
  h1 {{ color: #333; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
  th {{ background: #f0f0f0; }}
  .high {{ color: #d32f2f; font-weight: bold; }}
  .medium {{ color: #f57c00; }}
  .low {{ color: #388e3c; }}
</style>
</head>
<body>
<h1>扫描报告</h1>
<p>生成时间：{timestamp}</p>
<p>目标数：{len(results)} | 漏洞数：{vuln_count}</p>
<table>
<tr><th>URL</th><th>漏洞类型</th><th>严重度</th><th>证据</th></tr>
{rows}
</table>
</body>
</html>"""

class RequestEngine:
    def __init__(self, config: ScanConfig, session: requests.Session,
                 logger: logging.Logger):
        self.config = config
        self.session = session
        self.logger = logger

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        kwargs.setdefault("timeout", self.config.request_timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)
        for attempt in range(self.config.max_retries + 1):
            try:
                resp = self.session.request(method, url, **kwargs)
                return resp
            except requests.Timeout:
                if attempt < self.config.max_retries:
                    self.logger.debug(f"超时 {url}，重试 {attempt+2}/{self.config.max_retries+1}")
                    time.sleep(self.config.retry_delay)
            except requests.ConnectionError as e:
                if attempt < self.config.max_retries:
                    self.logger.debug(f"连接失败 {url}: {e}，重试")
                    time.sleep(self.config.retry_delay)
            except Exception as e:
                self.logger.debug(f"请求异常 {url}: {e}")
                break
        return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

class ScanOrchestrator:
    def __init__(self, config: ScanConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (POC-Scanner-v3.0)",
        })

        self.kb = KnowledgeBase(config.kb_dir, logger)
        self.request_engine = RequestEngine(config, self.session, logger)
        self.analyzer = ResponseAnalyzer(logger)
        self.prober = AttackProber(config, self.session, logger, self.analyzer)
        self.payload_gen = AdaptivePayloadGenerator(logger)
        self.verifier = VulnVerifier(logger)
        self.prefilter = POCPrefilter(logger)
        self.parser = POCParser(logger)
        self.defender = DefenseAdvisor(logger, self.kb)
        self.recon_module = ReconModule(config, self.session, logger, self.kb)
        self.learner = ThreatLearner(logger, self.kb)
        self.reporter = ReportGenerator(config, logger)
        self.checkpoint = CheckpointManager(config.checkpoint_file, logger)
        self.memory_guard = MemoryGuard(config.max_memory_percent,
                                        config.memory_check_interval)
        self.rate_limiter = RateLimiter(config.payload_interval)
        
        self.callback_server = CallbackServer(logger=logger)
        self.template_engine = TemplateEngine(logger)
        self.crawler = AdvancedCrawler(self.session, config, logger)
        self.adaptive_limiter = AdaptiveRateLimiter(logger=logger)
        
        self.nuclei_engine = NucleiStyleTemplateEngine(config, logger)

        self.scan_results: List[Dict] = []
        self.last_recon_data: Optional[Dict] = None
        self.last_scan_results: List[Dict] = []

    def scan(self, target_url: str, deep: bool = True) -> Dict[str, Any]:
        self.logger.info(f"[Orchestrator] 开始扫描：{target_url}")
        result = {
            "url": target_url,
            "start_time": datetime.now().isoformat(),
            "vulnerabilities": [],
            "recon": {},
            "defense_advices": [],
            "probed_urls": [],
            "crawled_urls": [],
            "template_results": [],
        }

        self.callback_server.start()

        self.logger.info("[阶段 1] 被动侦察")
        recon_data = self.recon_module.recon(target_url)
        result["recon"] = recon_data
        self.last_recon_data = recon_data

        self.logger.info("[阶段 2] 高级爬虫")
        crawl_result = self.crawler.crawl(target_url)
        result["crawled_urls"] = crawl_result["urls"][:50]
        
        self.logger.info("[阶段 3] 攻击即探测")
        probe_result = self.prober.probe(target_url)
        result["probed_urls"] = probe_result.get("discovered_urls", [])

        self.logger.info("[阶段 4] 响应分析 + 自适应 Payload")
        attack_surface = {
            "tech_fingerprint": recon_data.get("tech_stack", []),
            "forms": crawl_result["forms"] + probe_result.get("tech_info", {}).get("forms", []),
            "api_endpoints": crawl_result["js_endpoints"] + probe_result.get("discovered_urls", [])[:10],
            "sensitive_info": probe_result.get("tech_info", {}),
        }

        self.logger.info("[阶段 5] 生成自适应 Payload")
        payloads = self.payload_gen.generate(attack_surface)
        self.logger.info(f"  生成 {len(payloads)} 个 Payload")

        if deep and payloads:
            self.logger.info("[阶段 6] 深入攻击")
            for p in payloads[:20]:
                if not self.memory_guard.check():
                    self.logger.warning("内存超阈值，停止攻击")
                    break
                self.adaptive_limiter.acquire()
                vuln = self._execute_payload(target_url, p)
                if vuln:
                    result["vulnerabilities"].append(vuln)
                    self.adaptive_limiter.record_success()
                else:
                    self.adaptive_limiter.record_timeout()

        if self.config.poc_folder and os.path.isdir(self.config.poc_folder):
            self.logger.info("[阶段 7] POC 验证")
            pocs = self.parser.load_poc_folder(self.config.poc_folder)
            filtered = self.prefilter.filter(
                pocs, {"web_server": recon_data.get("http", {}).get("server", "")},
                self.config.min_confidence
            )
            for poc in filtered[:20]:
                vuln = self._test_poc(target_url, poc)
                if vuln:
                    result["vulnerabilities"].append(vuln)

        if os.path.isdir("templates"):
            self.logger.info("[阶段 8] 模板引擎扫描")
            self.template_engine.load_directory("templates")
            template_results = self.template_engine.batch_execute(
                target_url, self.session, max_workers=5
            )
            result["template_results"] = template_results
            for tr in template_results:
                result["vulnerabilities"].append(tr)

        self.logger.info("[阶段 9] Nuclei 引擎扫描")
        nuclei_count = self.nuclei_engine.load_templates()
        if nuclei_count > 0:
            nuclei_results = self.nuclei_engine.batch_execute(
                target_url, self.session
            )
            result["nuclei_results"] = nuclei_results
            for nr in nuclei_results:
                result["vulnerabilities"].append(nr)
            self.logger.info(f"[NucleiEngine] 发现 {len(nuclei_results)} 个漏洞")

        self.logger.info("[阶段 10] 反连平台检测")
        callback_token = hashlib.md5(target_url.encode()).hexdigest()[:8]
        callback_data = self.callback_server.get_all_callbacks(callback_token)
        if callback_data:
            result["vulnerabilities"].append({
                "type": "oob_callback",
                "severity": "高危",
                "url": target_url,
                "evidence": f"收到 {len(callback_data)} 个反连请求",
                "callback_count": len(callback_data),
            })

        self.logger.info("[阶段 10] 生成防御建议")
        advices = self.defender.advise_from_scan(result)
        result["defense_advices"] = advices

        result["end_time"] = datetime.now().isoformat()
        result["vuln_count"] = len(result["vulnerabilities"])
        self.scan_results.append(result)
        self.last_scan_results.append(result)

        self.logger.info(
            f"[Orchestrator] 扫描完成：{target_url}, "
            f"发现 {result['vuln_count']} 个漏洞"
        )
        return result

    def _execute_payload(self, base_url: str, payload_info: Dict) -> Optional[Dict]:
        vuln_type = payload_info.get("vuln_type", "unknown")
        target = payload_info.get("target", "param")
        payload_str = payload_info.get("payload", "")

        test_url = base_url
        if target == "param":
            sep = "&" if "?" in base_url else "?"
            test_url = f"{base_url}{sep}{payload_str}"
        elif target == "path":
            test_url = base_url.rstrip("/") + "/" + requests.utils.quote(payload_str)

        resp = self.request_engine.get(test_url)
        if not resp:
            return None

        verification = self.verifier.verify(vuln_type, resp)
        if verification.get("verified"):
            return {
                "type": vuln_type,
                "severity": verification.get("severity", "中危"),
                "url": test_url,
                "payload": payload_str,
                "evidence": verification.get("evidence", "")[:200],
            }
        return None

    def _test_poc(self, base_url: str, poc: Dict) -> Optional[Dict]:
        template = poc.get("template", "/")
        test_url = base_url.rstrip("/") + "/" + template.lstrip("/")
        resp = self.request_engine.get(test_url)
        if not resp:
            return None
        if resp.status_code != 404:
            return {
                "type": poc.get("vuln_type", "unknown"),
                "severity": "待定",
                "url": test_url,
                "poc_name": poc.get("name", ""),
                "status": resp.status_code,
            }
        return None

    def scan_batch(self, targets: List[str], deep: bool = True) -> List[Dict]:
        results = []
        if self.config.max_workers > 1:
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures = {executor.submit(self.scan, url, deep): url for url in targets}
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        self.logger.error(f"扫描失败 {futures[future]}: {e}")
        else:
            for url in targets:
                results.append(self.scan(url, deep))
        return results

    def load_targets(self, file_path: str) -> List[str]:
        targets = []
        if not os.path.exists(file_path):
            self.logger.warning(f"目标文件不存在：{file_path}")
            return targets
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
        self.logger.info(f"[Targets] 加载 {len(targets)} 个目标")
        return targets

    def diff_scans(self, scan_a: Dict, scan_b: Dict) -> Dict[str, Any]:
        vulns_a = {v["type"] for v in scan_a.get("vulnerabilities", [])}
        vulns_b = {v["type"] for v in scan_b.get("vulnerabilities", [])}
        return {
            "only_in_a": sorted(vulns_a - vulns_b),
            "only_in_b": sorted(vulns_b - vulns_a),
            "common": sorted(vulns_a & vulns_b),
            "vuln_count_a": len(scan_a.get("vulnerabilities", [])),
            "vuln_count_b": len(scan_b.get("vulnerabilities", [])),
        }

class POCAgent:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = setup_logger(
            "poc_scanner_v3", config.log_level, config.log_file
        )
        self.registry = ToolRegistry()
        self.router = IntentRouter()
        self.orchestrator = ScanOrchestrator(config, self.logger)
        self._register_tools()

        self.context: List[Dict[str, str]] = []
        self.max_context = 20
        self.logger.info("POC Scanner v3.0 Agent 初始化完成")

    def _register_tools(self):
        self.registry.register(
            name="scan", description="扫描单个目标 URL",
            func=lambda url, deep=True: self.orchestrator.scan(url, deep),
            danger_level=1, pattern=r"scan\s+\S+"
        )
        self.registry.register(
            name="scan_batch", description="批量扫描目标列表",
            func=lambda targets, deep=True: self.orchestrator.scan_batch(targets, deep),
            danger_level=1, pattern=r"scan_batch|批量"
        )
        self.registry.register(
            name="recon", description="被动侦察目标",
            func=lambda url: self.orchestrator.recon_module.recon(url),
            danger_level=0, pattern=r"recon|侦察|指纹"
        )
        self.registry.register(
            name="defend", description="生成防御建议",
            func=lambda vuln_type, details: self.orchestrator.defender.advise(vuln_type, details),
            danger_level=0, pattern=r"defend|防御|修复"
        )
        self.registry.register(
            name="learn", description="从日志学习攻击模式",
            func=lambda log_path: self.orchestrator.learner.learn_from_log(log_path),
            danger_level=1, pattern=r"learn|学习|日志"
        )
        self.registry.register(
            name="report", description="生成扫描报告",
            func=lambda: self.orchestrator.reporter.generate(
                self.orchestrator.scan_results
            ),
            danger_level=0, pattern=r"report|报告"
        )
        self.registry.register(
            name="kb_stats", description="查看知识库统计",
            func=lambda: self.orchestrator.kb.stats(),
            danger_level=0, pattern=r"kb|知识库"
        )
        self.registry.register(
            name="kb_export", description="导出知识库",
            func=lambda: self.orchestrator.kb.export_all(),
            danger_level=0, pattern=r"kb.*export|导出.*知识库"
        )
        self.registry.register(
            name="diff", description="对比两次扫描结果",
            func=lambda: "请先完成两次扫描后再使用 diff",
            danger_level=0, pattern=r"diff|对比"
        )
        self.registry.register(
            name="watch", description="持续监控目标（周期性扫描）",
            func=self._watch_target,
            danger_level=1, pattern=r"watch|监控"
        )
        self.registry.register(
            name="template", description="加载并执行模板扫描",
            func=lambda: self._cmd_template_exec(""),
            danger_level=1, pattern=r"template|模板"
        )
        self.registry.register(
            name="callback", description="查看反连平台状态",
            func=lambda: self.orchestrator.callback_server.get_all_callbacks("default"),
            danger_level=0, pattern=r"callback|反连"
        )
        self.registry.register(
            name="nuclei", description="执行 Nuclei 模板扫描",
            func=lambda: self._cmd_nuclei(""),
            danger_level=1, pattern=r"nuclei|nuclei 扫描"
        )

    def _watch_target(self, url: str, interval: int = 3600):
        self.logger.info(f"[Watch] 开始监控 {url}，间隔 {interval}s（Ctrl+C 停止）")
        try:
            while True:
                result = self.orchestrator.scan(url, deep=False)
                self.logger.info(f"  发现 {result.get('vuln_count', 0)} 个漏洞")
                time.sleep(interval)
        except KeyboardInterrupt:
            self.logger.info("[Watch] 监控已停止")

    def run_repl(self):
        print(self._banner())
        print("输入 'help' 查看命令，'quit' 退出\n")
        while True:
            try:
                user_input = input("poc> ").strip()
                if not user_input:
                    continue
                intent = self.router.route(user_input)
                self._dispatch(intent, user_input)
                if intent == "quit":
                    break
            except KeyboardInterrupt:
                print("\n退出中...")
                break
            except EOFError:
                break

    def _dispatch(self, intent: str, user_input: str):
        if intent == "scan":
            self._cmd_scan(user_input)
        elif intent == "recon":
            self._cmd_recon(user_input)
        elif intent == "defend":
            self._cmd_defend(user_input)
        elif intent == "learn":
            self._cmd_learn(user_input)
        elif intent == "diff":
            self._cmd_diff(user_input)
        elif intent == "kb":
            self._cmd_kb(user_input)
        elif intent == "watch":
            self._cmd_watch(user_input)
        elif intent == "template":
            self._cmd_template_exec(user_input)
        elif intent == "callback":
            self._cmd_callback(user_input)
        elif intent == "nuclei":
            self._cmd_nuclei(user_input)
        elif intent == "help":
            self._cmd_help(user_input)
        elif intent == "quit":
            print("再见！")
        else:
            print(f"未知命令：{user_input}")
            print("输入 'help' 查看可用命令")

    def _cmd_scan(self, user_input: str):
        words = user_input.split()
        url = None
        for w in words:
            if w.startswith("http://") or w.startswith("https://"):
                url = w
                break
        if not url and self.config.target_url:
            url = self.config.target_url
        if not url:
            url = input("请输入目标 URL: ").strip()
        if not url:
            print("错误：未提供目标 URL")
            return
        if not url.startswith("http"):
            url = "http://" + url
        print(f"开始扫描：{url}")
        result = self.orchestrator.scan(url)
        self._print_scan_result(result)

    def _cmd_recon(self, user_input: str):
        url = self._extract_url(user_input)
        if not url:
            url = input("请输入目标 URL: ").strip()
        if not url:
            return
        if not url.startswith("http"):
            url = "http://" + url
        result = self.orchestrator.recon_module.recon(url)
        print(self.orchestrator.recon_module.format_recon(result))

    def _cmd_defend(self, user_input: str):
        if not self.orchestrator.last_scan_results:
            print("请先执行扫描（scan 命令）")
            return
        last = self.orchestrator.last_scan_results[-1]
        vulns = last.get("vulnerabilities", [])
        if not vulns:
            print("上次扫描未发现漏洞，无需生成防御建议")
            return
        print(f"\n为上次扫描的 {len(vulns)} 个漏洞生成防御建议:\n")
        for v in vulns:
            adv = self.orchestrator.defender.advise(v.get("type", "info_leak"), v)
            print(f"  [{adv['vuln_type']}] {adv['fix']}")
            if adv["modsecurity_rules"]:
                print(f"    ModSec: {adv['modsecurity_rules'][0][:80]}")

    def _cmd_learn(self, user_input: str):
        log_path = self._extract_path(user_input)
        if not log_path:
            log_path = input("请输入日志文件路径：").strip()
        if not log_path or not os.path.exists(log_path):
            print("日志文件不存在")
            return
        pocs = self.orchestrator.learner.learn_from_log(log_path)
        print(f"从日志学习完成，生成 {len(pocs)} 个 POC 模板")

    def _cmd_diff(self, user_input: str):
        results = self.orchestrator.scan_results
        if len(results) < 2:
            print("需要至少两次扫描结果才能对比")
            return
        diff = self.orchestrator.diff_scans(results[-2], results[-1])
        print(f"\n扫描对比 (前一次 vs 最近一次):")
        print(f"  前次漏洞数：{diff['vuln_count_a']}")
        print(f"  本次漏洞数：{diff['vuln_count_b']}")
        if diff["only_in_b"]:
            print(f"  新增：{', '.join(diff['only_in_b'])}")
        if diff["only_in_a"]:
            print(f"  消失：{', '.join(diff['only_in_a'])}")

    def _cmd_kb(self, user_input: str):
        if "export" in user_input.lower():
            path = self.orchestrator.kb.export_all()
            print(f"知识库已导出：{path}")
        elif "clear" in user_input.lower():
            confirm = input("确认清空知识库？(y/n): ")
            if confirm.lower() == "y":
                self.orchestrator.kb.clear()
                print("知识库已清空")
        else:
            print(self.orchestrator.kb.stats())

    def _cmd_watch(self, user_input: str):
        url = self._extract_url(user_input)
        if not url:
            url = input("请输入监控目标 URL: ").strip()
        if not url:
            return
        if not url.startswith("http"):
            url = "http://" + url
        interval = 3600
        try:
            parts = user_input.split()
            for i, p in enumerate(parts):
                if p == "watch" and i + 1 < len(parts):
                    if parts[i+1].isdigit():
                        interval = int(parts[i+1])
        except Exception:
            pass
        self._watch_target(url, interval)

    def _cmd_help(self, user_input: str):
        print(self._help_text())

    def _cmd_template_exec(self, user_input: str):
        template_dir = "templates"
        if not os.path.isdir(template_dir):
            print(f"模板目录不存在：{template_dir}")
            print("请创建 templates 目录并放入 YAML/JSON 模板文件")
            return
        url = self._extract_url(user_input)
        if not url:
            url = self.config.target_url
        if not url:
            print("错误：未提供目标 URL")
            return
        if not url.startswith("http"):
            url = "http://" + url
        print(f"开始模板扫描：{url}")
        count = self.orchestrator.template_engine.load_directory(template_dir)
        print(f"加载 {count} 个模板")
        results = self.orchestrator.template_engine.batch_execute(
            url, self.orchestrator.session, max_workers=5
        )
        print(f"\n发现 {len(results)} 个漏洞:")
        for r in results:
            print(f"  [{r.get('severity','?')}] {r.get('type','?')} - {r.get('template','')}")

    def _cmd_callback(self, user_input: str):
        callbacks = self.orchestrator.callback_server.get_all_callbacks("default")
        if not callbacks:
            print("暂无反连请求")
            return
        print(f"收到 {len(callbacks)} 个反连请求:")
        for cb in callbacks[-10:]:
            print(f"  [{cb.get('timestamp','')}] {cb.get('type','?')} from {cb.get('client_ip','')}")
            print(f"    Path: {cb.get('path','')}")

    def _cmd_nuclei(self, user_input: str):
        url = self._extract_url(user_input)
        if not url:
            url = self.config.target_url
        if not url:
            print("错误：未提供目标 URL")
            return
        if not url.startswith("http"):
            url = "http://" + url
        
        print(f"开始 Nuclei 模板扫描：{url}")
        count = self.orchestrator.nuclei_engine.load_templates()
        print(f"加载 {count} 个 Nuclei 模板")
        
        if count == 0:
            print("未找到任何 Nuclei 模板，请在 templates/ 目录放置 YAML 模板文件")
            return
        
        results = self.orchestrator.nuclei_engine.batch_execute(url, self.orchestrator.session)
        print(f"\n发现 {len(results)} 个漏洞:")
        for r in results:
            print(f"  [{r.get('severity','info').upper()}] {r.get('name','?')}")
            print(f"    URL: {r.get('url','')}")
            if r.get('extracted'):
                print(f"    提取：{r['extracted']}")

    def _print_scan_result(self, result: Dict):
        print(f"\n{'='*60}")
        print(f"  扫描结果：{result['url']}")
        print(f"  耗时：{result.get('end_time','')} -> {result.get('start_time','')}")
        print(f"  漏洞数：{result.get('vuln_count', 0)}")
        if result.get("vulnerabilities"):
            print(f"\n  漏洞列表:")
            for v in result["vulnerabilities"]:
                print(f"    [{v.get('severity','?')}] {v.get('type','?')}")
                print(f"      URL: {v.get('url','')}")
                print(f"      证据：{v.get('evidence','')[:80]}")
        if result.get("defense_advices"):
            print(f"\n  防御建议：{len(result['defense_advices'])} 条")
        print(f"{'='*60}\n")

    @staticmethod
    def _extract_url(text: str) -> Optional[str]:
        for w in text.split():
            if w.startswith("http://") or w.startswith("https://"):
                return w
        return None

    @staticmethod
    def _extract_path(text: str) -> Optional[str]:
        for w in text.split():
            if os.path.exists(w):
                return w
        return None

    @staticmethod
    def _banner() -> str:
        return "\n".join([
            "============================================",
            "   POC Scanner v3.0 增强版",
            "   统一安全扫描平台",
            "   整合：v2.5 攻击即探测 + ARCEP 侦察防御",
            "         + agent_v0.5 工具注册调度",
            "         + Nuclei 模板引擎",
            "         + Xray 反连平台",
            "         + 高级爬虫",
            "         + 智能并发控制",
            "============================================",
        ])

    @staticmethod
    def _help_text() -> str:
        return "\n".join([
            "可用命令:",
            "  scan <url>           扫描目标 (攻击即探测)",
            "  recon <url>          被动侦察目标",
            "  defend               为上次扫描生成防御建议",
            "  learn <log_path>    从日志学习攻击模式",
            "  diff                 对比最近两次扫描",
            "  kb [export|clear]   知识库管理",
            "  watch <url> [sec]   持续监控目标",
            "  template [url]      执行模板扫描 (Nuclei 风格)",
            "  callback            查看反连平台状态",
            "  nuclei [url]        执行 Nuclei YAML 模板扫描",
            "  report              生成扫描报告",
            "  help                显示本帮助",
            "  quit                退出",
            "",
            "命令行模式:",
            "  python poc.py -u <url> [-d] [--batch <file>]",
            "",
            "模板语法:",
            "  支持 YAML/JSON/Markdown格式模板，放置在 templates/ 目录",
            "  参考 Nuclei 模板语法:id, name, severity, method, path, matchers",
            "",
            "Markdown 模板格式:",
            "  使用 ```template 代码块包裹 YAML 内容",
            "  或使用标题 (##) 分隔不同模板",
        ])

def main():
    import argparse

    config_path = "scanner_config.json"
    if not os.path.exists(config_path):
        default_config = ScanConfig()
        default_config.save(config_path)
        print(f"[Config] 已生成默认配置文件：{config_path}")

    parser = argparse.ArgumentParser(
        description="POC Scanner v3.0 — 统一安全扫描平台"
    )
    parser.add_argument("-u", "--url", type=str, default="",
                        help="目标 URL（如 http://example.com）")
    parser.add_argument("-f", "--file", type=str, default="",
                        help="目标 URL 列表文件（每行一个 URL）")
    parser.add_argument("-d", "--deep", action="store_true",
                        help="启用深度攻击（自适应 Payload）")
    parser.add_argument("-c", "--config", type=str, default=config_path,
                        help="配置文件路径")
    parser.add_argument("--poc-folder", type=str, default="",
                        help="POC 文件夹路径")
    parser.add_argument("--log-level", type=str, default="INFO",
                        help="日志级别：DEBUG, INFO, WARNING, ERROR")
    parser.add_argument("--recon-only", action="store_true",
                        help="仅执行被动侦察，不攻击")
    parser.add_argument("--report-only", type=str, default="",
                        help="仅从已有结果生成报告（传入 JSON 结果文件）")
    args = parser.parse_args()

    config = ScanConfig.from_file(args.config)
    if args.log_level:
        config.log_level = args.log_level.upper()
    if args.poc_folder:
        config.poc_folder = args.poc_folder
    if args.deep:
        config.max_attack_depth = 5

    logger = setup_logger("poc_scanner_v3", config.log_level, config.log_file)

    if args.report_only:
        if not os.path.exists(args.report_only):
            logger.error(f"结果文件不存在：{args.report_only}")
            sys.exit(1)
        with open(args.report_only, "r", encoding="utf-8") as f:
            results = json.load(f).get("results", [])
        agent = POCAgent(config)
        paths = agent.orchestrator.reporter.generate(results)
        print(f"报告已生成：{paths}")
        sys.exit(0)

    if not args.url and not args.file:
        agent = POCAgent(config)
        agent.run_repl()
        sys.exit(0)

    if args.url:
        url = args.url
        if not url.startswith("http"):
            url = "http://" + url
        agent = POCAgent(config)
        if args.recon_only:
            result = agent.orchestrator.recon_module.recon(url)
            print(agent.orchestrator.recon_module.format_recon(result))
        else:
            result = agent.orchestrator.scan(url, deep=args.deep)
            agent._print_scan_result(result)
            agent.orchestrator.reporter.generate(agent.orchestrator.scan_results)
        sys.exit(0)

    if args.file:
        if not os.path.exists(args.file):
            logger.error(f"目标文件不存在：{args.file}")
            sys.exit(1)
        agent = POCAgent(config)
        targets = agent.orchestrator.load_targets(args.file)
        if not targets:
            logger.error("未加载到任何目标 URL")
            sys.exit(1)
        results = agent.orchestrator.scan_batch(targets, deep=args.deep)
        agent.orchestrator.reporter.generate(results)
        print(f"\n批量扫描完成，共 {len(results)} 个目标")
        total_vulns = sum(r.get("vuln_count", 0) for r in results)
        print(f"共发现 {total_vulns} 个漏洞")
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断，退出。")
        sys.exit(0)
    except Exception as e:
        print(f"致命错误：{e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
