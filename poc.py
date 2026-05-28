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
        print(f"检测到缺失依赖：{', '.join(missing)}")
        print("正在自动安装...")
        python = sys.executable
        for pkg in missing:
            try:
                subprocess.check_call([python, "-m", "pip", "install", "--user", pkg])
                print(f"已安装：{pkg}")
            except subprocess.CalledProcessError:
                print(f"安装失败：{pkg}，请手动运行 pip install {pkg}")
                sys.exit(1)
        print("依赖安装完成，继续执行")

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
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Event
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class ScanConfig:
    payload_interval: float = 2.0
    max_workers: int = 3
    request_timeout: int = 15
    max_retries: int = 2
    retry_delay: float = 1.5
    baseline_variance: int = 200
    min_confidence: float = 0.6
    max_memory_percent: float = 80.0
    memory_check_interval: int = 10
    response_truncate: int = 2000
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


class ModuleManager:
    def __init__(self, module_dir: str, logger: logging.Logger):
        self.module_dir = module_dir
        self.logger = logger
        self.payloads: List[Dict] = []
        self.verifiers: List[Dict] = []
        self.profiles: List[Dict] = []
        self._load_all()

    def _ensure_dirs(self):
        for sub in ["payloads", "verifiers", "profiles"]:
            os.makedirs(os.path.join(self.module_dir, sub), exist_ok=True)

    def _load_all(self):
        self._ensure_dirs()
        self.payloads = self._load_folder("payloads")
        self.verifiers = self._load_folder("verifiers")
        self.profiles = self._load_folder("profiles")
        total = len(self.payloads) + len(self.verifiers) + len(self.profiles)
        if total > 0:
            self.logger.info(f"已加载 {total} 个自定义模块 "
                           f"(P:{len(self.payloads)} V:{len(self.verifiers)} R:{len(self.profiles)})")

    def _load_folder(self, sub: str) -> List[Dict]:
        folder = os.path.join(self.module_dir, sub)
        items = []
        for f in os.listdir(folder):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(folder, f), "r", encoding="utf-8") as fp:
                        items.append(json.load(fp))
                except Exception as e:
                    self.logger.warning(f"模块加载失败：{f} - {e}")
        return items

    def _save_module(self, category: str, name: str, data: Dict):
        folder = os.path.join(self.module_dir, category)
        os.makedirs(folder, exist_ok=True)
        safe_name = re.sub(r'[^\w\u4e00-\u9fff]', '_', name)
        path = os.path.join(folder, f"{safe_name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _remove_file(self, category: str, name: str) -> bool:
        folder = os.path.join(self.module_dir, category)
        safe_name = re.sub(r'[^\w\u4e00-\u9fff]', '_', name)
        path = os.path.join(folder, f"{safe_name}.json")
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def execute(self, cmd: str) -> str:
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
        else:
            return f"未知命令：{action}\n输入 help 查看帮助"

    def _parse_flags(self, args: List[str]) -> Tuple[Dict, List]:
        flags = {}
        positional = []
        i = 0
        while i < len(args):
            if args[i].startswith("--"):
                key = args[i][2:]
                if i + 1 < len(args) and not args[i + 1].startswith("--"):
                    flags[key] = args[i + 1]
                    i += 2
                else:
                    flags[key] = True
                    i += 1
            else:
                positional.append(args[i])
                i += 1
        return flags, positional

    def _cmd_payload(self, args: List[str]) -> str:
        if not args or args[0].lower() != "add":
            return "用法：payload add <名称> <路径 1,路径 2,...> [--type 类型] [--must 关键词] [--ban 关键词]"

        flags, pos = self._parse_flags(args[1:])
        if len(pos) < 2:
            return "缺少参数\n用法：payload add <名称> <路径 1,路径 2,...>"

        name = pos[0]
        paths = [p.strip() for p in pos[1].split(",") if p.strip()]
        vuln_type = flags.get("type", "custom")
        must = [k.strip() for k in flags.get("must", "").split(",") if k.strip()]
        ban = [k.strip() for k in flags.get("ban", "").split(",") if k.strip()]

        module = {
            "name": name,
            "type": vuln_type,
            "payloads": paths,
            "verify": {
                "status_code": [200],
                "must_contain": must,
                "must_not_contain": ban,
            },
            "created": datetime.now().isoformat(),
        }

        self.payloads.append(module)
        self._save_module("payloads", name, module)

        return (f"已添加 payload [{name}]\n"
                f"   类型：{vuln_type}\n"
                f"   路径：{', '.join(paths)}\n"
                f"   必含：{must or '(无)'}\n"
                f"   禁含：{ban or '(无)'}")

    def _cmd_verify(self, args: List[str]) -> str:
        if not args or args[0].lower() != "add":
            return "用法：verify add <名称> <正则> [--level high/medium] [--confidence 0.8] [--fp 误报词]"

        flags, pos = self._parse_flags(args[1:])
        if len(pos) < 2:
            return "缺少参数\n用法：verify add <名称> <正则>"

        name = pos[0]
        pattern = pos[1]
        level = flags.get("level", "medium")
        try:
            confidence = float(flags.get("confidence", "0.7"))
        except ValueError:
            confidence = 0.7
        fp_words = [k.strip() for k in flags.get("fp", "").split(",") if k.strip()]

        module = {
            "name": name,
            "level": level,
            "pattern": pattern,
            "confidence": confidence,
            "false_positive_filter": fp_words,
            "created": datetime.now().isoformat(),
        }

        self.verifiers.append(module)
        self._save_module("verifiers", name, module)

        return (f"已添加 verify [{name}]\n"
                f"   级别：{level}\n"
                f"   正则：{pattern}\n"
                f"   置信度：{confidence}\n"
                f"   误报过滤：{fp_words or '(无)'}")

    def _cmd_profile(self, args: List[str]) -> str:
        if not args or args[0].lower() != "add":
            return "用法：profile add <名称> [--title 标题词] [--header 头部词] [--skip 跳过标签] [--prior 优先标签]"

        flags, pos = self._parse_flags(args[1:])
        if len(pos) < 1:
            return "缺少参数\n用法：profile add <名称>"

        name = pos[0]
        title_kw = [k.strip() for k in flags.get("title", "").split(",") if k.strip()]
        header_kw = [k.strip() for k in flags.get("header", "").split(",") if k.strip()]
        skip_tags = [k.strip() for k in flags.get("skip", "").split(",") if k.strip()]
        prior_tags = [k.strip() for k in flags.get("prior", "").split(",") if k.strip()]

        module = {
            "name": name,
            "fingerprint": {
                "title_contains": title_kw,
                "header_contains": header_kw,
            },
            "skip_poc_tags": skip_tags,
            "priority_poc_tags": prior_tags,
            "created": datetime.now().isoformat(),
        }

        self.profiles.append(module)
        self._save_module("profiles", name, module)

        return (f"已添加 profile [{name}]\n"
                f"   标题匹配：{title_kw or '(无)'}\n"
                f"   头部匹配：{header_kw or '(无)'}\n"
                f"   跳过标签：{skip_tags or '(无)'}\n"
                f"   优先标签：{prior_tags or '(无)'}")

    def _cmd_list(self, category: List[str]) -> str:
        cat = category[0].lower() if category else "all"

        lines = []
        if cat in ("all", "payloads"):
            lines.append(f"Payloads ({len(self.payloads)}):")
            for m in self.payloads:
                lines.append(f"  * {m['name']} | 类型：{m.get('type', '?')} | "
                           f"路径：{len(m.get('payloads', []))} 条")
        if cat in ("all", "verifiers"):
            lines.append(f"Verifiers ({len(self.verifiers)}):")
            for m in self.verifiers:
                lines.append(f"  * {m['name']} | 级别：{m.get('level', '?')} | "
                           f"置信度：{m.get('confidence', 0)}")
        if cat in ("all", "profiles"):
            lines.append(f"Profiles ({len(self.profiles)}):")
            for m in self.profiles:
                skip = m.get('skip_poc_tags', [])
                lines.append(f"  * {m['name']} | 跳过：{skip or '(无)'}")

        if not lines:
            lines.append("模块库为空，用 payload/verify/profile add 添加")

        return "\n".join(lines)

    def _cmd_remove(self, args: List[str]) -> str:
        if len(args) < 2:
            return "用法：remove <payload|verify|profile> <名称>"

        cat = args[0].lower()
        name = args[1]

        cat_map = {"payload": "payloads", "verify": "verifiers", "profile": "profiles"}
        if cat not in cat_map:
            return f"类别错误：{cat}，可选：payload, verify, profile"

        folder_name = cat_map[cat]
        target_list = getattr(self, folder_name)

        before = len(target_list)
        target_list[:] = [m for m in target_list if m.get("name") != name]
        removed = len(target_list) < before

        file_removed = self._remove_file(folder_name, name)

        if removed or file_removed:
            return f"已删除 {cat} [{name}]"
        else:
            return f"未找到 {cat} [{name}]"

    def _help(self) -> str:
        return """
POC Scanner v2.3 模块命令

  payload add <名称> <路径,...>
    --type 类型   (默认 custom)
    --must 关键词  (响应必须包含)
    --ban 关键词   (响应不能包含)

  verify add <名称> <正则>
    --level high/medium
    --confidence 0.0~1.0
    --fp 误报词  (出现则不算漏洞)

  profile add <名称>
    --title 标题关键词
    --header 响应头关键词
    --skip 跳过的 POC 标签
    --prior 优先的 POC 标签

  targets <文件>   加载批量目标 URL 列表
  report           查看历史 HTML 报告
  list [payloads|verifiers|profiles]
  remove <payload|verify|profile> <名称>
  scan             扫描 (单目标或批量自动判断)
  exit

示例:
  payload add spring_actuator /actuator,/actuator/env --type info_leak --must spring --ban login,403
  verify add java泄露 javax\\.sql\\.DataSource --level high --confidence 0.8 --fp example.com
  profile add 宝塔面板 --title 宝塔 --header BT-Panel --skip iis,asp --prior php,nginx
""".strip()


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


class FingerprintEngine:
    def __init__(self, config: ScanConfig, session: requests.Session, logger: logging.Logger):
        self.config = config
        self.session = session
        self.logger = logger
        self.baseline: Dict[str, Any] = {}

    def identify(self, url: str) -> Dict[str, Any]:
        self.logger.info(f"指纹识别：{url}")
        try:
            resp = self.session.get(url, timeout=self.config.request_timeout, allow_redirects=True)
            self.baseline = {
                "url": url, "status_code": resp.status_code,
                "content_length": len(resp.text),
                "content_hash": hashlib.md5(resp.text.encode()).hexdigest()[:16],
                "server": resp.headers.get("Server", ""),
                "x_powered_by": resp.headers.get("X-Powered-By", ""),
                "content_type": resp.headers.get("Content-Type", ""),
                "title": self._extract_title(resp.text),
                "generator": self._extract_generator(resp.text),
                "cookies": dict(resp.cookies),
            }
            self.logger.info(
                f"指纹：{self.baseline['server']} | "
                f"标题：{self.baseline['title'][:30]} | "
                f"长度：{self.baseline['content_length']}"
            )
            return self.baseline
        except Exception as e:
            self.logger.error(f"指纹识别失败：{e}")
            return {"error": str(e)}

    def get_headers(self) -> Dict[str, str]:
        uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
        ]
        headers = {
            "User-Agent": random.choice(uas),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }
        if self.baseline.get("cookies"):
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.baseline["cookies"].items())
        return headers

    @staticmethod
    def _extract_title(html: str) -> str:
        m = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    @staticmethod
    def _extract_generator(html: str) -> str:
        m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\'](.*?)["\']', html, re.IGNORECASE)
        return m.group(1) if m else ""


class PayloadGenerator:
    BUILTIN = {
        "sql_injection": ["' OR '1'='1", "1' AND '1'='1", "admin'--", "' UNION SELECT NULL--"],
        "file_inclusion": ["/etc/passwd", "../../../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
        "rce": ["whoami", "id", "uname -a", "cat /etc/passwd"],
        "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"],
        "upload": ["<?php echo md5('test');?>"],
        "ssti": ["{{7*7}}", "${7*7}", "#{7*7}"],
    }

    TYPE_KEYWORDS = {
        "sql_injection": ["sql", "inject", "sqli"],
        "file_inclusion": ["file", "read", "lfi", "rfi"],
        "rce": ["rce", "command", "exec"],
        "xss": ["xss", "script"],
        "upload": ["upload"],
        "ssti": ["ssti", "template"],
    }

    def __init__(self, logger: logging.Logger, modules: ModuleManager):
        self.logger = logger
        self.modules = modules

    def classify_poc(self, poc_name: str, content: str) -> List[str]:
        text = (poc_name + " " + content).lower()
        matched = []
        for vtype, kws in self.TYPE_KEYWORDS.items():
            if any(kw in text for kw in kws):
                matched.append(vtype)
        for m in self.modules.payloads:
            if m.get("type", "").lower() in text or m.get("name", "").lower() in text:
                matched.append(m["name"])
        return matched or ["sql_injection"]

    def generate(self, poc_name: str, content: str, fingerprint: Dict = None) -> List[Tuple[str, Optional[Dict]]]:
        vuln_types = self.classify_poc(poc_name, content)
        payloads = []

        for vtype in vuln_types:
            custom_found = False
            for m in self.modules.payloads:
                if m.get("name") == vtype or m.get("type") == vtype:
                    for p in m.get("payloads", []):
                        payloads.append((p, m.get("verify")))
                    custom_found = True

            if vtype in self.BUILTIN:
                for p in self.BUILTIN[vtype]:
                    payloads.append((p, None))

        seen = set()
        unique = []
        for p, v in payloads:
            if p not in seen:
                seen.add(p)
                unique.append((p, v))

        self.logger.debug(f"POC [{poc_name}] {len(unique)} 条 payload")
        return unique


class VulnVerifier:
    BUILTIN_CRITICAL = [
        (r"root:[:x:]", "linux_passwd_leak", 0.9),
        (r"uid=\d+\([^)]+\)\s+gid=\d+", "command_execution", 0.95),
        (r"mysql_fetch_array|sql syntax.*?mysql|ORA-\d{5}", "sql_error_leak", 0.8),
        (r"/bin/(?:bash|sh|dash)", "shell_path_leak", 0.85),
        (r"ConnectionStrings|AppSettings", "config_leak", 0.85),
    ]
    BUILTIN_MEDIUM = [
        (r"warning.*?mysql|warning.*?sql", "sql_warning", 0.5),
        (r"<script>alert\(", "xss_reflected", 0.7),
    ]

    def __init__(self, config: ScanConfig, baseline: Dict, logger: logging.Logger,
                 modules: ModuleManager):
        self.config = config
        self.baseline = baseline
        self.logger = logger
        self.modules = modules

    def verify(self, resp: requests.Response, payload: str,
               poc_name: str, custom_rule: Dict = None) -> Tuple[bool, float, str]:
        if custom_rule:
            result = self._verify_custom(resp, custom_rule)
            if result[0]:
                return result

        if resp.status_code != 200:
            if resp.status_code == 500:
                if any(kw in poc_name.lower() for kw in ["sql", "inject"]):
                    if any(kw in resp.text.lower() for kw in ["sql", "mysql", "syntax"]):
                        return True, 0.6, "SQL 触发 500"
            return False, 0.0, f"状态码 {resp.status_code}"

        if self._matches_baseline(resp):
            return False, 0.0, "与基线一致"

        for pat, vtype, conf in self.BUILTIN_CRITICAL:
            if re.search(pat, resp.text, re.IGNORECASE):
                return True, conf, f"高危：{vtype}"

        hits = []
        for pat, vtype, conf in self.BUILTIN_MEDIUM:
            if re.search(pat, resp.text, re.IGNORECASE):
                hits.append((vtype, conf))

        for m in self.modules.verifiers:
            try:
                if re.search(m["pattern"], resp.text, re.IGNORECASE):
                    level = m.get("level", "medium")
                    conf = m.get("confidence", 0.6)
                    fp_words = m.get("false_positive_filter", [])
                    if any(fp in resp.text for fp in fp_words):
                        continue
                    if level == "high":
                        return True, conf, f"自定义验证：{m['name']}"
                    hits.append((f"custom:{m['name']}", conf))
            except Exception:
                pass

        if payload and payload in resp.text:
            hits.append(("payload_echo", 0.7))

        if hits:
            best = max(hits, key=lambda x: x[1])
            total = min(best[1] + 0.1 * (len(hits) - 1), 1.0)
            if total >= self.config.min_confidence:
                return True, total, f"多信号：{', '.join(h[0] for h in hits)}"

        return False, 0.0, "无特征"

    def _verify_custom(self, resp, rule: Dict) -> Tuple[bool, float, str]:
        allowed_codes = rule.get("status_code", [200])
        if resp.status_code not in allowed_codes:
            return False, 0.0, f"状态码 {resp.status_code} 不在 {allowed_codes}"

        must = rule.get("must_contain", [])
        if must and not all(kw.lower() in resp.text.lower() for kw in must):
            return False, 0.0, f"缺少必含关键词"

        ban = rule.get("must_not_contain", [])
        if ban and any(kw.lower() in resp.text.lower() for kw in ban):
            return False, 0.0, f"包含禁含关键词"

        return True, 0.85, "自定义规则验证通过"

    def _matches_baseline(self, resp) -> bool:
        bl = self.baseline
        resp_len = len(resp.text)
        v = self.config.baseline_variance
        if abs(resp_len - bl.get("content_length", 0)) < v:
            h = hashlib.md5(resp.text.encode()).hexdigest()[:16]
            if h == bl.get("content_hash"):
                return True
        title = bl.get("title", "").lower()
        if title and title in resp.text.lower() and abs(resp_len - bl.get("content_length", 0)) < v * 2:
            return True
        return False


class POCPrefilter:
    PLATFORM_RULES = {
        "windows": ["iis", "asp", "aspx", ".net", "powershell"],
        "linux": ["apache", "nginx", "php", "mysql"],
        "java": ["tomcat", "weblogic", "jboss", "struts", "spring", "shiro", "fastjson"],
        "node": ["express", "nodejs"],
        "python": ["django", "flask"],
    }
    FP_MAP = {
        "server": {"iis": "windows", "apache": "linux", "nginx": "linux", "tomcat": "java", "express": "node"},
        "x_powered_by": {"asp.net": "windows", "php": "linux", "express": "node"},
    }

    def __init__(self, logger: logging.Logger, modules: ModuleManager):
        self.logger = logger
        self.modules = modules
        self.target_tags: set = set()

    def build_profile(self, fingerprint: Dict) -> set:
        self.target_tags = set()
        for fp_key, mapping in self.FP_MAP.items():
            value = fingerprint.get(fp_key, "").lower()
            for kw, tag in mapping.items():
                if kw in value:
                    self.target_tags.add(tag)
        for m in self.modules.profiles:
            fp = m.get("fingerprint", {})
            title_kw = fp.get("title_contains", [])
            header_kw = fp.get("header_contains", [])
            title = fingerprint.get("title", "").lower()
            server = fingerprint.get("server", "").lower()
            if any(kw.lower() in title for kw in title_kw) or any(kw.lower() in server for kw in header_kw):
                self.target_tags.add(m["name"])
        self.logger.info(f"目标技术栈：{self.target_tags or '未知'}")
        return self.target_tags

    def should_scan(self, poc_name: str, poc_content: str) -> Tuple[bool, str]:
        if not self.target_tags:
            return True, ""
        text = (poc_name + " " + poc_content).lower()
        poc_platforms = set()
        for platform, keywords in self.PLATFORM_RULES.items():
            if any(kw in text for kw in keywords):
                poc_platforms.add(platform)
        if not poc_platforms:
            return True, ""
        mismatch = poc_platforms - self.target_tags
        if mismatch and poc_platforms - mismatch == set():
            return False, f"平台不匹配：POC={poc_platforms}, 目标={self.target_tags}"
        return True, ""


class MemoryGuard:
    def __init__(self, config: ScanConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
    def check(self) -> bool:
        try:
            import psutil
            mem = psutil.virtual_memory()
            if mem.percent > self.config.max_memory_percent:
                self.logger.warning(f"内存 {mem.percent:.0f}% 超阈值，暂停等待...")
                for _ in range(60):
                    time.sleep(1)
                    if psutil.virtual_memory().percent < self.config.max_memory_percent - 10:
                        self.logger.info("内存恢复，继续")
                        return True
                self.logger.error("等待超时，强制继续")
            return True
        except ImportError:
            return True


class CheckpointManager:
    def __init__(self, config: ScanConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self._completed: set = set()
    def load(self) -> set:
        if not self.config.enable_checkpoint or not os.path.exists(self.config.checkpoint_file):
            return set()
        try:
            with open(self.config.checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._completed = set(data.get("completed", []))
            if self._completed:
                self.logger.info(f"断点恢复，跳过 {len(self._completed)} 个")
            return self._completed
        except Exception:
            return set()
    def save_one(self, poc_name: str):
        if not self.config.enable_checkpoint:
            return
        self._completed.add(poc_name)
        try:
            with open(self.config.checkpoint_file, "w", encoding="utf-8") as f:
                json.dump({"completed": list(self._completed)}, f, ensure_ascii=False)
        except Exception:
            pass
    def clear(self):
        if os.path.exists(self.config.checkpoint_file):
            os.remove(self.config.checkpoint_file)
    def is_completed(self, name: str) -> bool:
        return name in self._completed


class RequestEngine:
    def __init__(self, config, rate_limiter, session, logger):
        self.config = config
        self.rate_limiter = rate_limiter
        self.session = session
        self.logger = logger
        self._stats = {"total": 0, "success": 0, "failed": 0}
    def send(self, method, url, headers=None, body="", timeout=None) -> Optional[requests.Response]:
        timeout = timeout or self.config.request_timeout
        if not self.rate_limiter.acquire(timeout=60):
            return None
        self._stats["total"] += 1
        for attempt in range(self.config.max_retries + 1):
            try:
                kwargs = {"timeout": timeout, "allow_redirects": True, "verify": False}
                if headers:
                    kwargs["headers"] = headers
                m = method.upper()
                if m == "GET":
                    resp = self.session.get(url, **kwargs)
                elif m == "POST":
                    resp = self.session.post(url, data=body, **kwargs)
                elif m == "PUT":
                    resp = self.session.put(url, data=body, **kwargs)
                elif m == "DELETE":
                    resp = self.session.delete(url, **kwargs)
                else:
                    return None
                self._stats["success"] += 1
                if len(resp.text) > self.config.response_truncate:
                    resp._content = resp.text[:self.config.response_truncate].encode()
                return resp
            except requests.exceptions.Timeout:
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_delay)
            except requests.exceptions.ConnectionError:
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_delay * 2)
            except Exception:
                break
        self._stats["failed"] += 1
        return None
    @property
    def stats(self):
        return dict(self._stats)


class POCParser:
    PATTERNS = [r"```plain\s*(.*?)\s*```", r"```http\s*(.*?)\s*```",
                r"```bash\s*(.*?)\s*```", r"```\s*(GET|POST|PUT|DELETE)\s+(.*?)\s*```"]
    def __init__(self, logger):
        self.logger = logger
    def parse_file(self, path):
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return []
        results = []
        for pat in self.PATTERNS:
            for m in re.findall(pat, content, re.DOTALL | re.IGNORECASE):
                p = self._parse(m if isinstance(m, str) else m[0])
                if p:
                    results.append(p)
        if not results:
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if line.upper().startswith(("GET ", "POST ", "PUT ", "DELETE ")):
                    p = self._parse("\n".join(lines[i:i+20]))
                    if p:
                        results.append(p)
        return results
    @staticmethod
    def _parse(raw):
        lines = raw.strip().split("\n")
        if not lines:
            return None
        first = lines[0].split(" ", 1)
        if len(first) < 2 or first[0].upper() not in ("GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH"):
            return None
        headers, body, in_body = {}, "", False
        for line in lines[1:]:
            if in_body:
                body += line + "\n"
            elif line.strip() == "":
                in_body = True
            elif ": " in line and not line.startswith((" ","\t")):
                k, v = line.split(": ", 1)
                headers[k.strip()] = v.strip()
        return {"method": first[0].upper(), "path": first[1].split(" ")[0], "headers": headers, "body": body.strip()}


class ReportGenerator:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        os.makedirs(config.report_dir, exist_ok=True)

    def generate(self, target, results, fingerprint, stats, batch_results=None):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = re.sub(r'[^\w]', '_', target.split("//")[-1][:30])

        json_path = os.path.join(self.config.report_dir, f"scan_{domain}_{ts}.json")
        report = {
            "scan_info": {"target": target, "timestamp": datetime.now().isoformat(), "version": "2.3"},
            "fingerprint": fingerprint,
            "summary": {
                "total": stats.get("total", 0), "skipped": stats.get("skipped", 0),
                "vulnerable": len([r for r in results if r.get("vuln")]),
                "requests": stats.get("requests", 0), "elapsed": stats.get("elapsed", 0),
            },
            "vulnerabilities": [r for r in results if r.get("vuln")],
            "batch_results": batch_results,
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        html_path = os.path.join(self.config.report_dir, f"scan_{domain}_{ts}.html")
        html = self._build_html(target, results, fingerprint, stats, batch_results)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        self.logger.info(f"报告：{html_path}")
        return html_path

    def _build_html(self, target, results, fingerprint, stats, batch_results=None):
        vulns = [r for r in results if r.get("vuln")]
        safe = [r for r in results if not r.get("vuln") and not r.get("skipped")]
        skipped = [r for r in results if r.get("skipped")]
        elapsed = stats.get("elapsed", 0)

        batch_section = ""
        if batch_results:
            batch_vuln_total = sum(len([r for r in br.get("results", []) if r.get("vuln")]) for br in batch_results)
            batch_rows = ""
            for br in batch_results:
                bv = len([r for r in br.get("results", []) if r.get("vuln")])
                tag = "vuln" if bv > 0 else "safe"
                batch_rows += f'<tr class="{tag}"><td>{br["target"]}</td><td>{bv}</td><td>{br.get("elapsed", 0):.0f}s</td></tr>'
            batch_section = f"""
            <div class="section">
                <h2>批量扫描汇总 ({len(batch_results)} 个目标)</h2>
                <p>共发现 <span class="vuln-count">{batch_vuln_total}</span> 个漏洞</p>
                <table><tr><th>目标</th><th>漏洞数</th><th>耗时</th></tr>{batch_rows}</table>
            </div>"""

        vuln_rows = ""
        for v in vulns:
            vuln_rows += f"""
                <tr class="vuln">
                    <td>{v.get('poc_name', '')}</td>
                    <td>{v.get('method', '')}</td>
                    <td class="url">{v.get('url', '')}</td>
                    <td>{v.get('status_code', '')}</td>
                    <td>{v.get('confidence', 0)}</td>
                    <td>{v.get('reason', '')}</td>
                    <td class="payload">{v.get('payload', '')[:60]}</td>
                </tr>"""

        vuln_section = ""
        if vulns:
            vuln_section = f"""
            <div class="section">
                <h2>漏洞详情 ({len(vulns)})</h2>
                <table>
                    <tr><th>POC</th><th>方法</th><th>URL</th><th>状态码</th><th>置信度</th><th>原因</th><th>Payload</th></tr>
                    {vuln_rows}
                </table>
            </div>"""
        else:
            vuln_section = """<div class="section"><h2>未发现漏洞</h2></div>"""

        fp_items = ""
        for k, v in fingerprint.items():
            if v and k != "content_hash":
                fp_items += f"<tr><td>{k}</td><td>{v}</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>POC Scanner 报告 - {target}</title>
<style>
body {{ font-family: -apple-system, "Microsoft YaHei", sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
.header {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }}
.header h1 {{ margin: 0 0 8px; color: #58a6ff; font-size: 22px; }}
.header .meta {{ color: #8b949e; font-size: 13px; }}
.section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
.section h2 {{ margin: 0 0 12px; color: #e6edf3; font-size: 17px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ background: #21262d; color: #8b949e; text-align: left; padding: 8px 10px; border-bottom: 1px solid #30363d; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; word-break: break-all; }}
tr.vuln {{ background: rgba(248,81,73,0.1); }}
tr.safe {{ background: rgba(63,185,80,0.05); }}
.vuln-count {{ color: #f85149; font-weight: bold; font-size: 18px; }}
.safe-count {{ color: #3fb950; }}
.url {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; }}
.payload {{ font-family: monospace; color: #d2a8ff; font-size: 12px; }}
.stats {{ display: flex; gap: 24px; margin: 12px 0; }}
.stat {{ text-align: center; }}
.stat .num {{ font-size: 28px; font-weight: bold; }}
.stat .label {{ font-size: 12px; color: #8b949e; }}
</style>
</head>
<body>
<div class="header">
    <h1>POC Scanner v2.3 报告</h1>
    <div class="meta">目标：<strong>{target}</strong> | 时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | 耗时：{elapsed:.0f}s</div>
    <div class="stats">
        <div class="stat"><div class="num vuln-count">{len(vulns)}</div><div class="label">漏洞</div></div>
        <div class="stat"><div class="num safe-count">{len(safe)}</div><div class="label">安全</div></div>
        <div class="stat"><div class="num">{len(skipped)}</div><div class="label">跳过</div></div>
        <div class="stat"><div class="num">{stats.get('requests', 0)}</div><div class="label">请求数</div></div>
    </div>
</div>
{batch_section}
<div class="section">
    <h2>指纹信息</h2>
    <table>{fp_items}</table>
</div>
{vuln_section}
</body>
</html>"""
        return html

    def list_reports(self):
        if not os.path.exists(self.config.report_dir):
            return []
        reports = []
        for f in sorted(os.listdir(self.config.report_dir), reverse=True):
            if f.endswith(".html"):
                reports.append(os.path.join(self.config.report_dir, f))
        return reports[:20]


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

        self.results: List[Dict] = []
        self._stop_event = Event()
        self._skipped = 0
        self._target_urls: List[str] = []

    def _check_poc_repo(self):
        poc_folder = self.config.poc_folder
        if not poc_folder or not os.path.exists(poc_folder):
            self.logger.warning(f"POC 目录不存在：{poc_folder}")
            self.logger.info("正在从 GitHub 自动下载 POC 库...")
            default_poc_dir = "POC"
            if not os.path.exists(default_poc_dir):
                try:
                    subprocess.check_call(["git", "clone", "--depth", "1", self.config.poc_repo_url, default_poc_dir])
                    self.logger.info(f"POC 库已下载到：{default_poc_dir}")
                    self.config.poc_folder = default_poc_dir
                except subprocess.CalledProcessError:
                    self.logger.error("Git 克隆失败，请检查网络连接或手动下载 POC 库")
                    self.logger.info(f"下载地址：{self.config.poc_repo_url}")
                except FileNotFoundError:
                    self.logger.error("未找到 Git 命令，请先安装 Git")
                    self.logger.info(f"然后运行：git clone {self.config.poc_repo_url}")
            else:
                self.logger.info(f"使用现有 POC 目录：{default_poc_dir}")
                self.config.poc_folder = default_poc_dir
        else:
            poc_count = len([f for f in os.listdir(poc_folder) if f.endswith(".md")])
            if poc_count == 0:
                self.logger.warning(f"POC 目录为空：{poc_folder}")
                self.logger.info("正在从 GitHub 自动下载 POC 库...")
                try:
                    subprocess.check_call(["git", "clone", "--depth", "1", self.config.poc_repo_url, poc_folder])
                    self.logger.info(f"POC 库已下载到：{poc_folder}")
                except subprocess.CalledProcessError:
                    self.logger.error("Git 克隆失败，请检查网络连接")
                except FileNotFoundError:
                    self.logger.error("未找到 Git 命令，请先安装 Git")
            else:
                self.logger.info(f"POC 目录已存在，共 {poc_count} 个 POC")

    def _get_poc_list(self):
        folder = self.config.poc_folder
        if not os.path.exists(folder):
            return []
        return [f.replace(".md", "") for f in os.listdir(folder) if f.endswith(".md")]

    def _scan_single(self, poc_name, base_url, fingerprint):
        poc_path = os.path.join(self.config.poc_folder, f"{poc_name}.md")
        verifier = VulnVerifier(self.config, fingerprint, self.logger, self.modules)

        try:
            with open(poc_path, "r", encoding="utf-8") as f:
                poc_content = f.read()
        except Exception as e:
            return {"poc_name": poc_name, "status": f"读取失败：{e}", "vuln": False}

        if self.config.enable_prefilter:
            should, reason = self.prefilter.should_scan(poc_name, poc_content)
            if not should:
                self._skipped += 1
                return {"poc_name": poc_name, "status": f"预筛跳过：{reason}", "vuln": False, "skipped": True}

        parsed = self.poc_parser.parse_file(poc_path)
        if not parsed:
            return {"poc_name": poc_name, "status": "无有效请求", "vuln": False}

        payloads = self.payload_generator.generate(poc_name, poc_content, fingerprint)
        headers = self.fingerprint_engine.get_headers()

        for req in parsed:
            merged = {**headers, **req.get("headers", {})}
            path = req["path"]
            if not path.startswith("http"):
                path = ("/" + path) if not path.startswith("/") else path
                target_url = base_url.rstrip("/") + path
            else:
                target_url = path

            for payload, custom_rule in payloads:
                if self._stop_event.is_set():
                    return {"poc_name": poc_name, "status": "中断", "vuln": False}
                all_test = [req["body"]] if req.get("body") else []
                if payload not in all_test:
                    all_test.append(payload)

                for p in all_test:
                    rule = custom_rule if p == payload else None
                    resp = self.request_engine.send(req["method"], target_url, merged, p)
                    if resp is None:
                        continue
                    is_vuln, conf, reason = verifier.verify(resp, p, poc_name, rule)
                    if is_vuln:
                        return {
                            "poc_name": poc_name, "method": req["method"],
                            "url": target_url, "payload": p[:100] if p else "default",
                            "status_code": resp.status_code, "response_length": len(resp.text),
                            "confidence": round(conf, 2), "reason": reason, "vuln": True,
                        }

        return {"poc_name": poc_name, "url": base_url, "status_code": 0, "vuln": False}

    def scan(self) -> List[Dict]:
        base_url = self.config.target_url
        all_pocs = self._get_poc_list()
        if not all_pocs:
            self.logger.error("未找到 POC")
            return []

        completed_set = self.checkpoint.load()
        remaining = [p for p in all_pocs if not self.checkpoint.is_completed(p)]
        if len(remaining) < len(all_pocs):
            self.logger.info(f"跳过 {len(all_pocs) - len(remaining)} 已完成")

        self.logger.info(f"待扫描：{len(remaining)}/{len(all_pocs)} | 速率：{self.config.payload_interval}s")
        self.logger.info("-" * 50)

        fingerprint = self.fingerprint_engine.identify(base_url)
        if "error" in fingerprint:
            fingerprint = {}

        if self.config.enable_prefilter:
            self.prefilter.build_profile(fingerprint)

        results = []
        completed = 0
        total = len(remaining)
        start = time.time()
        self._skipped = 0

        for poc_name in remaining:
            if self._stop_event.is_set():
                break
            if completed % self.config.memory_check_interval == 0 and completed > 0:
                self.memory_guard.check()

            result = self._scan_single(poc_name, base_url, fingerprint)
            results.append(result)
            completed += 1
            self.checkpoint.save_one(poc_name)

            elapsed = time.time() - start
            eta = (elapsed / completed) * (total - completed) if completed else 0

            if result.get("vuln"):
                self.logger.info(f"[{completed}/{total}]  {result['poc_name']} | "
                               f"置信度 {result.get('confidence', 0)} | {result.get('reason', '')}")
            elif not result.get("skipped"):
                self.logger.info(f"[{completed}/{total}]  {result['poc_name']}")

            if completed % 10 == 0:
                self.logger.info(f" {completed}/{total} | {elapsed:.0f}s | ~{eta:.0f}s | "
                               f"请求 {self.rate_limiter.request_count} | 跳过 {self._skipped}")

        elapsed = time.time() - start
        vuln_count = len([r for r in results if r.get("vuln")])
        self.logger.info("=" * 50)
        self.logger.info(f"完成 | {elapsed:.0f}s | {vuln_count} 漏洞 | {self._skipped} 跳过")
        self.report_generator.generate(base_url, results, fingerprint,
                                       {"total": len(all_pocs), "skipped": self._skipped,
                                        "requests": self.rate_limiter.request_count,
                                        "elapsed": round(elapsed, 1)})
        self.checkpoint.clear()
        self.results = results
        return results

    def stop(self):
        self._stop_event.set()
        self.logger.info("中断，断点已保存")

    def load_targets(self, filepath: str) -> int:
        if not os.path.exists(filepath):
            self.logger.error(f"目标文件不存在：{filepath}")
            return 0
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            self._target_urls = urls
            self.logger.info(f"已加载 {len(urls)} 个目标")
            return len(urls)
        except Exception as e:
            self.logger.error(f"加载目标失败：{e}")
            return 0

    def scan_batch(self) -> List[Dict]:
        if not self._target_urls:
            self.logger.error("未加载目标列表，先用 targets <文件> 加载")
            return []

        batch_results = []
        total_targets = len(self._target_urls)

        for i, url in enumerate(self._target_urls):
            if self._stop_event.is_set():
                break

            self.logger.info(f"\n{'='*50}")
            self.logger.info(f"目标 [{i+1}/{total_targets}]: {url}")
            self.config.target_url = url

            self.checkpoint = CheckpointManager(self.config, self.logger)
            self._skipped = 0

            results = self.scan()

            vuln_count = len([r for r in results if r.get("vuln")])
            elapsed = 0
            batch_results.append({
                "target": url,
                "results": results,
                "vuln_count": vuln_count,
                "elapsed": elapsed,
            })

            self.logger.info(f" [{i+1}/{total_targets}] {url}: {vuln_count} 漏洞")

        if batch_results:
            all_results = []
            for br in batch_results:
                all_results.extend(br.get("results", []))

            total_vulns = sum(br["vuln_count"] for br in batch_results)
            self.logger.info(f"\n{'='*50}")
            self.logger.info(f"批量扫描完成：{total_targets} 目标 | {total_vulns} 漏洞")

            first_fp = self.fingerprint_engine.baseline or {}
            self.report_generator.generate(
                self._target_urls[0], all_results, first_fp,
                {"total": 0, "skipped": 0, "requests": self.rate_limiter.request_count, "elapsed": 0},
                batch_results=batch_results
            )

        return batch_results


def main():
    print("=" * 50)
    print("  POC Scanner v2.3 — 批量扫描 + HTML 报告版")
    print("  输入 help 查看命令 | 输入 scan 开始扫描")
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
                print("\n  targets <文件>     加载批量目标 URL 列表")
                print("  scan               开始扫描 (单目标或批量)")
                print("  report             查看历史报告")
                continue

            if lower.startswith("targets"):
                parts = cmd.split(maxsplit=1)
                if len(parts) < 2:
                    print("用法：targets <URL 列表文件>")
                    print("文件格式：每行一个 URL，# 开头为注释")
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

                if scanner._target_urls:
                    print(f"批量模式：{len(scanner._target_urls)} 个目标")
                    try:
                        scanner.scan_batch()
                    except KeyboardInterrupt:
                        scanner.stop()
                        print("\n已中断，断点已保存")
                else:
                    if not config.target_url:
                        config.target_url = input("目标 URL: ").strip()
                    try:
                        scanner.scan()
                    except KeyboardInterrupt:
                        scanner.stop()
                        print("\n已中断，断点已保存")
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
