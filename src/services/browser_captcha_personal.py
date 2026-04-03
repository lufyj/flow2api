"""
浏览器自动化获取 reCAPTCHA token
使用 nodriver (undetected-chromedriver 继任者) 实现反检测浏览器
支持常驻模式：维护全局共享的常驻标签页池，即时生成 token
"""
import asyncio
from collections import deque
import inspect
import time
import os
import sys
import re
import json
import random
import shutil
import tempfile
import subprocess
import traceback
from typing import Optional, Dict, Any, Iterable

from ..core.logger import debug_logger
from ..core.config import config


# ==================== Docker 环境检测 ====================
def _is_running_in_docker() -> bool:
    """检测是否在 Docker 容器中运行"""
    # 方法1: 检查 /.dockerenv 文件
    if os.path.exists('/.dockerenv'):
        return True
    # 方法2: 检查 cgroup
    try:
        with open('/proc/1/cgroup', 'r') as f:
            content = f.read()
            if 'docker' in content or 'kubepods' in content or 'containerd' in content:
                return True
    except:
        pass
    # 方法3: 检查环境变量
    if os.environ.get('DOCKER_CONTAINER') or os.environ.get('KUBERNETES_SERVICE_HOST'):
        return True
    return False


IS_DOCKER = _is_running_in_docker()


def _is_truthy_env(name: str) -> bool:
    """判断环境变量是否为 true。"""
    value = os.environ.get(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


ALLOW_DOCKER_HEADED = (
    _is_truthy_env("ALLOW_DOCKER_HEADED_CAPTCHA")
    or _is_truthy_env("ALLOW_DOCKER_BROWSER_CAPTCHA")
)
DOCKER_HEADED_BLOCKED = IS_DOCKER and not ALLOW_DOCKER_HEADED


# ==================== nodriver 自动安装 ====================
def _run_pip_install(package: str, use_mirror: bool = False) -> bool:
    """运行 pip install 命令
    
    Args:
        package: 包名
        use_mirror: 是否使用国内镜像
    
    Returns:
        是否安装成功
    """
    cmd = [sys.executable, '-m', 'pip', 'install', package]
    if use_mirror:
        cmd.extend(['-i', 'https://pypi.tuna.tsinghua.edu.cn/simple'])
    
    try:
        debug_logger.log_info(f"[BrowserCaptcha] 正在安装 {package}...")
        print(f"[BrowserCaptcha] 正在安装 {package}...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            debug_logger.log_info(f"[BrowserCaptcha] ✅ {package} 安装成功")
            print(f"[BrowserCaptcha] ✅ {package} 安装成功")
            return True
        else:
            debug_logger.log_warning(f"[BrowserCaptcha] {package} 安装失败: {result.stderr[:200]}")
            return False
    except Exception as e:
        debug_logger.log_warning(f"[BrowserCaptcha] {package} 安装异常: {e}")
        return False


def _ensure_nodriver_installed() -> bool:
    """确保 nodriver 已安装
    
    Returns:
        是否安装成功/已安装
    """
    try:
        import nodriver
        debug_logger.log_info("[BrowserCaptcha] nodriver 已安装")
        return True
    except ImportError:
        pass
    
    debug_logger.log_info("[BrowserCaptcha] nodriver 未安装，开始自动安装...")
    print("[BrowserCaptcha] nodriver 未安装，开始自动安装...")
    
    # 先尝试官方源
    if _run_pip_install('nodriver', use_mirror=False):
        return True
    
    # 官方源失败，尝试国内镜像
    debug_logger.log_info("[BrowserCaptcha] 官方源安装失败，尝试国内镜像...")
    print("[BrowserCaptcha] 官方源安装失败，尝试国内镜像...")
    if _run_pip_install('nodriver', use_mirror=True):
        return True
    
    debug_logger.log_error("[BrowserCaptcha] ❌ nodriver 自动安装失败，请手动安装: pip install nodriver")
    print("[BrowserCaptcha] ❌ nodriver 自动安装失败，请手动安装: pip install nodriver")
    return False


# 尝试导入 nodriver
uc = None
NODRIVER_AVAILABLE = False

if DOCKER_HEADED_BLOCKED:
    debug_logger.log_warning(
        "[BrowserCaptcha] 检测到 Docker 环境，默认禁用内置浏览器打码。"
        "如需启用请设置 ALLOW_DOCKER_HEADED_CAPTCHA=true，并提供 DISPLAY/Xvfb。"
    )
    print("[BrowserCaptcha] ⚠️ 检测到 Docker 环境，默认禁用内置浏览器打码")
    print("[BrowserCaptcha] 如需启用请设置 ALLOW_DOCKER_HEADED_CAPTCHA=true，并提供 DISPLAY/Xvfb")
else:
    if IS_DOCKER and ALLOW_DOCKER_HEADED:
        debug_logger.log_warning(
            "[BrowserCaptcha] Docker 内置浏览器打码白名单已启用，请确保 DISPLAY/Xvfb 可用"
        )
        print("[BrowserCaptcha] ✅ Docker 内置浏览器打码白名单已启用")
    if _ensure_nodriver_installed():
        try:
            import nodriver as uc
            NODRIVER_AVAILABLE = True
        except ImportError as e:
            debug_logger.log_error(f"[BrowserCaptcha] nodriver 导入失败: {e}")
            print(f"[BrowserCaptcha] ❌ nodriver 导入失败: {e}")


def _parse_proxy_url(proxy_url: str):
    """Parse a proxy URL into (protocol, host, port, username, password)."""
    if not proxy_url:
        return None, None, None, None, None
    url = proxy_url.strip()
    if not re.match(r'^(http|https|socks5h?|socks5)://', url):
        url = f"http://{url}"
    m = re.match(r'^(socks5h?|socks5|http|https)://(?:([^:]+):([^@]+)@)?([^:]+):(\d+)$', url)
    if not m:
        return None, None, None, None, None
    protocol, username, password, host, port = m.groups()
    if protocol == "socks5h":
        protocol = "socks5"
    return protocol, host, port, username, password


def _create_proxy_auth_extension(protocol: str, host: str, port: str, username: str, password: str) -> str:
    """Create a temporary Chrome extension directory for proxy authentication.
    Returns the path to the extension directory."""
    ext_dir = tempfile.mkdtemp(prefix="nodriver_proxy_auth_")

    scheme_map = {"http": "http", "https": "https", "socks5": "socks5"}
    scheme = scheme_map.get(protocol, "http")

    manifest = {
        "version": "1.0.0",
        "manifest_version": 2,
        "name": "Proxy Auth Helper",
        "permissions": [
            "proxy", "tabs", "unlimitedStorage", "storage",
            "<all_urls>", "webRequest", "webRequestBlocking"
        ],
        "background": {"scripts": ["background.js"]},
        "minimum_chrome_version": "76.0.0"
    }
    background_js = (
        "var config = {\n"
        '    mode: "fixed_servers",\n'
        "    rules: {\n"
        "        singleProxy: {\n"
        f'            scheme: "{scheme}",\n'
        f'            host: "{host}",\n'
        f"            port: parseInt({port})\n"
        "        },\n"
        '        bypassList: ["localhost"]\n'
        "    }\n"
        "};\n"
        'chrome.proxy.settings.set({value: config, scope: "regular"}, function(){});\n'
        "chrome.webRequest.onAuthRequired.addListener(\n"
        "    function(details) {\n"
        "        return {\n"
        "            authCredentials: {\n"
        f'                username: "{username}",\n'
        f'                password: "{password}"\n'
        "            }\n"
        "        };\n"
        "    },\n"
        '    {urls: ["<all_urls>"]},\n'
        "    ['blocking']\n"
        ");\n"
    )
    with open(os.path.join(ext_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    with open(os.path.join(ext_dir, "background.js"), "w", encoding="utf-8") as f:
        f.write(background_js)
    return ext_dir


class ResidentTabInfo:
    """常驻标签页信息结构"""
    def __init__(self, tab, slot_id: str, project_id: Optional[str] = None, token_id: Optional[int] = None):
        self.tab = tab
        self.slot_id = slot_id
        self.project_id = project_id or slot_id
        self.token_id = int(token_id) if token_id else None
        self.recaptcha_ready = False
        self.created_at = time.time()
        self.last_used_at = time.time()  # 最后使用时间
        self.use_count = 0  # 使用次数
        self.solve_lock = asyncio.Lock()  # 串行化同一标签页上的执行，降低并发冲突
        self.health_score = 0
        self.upstream_success_count = 0
        self.upstream_error_count = 0
        self.last_token_at = 0.0
        self.last_upstream_success_at = 0.0
        self.cooldown_until = 0.0
        self.recent_token_timestamps = deque()
        self.recent_upstream_success_timestamps = deque()


class BrowserCaptchaService:
    """浏览器自动化获取 reCAPTCHA token（nodriver 有头模式）
    
    支持两种模式：
    1. 常驻模式 (Resident Mode): 维护全局共享常驻标签页池，谁抢到空闲页谁执行
    2. 传统模式 (Legacy Mode): 每次请求创建新标签页 (fallback)
    """

    _instances: Dict[str, 'BrowserCaptchaService'] = {}
    _project_pool_keys: Dict[str, str] = {}
    _lock = asyncio.Lock()
    _PROFILE_LANG_CANDIDATES = [
        "en-US",
        "en-US,en",
        "en-GB,en",
        "en-CA,en",
    ]
    _PROFILE_TIMEZONE_BY_LANG = {
        "en-US": [
            "America/New_York",
            "America/Chicago",
            "America/Denver",
            "America/Los_Angeles",
            "America/Phoenix",
        ],
        "en-GB": [
            "Europe/London",
        ],
        "en-CA": [
            "America/Toronto",
            "America/Vancouver",
            "America/Winnipeg",
        ],
    }
    _PROFILE_COLOR_SCHEME_CANDIDATES = [
        "light",
        "light",
        "dark",
        "no-preference",
    ]
    _PROFILE_REDUCED_MOTION_CANDIDATES = [
        "no-preference",
        "no-preference",
        "reduce",
    ]
    _PROFILE_COLOR_GAMUT_CANDIDATES = [
        "srgb",
        "srgb",
        "p3",
    ]
    _PROFILE_GREASE_BRAND_VERSION_CANDIDATES = ["8", "24", "99"]
    _PROFILE_BRAND_ORDER_CANDIDATES = [
        ("Not.A/Brand", "Chromium", "Google Chrome"),
        ("Chromium", "Not.A/Brand", "Google Chrome"),
        ("Not.A/Brand", "Google Chrome", "Chromium"),
    ]
    _PROFILE_NETWORK_CANDIDATES = [
        {"effective_type": "4g", "rtt": 50, "downlink": 9.5, "save_data": False},
        {"effective_type": "4g", "rtt": 80, "downlink": 7.8, "save_data": False},
        {"effective_type": "4g", "rtt": 120, "downlink": 5.2, "save_data": False},
        {"effective_type": "3g", "rtt": 180, "downlink": 2.4, "save_data": False},
    ]
    _PROFILE_WEBGL_CANDIDATES = [
        {
            "vendor": "Google Inc. (Intel)",
            "renderer": "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
        },
        {
            "vendor": "Google Inc. (Intel)",
            "renderer": "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
        },
        {
            "vendor": "Google Inc. (NVIDIA)",
            "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        },
        {
            "vendor": "Google Inc. (AMD)",
            "renderer": "ANGLE (AMD, AMD Radeon RX 6600 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
        },
    ]
    _PROFILE_CHROME_MAJOR_CANDIDATES = tuple(range(120, 146))
    _PROFILE_TEMPLATE_CANDIDATES = []
    for _chrome_major in _PROFILE_CHROME_MAJOR_CANDIDATES:
        _PROFILE_TEMPLATE_CANDIDATES.append(
            {
                "user_agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    f"Chrome/{_chrome_major}.0.0.0 Safari/537.36"
                ),
                "brands": [
                    {"brand": "Not.A/Brand", "version": "8"},
                    {"brand": "Chromium", "version": str(_chrome_major)},
                    {"brand": "Google Chrome", "version": str(_chrome_major)},
                ],
                "full_version_list": [
                    {"brand": "Not.A/Brand", "version": "8.0.0.0"},
                    {"brand": "Chromium", "version": f"{_chrome_major}.0.0.0"},
                    {"brand": "Google Chrome", "version": f"{_chrome_major}.0.0.0"},
                ],
                "platform": "Windows",
                "platform_version": "10.0.0",
                "architecture": "x86",
                "bitness": "64",
                "model": "",
                "mobile": False,
                "wow64": False,
            }
        )
    del _chrome_major
    _PROFILE_VIEWPORT_CANDIDATES = [
        (1280, 720),
        (1366, 768),
        (1440, 900),
        (1536, 864),
        (1600, 900),
        (1728, 972),
    ]

    def __init__(self, db=None, proxy_url_override: Optional[str] = None, pool_key: Optional[str] = None):
        """初始化服务"""
        self.headless = False  # nodriver 有头模式
        self.browser = None
        self._initialized = False
        self.website_key = "6LdsFiUsAAAAAIjVDZcuLhaHiDn5nnHVXVRQGeMV"
        self.db = db
        self._proxy_url_override = (proxy_url_override or "").strip() or None
        self._pool_key = pool_key or (self._proxy_url_override or "__default__")
        # 使用 None 让 nodriver 自动创建临时目录，避免目录锁定问题
        self.user_data_dir = None
        self._fingerprint_profile = self._build_fingerprint_profile()
        self._tab_fingerprint_profiles: dict[int, Dict[str, Any]] = {}

        # 常驻模式相关属性：打码标签页是全局共享池，不再按 project_id 一对一绑定
        self._resident_tabs: dict[str, 'ResidentTabInfo'] = {}  # slot_id -> 常驻标签页信息
        self._project_resident_affinity: dict[str, str] = {}  # project_id -> slot_id（最近一次使用）
        self._resident_slot_seq = 0
        self._resident_last_selected_order_key: Optional[tuple[float, str]] = None
        self._resident_lock = asyncio.Lock()  # 保护常驻标签页操作
        self._browser_lock = asyncio.Lock()  # 保护浏览器初始化/关闭/重启，避免重复拉起实例
        self._tab_build_lock = asyncio.Lock()  # 串行化冷启动/重建，降低 nodriver 抖动
        self._tab_build_semaphore = asyncio.Semaphore(
            int(max(1, getattr(config, "personal_tab_build_concurrency", 3) or 3))
        )
        self._legacy_lock = asyncio.Lock()  # 避免 legacy fallback 并发失控创建临时标签页
        self._max_resident_tabs = int(max(1, getattr(config, "personal_max_resident_tabs", 5) or 5))  # 最大常驻标签页数量（支持并发）
        self._idle_tab_ttl_seconds = int(max(60, getattr(config, "personal_idle_tab_ttl_seconds", 600) or 600))  # 标签页空闲超时(秒)
        self._idle_reaper_task: Optional[asyncio.Task] = None  # 空闲回收任务
        self._resident_max_use_count = int(max(1, getattr(config, "personal_resident_max_use_count", 3) or 3))
        self._resident_fingerprint_cooldown_seconds = float(
            max(0.0, getattr(config, "personal_resident_fingerprint_cooldown_seconds", 5.0) or 5.0)
        )
        self._resident_runtime_expand_enabled = bool(
            getattr(config, "personal_resident_runtime_expand_enabled", False)
        )
        self._pool_restart_unhealthy_ratio_threshold = float(
            min(
                1.0,
                max(
                    0.1,
                    getattr(config, "personal_pool_restart_unhealthy_ratio_threshold", 0.7) or 0.7,
                ),
            )
        )
        self._pool_restart_min_unhealthy_slots = int(
            max(2, getattr(config, "personal_pool_restart_min_unhealthy_slots", 4) or 4)
        )
        self._pool_restart_cooldown_seconds = float(
            max(5.0, getattr(config, "personal_pool_restart_cooldown_seconds", 45.0) or 45.0)
        )
        self._pool_restart_cooldown_until = 0.0
        self._resident_unhealthy_health_threshold = int(
            min(-1, getattr(config, "personal_resident_unhealthy_health_threshold", -6) or -6)
        )
        self._resident_rebuild_health_threshold = int(
            min(
                self._resident_unhealthy_health_threshold,
                getattr(config, "personal_resident_rebuild_health_threshold", -12) or -12,
            )
        )
        self._slot_wait_timeout_seconds = float(
            max(1.0, getattr(config, "personal_slot_wait_timeout_seconds", 12.0) or 12.0)
        )
        self._flow_recover_threshold = int(
            max(1, getattr(config, "browser_personal_recover_threshold", 2) or 2)
        )
        self._fingerprint_window_seconds = float(
            max(1.0, getattr(config, "personal_fingerprint_window_seconds", 30.0) or 30.0)
        )
        self._fingerprint_max_uses_per_window = int(
            max(1, getattr(config, "personal_fingerprint_max_uses_per_window", 2) or 2)
        )
        self._fingerprint_rate_limit_cooldown_seconds = float(
            max(0.0, getattr(config, "personal_fingerprint_rate_limit_cooldown_seconds", 15.0) or 15.0)
        )
        self._standby_target_count = int(
            max(0, getattr(config, "personal_resident_standby_count", 0) or 0)
        )
        self._queue_limit = int(
            max(1, getattr(config, "personal_queue_limit", 20) or 20)
        )
        self._queue_acquire_timeout_seconds = float(
            max(1.0, getattr(config, "personal_queue_acquire_timeout_seconds", 10.0) or 10.0)
        )
        self._command_timeout_seconds = 8.0
        self._navigation_timeout_seconds = 20.0
        self._solve_timeout_seconds = 45.0
        self._session_refresh_timeout_seconds = 45.0

        # 兼容旧 API（保留 single resident 属性作为别名）
        self.resident_project_id: Optional[str] = None  # 向后兼容
        self.resident_tab = None                         # 向后兼容
        self._running = False                            # 向后兼容
        self._recaptcha_ready = False                    # 向后兼容
        self._last_fingerprint: Optional[Dict[str, Any]] = None
        self._resident_error_streaks: dict[str, int] = {}
        self._project_flow_error_streaks: dict[str, int] = {}
        self._proxy_url: Optional[str] = None
        self._proxy_ext_dir: Optional[str] = None
        self._browser_ready_event = asyncio.Event()
        self._queue_semaphore = asyncio.Semaphore(self._queue_limit)
        self._standby_fill_task: Optional[asyncio.Task] = None
        # 自定义站点打码常驻页（用于 score-test）
        self._custom_tabs: dict[str, Dict[str, Any]] = {}
        self._custom_lock = asyncio.Lock()

    @classmethod
    async def get_instance(cls, db=None) -> 'BrowserCaptchaService':
        return await cls.get_pool_instance(db=db, proxy_url=None)

    @classmethod
    async def get_pool_instance(
        cls,
        db=None,
        proxy_url: Optional[str] = None,
    ) -> 'BrowserCaptchaService':
        normalized_proxy_url = (proxy_url or "").strip() or None
        pool_key = normalized_proxy_url or "__default__"
        instance = cls._instances.get(pool_key)
        if instance is not None:
            if db is not None:
                instance.db = db
            return instance

        async with cls._lock:
            instance = cls._instances.get(pool_key)
            if instance is None:
                instance = cls(db, proxy_url_override=normalized_proxy_url, pool_key=pool_key)
                instance._idle_reaper_task = asyncio.create_task(instance._idle_tab_reaper_loop())
                cls._instances[pool_key] = instance
            elif db is not None:
                instance.db = db
            return instance

    @classmethod
    async def get_instance_for_token(
        cls,
        db=None,
        token_id: Optional[int] = None,
    ) -> 'BrowserCaptchaService':
        proxy_url = None
        if db is not None and token_id:
            try:
                token = await db.get_token(token_id)
                if token and getattr(token, "captcha_proxy_url", None):
                    proxy_url = str(token.captcha_proxy_url or "").strip() or None
            except Exception as e:
                debug_logger.log_warning(f"[BrowserCaptcha] 读取 token({token_id}) 打码代理失败: {e}")
        return await cls.get_pool_instance(db=db, proxy_url=proxy_url)

    @classmethod
    async def get_instance_for_project(
        cls,
        db=None,
        project_id: Optional[str] = None,
    ) -> 'BrowserCaptchaService':
        normalized_project_id = str(project_id or "").strip()
        if normalized_project_id:
            pool_key = cls._project_pool_keys.get(normalized_project_id)
            if pool_key:
                instance = cls._instances.get(pool_key)
                if instance is not None:
                    if db is not None:
                        instance.db = db
                    return instance
        return await cls.get_instance(db=db)

    @classmethod
    def _build_fingerprint_profile(
        cls,
        *,
        excluded_user_agents: Optional[set[str]] = None,
    ) -> Dict[str, Any]:
        seed = random.SystemRandom().randint(1, 2**31 - 1)
        rng = random.Random(seed)
        excluded_user_agents = {
            str(user_agent or "").strip()
            for user_agent in (excluded_user_agents or set())
            if str(user_agent or "").strip()
        }
        available_templates = [
            candidate
            for candidate in cls._PROFILE_TEMPLATE_CANDIDATES
            if str(candidate.get("user_agent") or "").strip() not in excluded_user_agents
        ]
        template_pool = available_templates or cls._PROFILE_TEMPLATE_CANDIDATES
        template = dict(rng.choice(template_pool))
        width, height = rng.choice(cls._PROFILE_VIEWPORT_CANDIDATES)
        window_x = 2400 + rng.randint(0, 320)
        window_y = 80 + rng.randint(0, 220)
        lang = rng.choice(cls._PROFILE_LANG_CANDIDATES)
        language_items = [part.strip() for part in lang.split(",") if part.strip()]
        lang_primary = language_items[0] if language_items else "en-US"
        timezone_candidates = cls._PROFILE_TIMEZONE_BY_LANG.get(lang_primary, ["UTC"])
        timezone = rng.choice(timezone_candidates)
        dpr = rng.choice([1, 1.25, 1.5, 2])
        hardware_concurrency = rng.choice([4, 8, 12, 16])
        device_memory = rng.choice([4, 8, 16])
        max_touch_points = rng.choice([0, 0, 0, 1])
        color_depth = rng.choice([24, 30])
        prefers_color_scheme = rng.choice(cls._PROFILE_COLOR_SCHEME_CANDIDATES)
        prefers_reduced_motion = rng.choice(cls._PROFILE_REDUCED_MOTION_CANDIDATES)
        color_gamut = rng.choice(cls._PROFILE_COLOR_GAMUT_CANDIDATES)
        network_profile = dict(rng.choice(cls._PROFILE_NETWORK_CANDIDATES))
        webgl_profile = dict(rng.choice(cls._PROFILE_WEBGL_CANDIDATES))
        screen_width = width + rng.choice([0, 64, 80, 96, 128])
        screen_height = height + rng.choice([72, 80, 96, 120, 144])
        navigator_platform = "Win32" if template.get("platform", "Windows") == "Windows" else str(template.get("platform") or "")
        chrome_major = ""
        for brand_item in template.get("brands") or []:
            brand_name = str((brand_item or {}).get("brand") or "").strip()
            if brand_name == "Google Chrome":
                chrome_major = str((brand_item or {}).get("version") or "").strip()
                break
        if not chrome_major:
            user_agent_value = str(template.get("user_agent") or "")
            user_agent_match = re.search(r"Chrome/([0-9]+)\.0\.0\.0", user_agent_value)
            if user_agent_match:
                chrome_major = user_agent_match.group(1)
        chrome_major = chrome_major or "126"
        grease_brand_version = rng.choice(cls._PROFILE_GREASE_BRAND_VERSION_CANDIDATES)
        brand_entries = {
            "Not.A/Brand": {
                "brand": "Not.A/Brand",
                "version": grease_brand_version,
            },
            "Chromium": {
                "brand": "Chromium",
                "version": chrome_major,
            },
            "Google Chrome": {
                "brand": "Google Chrome",
                "version": chrome_major,
            },
        }
        full_version_entries = {
            "Not.A/Brand": {
                "brand": "Not.A/Brand",
                "version": f"{grease_brand_version}.0.0.0",
            },
            "Chromium": {
                "brand": "Chromium",
                "version": f"{chrome_major}.0.0.0",
            },
            "Google Chrome": {
                "brand": "Google Chrome",
                "version": f"{chrome_major}.0.0.0",
            },
        }
        brand_order = rng.choice(cls._PROFILE_BRAND_ORDER_CANDIDATES)
        brands = [dict(brand_entries[name]) for name in brand_order]
        full_version_list = [dict(full_version_entries[name]) for name in brand_order]
        return {
            "user_agent": template.get("user_agent", ""),
            "brands": brands,
            "full_version_list": full_version_list,
            "platform": template.get("platform", "Windows"),
            "platform_version": template.get("platform_version", "10.0.0"),
            "architecture": template.get("architecture", "x86"),
            "bitness": template.get("bitness", "64"),
            "model": template.get("model", ""),
            "mobile": bool(template.get("mobile", False)),
            "wow64": bool(template.get("wow64", False)),
            "lang": lang,
            "languages": language_items or ["en-US"],
            "timezone": timezone,
            "navigator_platform": navigator_platform,
            "viewport": {"width": width, "height": height},
            "window_position": {"x": window_x, "y": window_y},
            "device_pixel_ratio": dpr,
            "hardware_concurrency": hardware_concurrency,
            "device_memory": device_memory,
            "max_touch_points": max_touch_points,
            "color_depth": color_depth,
            "pixel_depth": color_depth,
            "prefers_color_scheme": prefers_color_scheme,
            "prefers_reduced_motion": prefers_reduced_motion,
            "color_gamut": color_gamut,
            "network": network_profile,
            "webgl_vendor": webgl_profile.get("vendor", ""),
            "webgl_renderer": webgl_profile.get("renderer", ""),
            "screen": {
                "width": screen_width,
                "height": screen_height,
                "avail_width": screen_width,
                "avail_height": max(height, screen_height - rng.choice([32, 40, 48])),
            },
            "seed": seed,
        }

    def _collect_active_tab_user_agents(self) -> set[str]:
        active_user_agents: set[str] = set()
        for profile in self._tab_fingerprint_profiles.values():
            if not isinstance(profile, dict):
                continue
            user_agent = str(profile.get("user_agent") or "").strip()
            if user_agent:
                active_user_agents.add(user_agent)
        return active_user_agents

    def _build_unique_tab_fingerprint_profile(self) -> Dict[str, Any]:
        return self._build_fingerprint_profile(
            excluded_user_agents=self._collect_active_tab_user_agents(),
        )

    def _get_tab_fingerprint_profile(self, tab) -> Optional[Dict[str, Any]]:
        if not tab:
            return None
        profile = self._tab_fingerprint_profiles.get(id(tab))
        return dict(profile) if isinstance(profile, dict) else None

    def _set_tab_fingerprint_profile(self, tab, profile: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not tab or not isinstance(profile, dict):
            return None
        stored_profile = dict(profile)
        self._tab_fingerprint_profiles[id(tab)] = stored_profile
        return dict(stored_profile)

    def _clear_tab_fingerprint_profile(self, tab):
        if not tab:
            return
        self._tab_fingerprint_profiles.pop(id(tab), None)

    def _ensure_tab_fingerprint_profile(
        self,
        tab,
        profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        existing_profile = self._get_tab_fingerprint_profile(tab)
        if existing_profile:
            return existing_profile
        base_profile = profile if isinstance(profile, dict) else self._build_unique_tab_fingerprint_profile()
        stored_profile = self._set_tab_fingerprint_profile(tab, base_profile) or dict(base_profile)
        return stored_profile

    def _build_user_agent_metadata(self, profile: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        profile = profile or self._fingerprint_profile or {}
        return {
            "brands": profile.get("brands") or [],
            "fullVersionList": profile.get("full_version_list") or [],
            "platform": str(profile.get("platform") or "Windows"),
            "platformVersion": str(profile.get("platform_version") or "10.0.0"),
            "architecture": str(profile.get("architecture") or "x86"),
            "bitness": str(profile.get("bitness") or "64"),
            "model": str(profile.get("model") or ""),
            "mobile": bool(profile.get("mobile", False)),
            "wow64": bool(profile.get("wow64", False)),
        }

    def _build_cdp_user_agent_metadata(self, profile: Optional[Dict[str, Any]] = None):
        profile = profile or self._fingerprint_profile or {}
        cdp_module = getattr(uc, "cdp", None)
        emulation = getattr(cdp_module, "emulation", None) if cdp_module else None
        if emulation is None:
            return None

        brand_cls = getattr(emulation, "UserAgentBrandVersion", None)
        metadata_cls = getattr(emulation, "UserAgentMetadata", None)
        if brand_cls is None or metadata_cls is None:
            return None

        def build_brands(items):
            if not isinstance(items, list):
                return None
            result = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                brand = str(item.get("brand") or "").strip()
                version = str(item.get("version") or "").strip()
                if not brand or not version:
                    continue
                result.append(brand_cls(brand=brand, version=version))
            return result or None

        return metadata_cls(
            platform=str(profile.get("platform") or "Windows"),
            platform_version=str(profile.get("platform_version") or "10.0.0"),
            architecture=str(profile.get("architecture") or "x86"),
            model=str(profile.get("model") or ""),
            mobile=bool(profile.get("mobile", False)),
            brands=build_brands(profile.get("brands")),
            full_version_list=build_brands(profile.get("full_version_list")),
            bitness=str(profile.get("bitness") or "64"),
            wow64=bool(profile.get("wow64", False)),
        )

    def _build_fingerprint_injection_script(self, profile: Optional[Dict[str, Any]] = None) -> str:
        profile = profile or self._fingerprint_profile or {}
        languages = profile.get("languages") or ["en-US"]
        if not isinstance(languages, list):
            languages = ["en-US"]
        payload = {
            "userAgent": str(profile.get("user_agent") or ""),
            "language": str(profile.get("lang") or languages[0] or "en-US"),
            "languages": [str(item) for item in languages if str(item).strip()],
            "devicePixelRatio": float(profile.get("device_pixel_ratio") or 1),
            "hardwareConcurrency": int(profile.get("hardware_concurrency") or 8),
            "deviceMemory": int(profile.get("device_memory") or 8),
            "maxTouchPoints": int(profile.get("max_touch_points") or 0),
            "colorDepth": int(profile.get("color_depth") or 24),
            "pixelDepth": int(profile.get("pixel_depth") or 24),
            "screen": profile.get("screen") or {},
            "brands": profile.get("brands") or [],
            "fullVersionList": profile.get("full_version_list") or [],
            "platform": str(profile.get("platform") or "Windows"),
            "platformVersion": str(profile.get("platform_version") or "10.0.0"),
            "navigatorPlatform": str(profile.get("navigator_platform") or "Win32"),
            "architecture": str(profile.get("architecture") or "x86"),
            "bitness": str(profile.get("bitness") or "64"),
            "model": str(profile.get("model") or ""),
            "mobile": bool(profile.get("mobile", False)),
            "wow64": bool(profile.get("wow64", False)),
            "timezone": str(profile.get("timezone") or "UTC"),
            "prefersColorScheme": str(profile.get("prefers_color_scheme") or "light"),
            "prefersReducedMotion": str(profile.get("prefers_reduced_motion") or "no-preference"),
            "colorGamut": str(profile.get("color_gamut") or "srgb"),
            "network": profile.get("network") or {},
            "webglVendor": str(profile.get("webgl_vendor") or ""),
            "webglRenderer": str(profile.get("webgl_renderer") or ""),
        }
        payload_json = json.dumps(payload, ensure_ascii=False)
        return f"""
            (() => {{
                const profile = {payload_json};
                const originalResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;
                const originalMatchMedia = window.matchMedia ? window.matchMedia.bind(window) : null;
                const defineGetter = (target, key, value) => {{
                    if (!target) return;
                    try {{
                        Object.defineProperty(target, key, {{
                            get: () => value,
                            configurable: true
                        }});
                    }} catch (e) {{}}
                }};

                defineGetter(Navigator.prototype, 'webdriver', undefined);
                defineGetter(Navigator.prototype, 'userAgent', profile.userAgent);
                defineGetter(Navigator.prototype, 'appVersion', profile.userAgent.replace(/^Mozilla\\//, ''));
                defineGetter(Navigator.prototype, 'platform', profile.navigatorPlatform || profile.platform);
                defineGetter(Navigator.prototype, 'vendor', 'Google Inc.');
                defineGetter(Navigator.prototype, 'vendorSub', '');
                defineGetter(Navigator.prototype, 'productSub', '20030107');
                defineGetter(Navigator.prototype, 'pdfViewerEnabled', true);
                defineGetter(Navigator.prototype, 'language', profile.language);
                defineGetter(Navigator.prototype, 'languages', profile.languages);
                defineGetter(Navigator.prototype, 'hardwareConcurrency', profile.hardwareConcurrency);
                defineGetter(Navigator.prototype, 'deviceMemory', profile.deviceMemory);
                defineGetter(Navigator.prototype, 'maxTouchPoints', profile.maxTouchPoints);
                defineGetter(window, 'devicePixelRatio', profile.devicePixelRatio);

                try {{
                    Intl.DateTimeFormat.prototype.resolvedOptions = function(...args) {{
                        const result = originalResolvedOptions.apply(this, args);
                        result.timeZone = profile.timezone;
                        if (!result.locale && profile.language) {{
                            result.locale = profile.language;
                        }}
                        return result;
                    }};
                }} catch (e) {{}}

                const uaData = {{
                    brands: profile.brands,
                    mobile: profile.mobile,
                    platform: profile.platform,
                    getHighEntropyValues: async (hints) => {{
                        const response = {{}};
                        const requested = Array.isArray(hints) ? hints : [];
                        for (const hint of requested) {{
                            if (hint === 'architecture') response.architecture = profile.architecture;
                            if (hint === 'bitness') response.bitness = profile.bitness;
                            if (hint === 'formFactors') response.formFactors = profile.mobile ? ['Mobile'] : ['Desktop'];
                            if (hint === 'fullVersionList') response.fullVersionList = profile.fullVersionList;
                            if (hint === 'model') response.model = profile.model;
                            if (hint === 'platform') response.platform = profile.platform;
                            if (hint === 'platformVersion') response.platformVersion = profile.platformVersion;
                            if (hint === 'uaFullVersion') response.uaFullVersion = (profile.fullVersionList[2] && profile.fullVersionList[2].version) || '';
                            if (hint === 'wow64') response.wow64 = profile.wow64;
                        }}
                        return response;
                    }}
                }};
                defineGetter(Navigator.prototype, 'userAgentData', uaData);

                const mediaMatches = {{
                    '(prefers-color-scheme: dark)': profile.prefersColorScheme === 'dark',
                    '(prefers-color-scheme: light)': profile.prefersColorScheme === 'light',
                    '(prefers-reduced-motion: reduce)': profile.prefersReducedMotion === 'reduce',
                    '(prefers-reduced-motion: no-preference)': profile.prefersReducedMotion !== 'reduce',
                    '(color-gamut: p3)': profile.colorGamut === 'p3',
                    '(color-gamut: srgb)': profile.colorGamut !== 'p3'
                }};
                if (originalMatchMedia) {{
                    window.matchMedia = (query) => {{
                        const normalized = String(query || '').trim();
                        if (Object.prototype.hasOwnProperty.call(mediaMatches, normalized)) {{
                            return {{
                                matches: !!mediaMatches[normalized],
                                media: normalized,
                                onchange: null,
                                addListener: () => {{}},
                                removeListener: () => {{}},
                                addEventListener: () => {{}},
                                removeEventListener: () => {{}},
                                dispatchEvent: () => false
                            }};
                        }}
                        return originalMatchMedia(normalized);
                    }};
                }}

                if (Navigator.prototype && 'connection' in Navigator.prototype) {{
                    const connectionValue = {{
                        effectiveType: profile.network.effective_type || '4g',
                        rtt: Number(profile.network.rtt || 80),
                        downlink: Number(profile.network.downlink || 6.5),
                        saveData: !!profile.network.save_data,
                        addEventListener: () => {{}},
                        removeEventListener: () => {{}},
                        dispatchEvent: () => false
                    }};
                    defineGetter(Navigator.prototype, 'connection', connectionValue);
                }}

                if (window.screen) {{
                    defineGetter(window.screen, 'width', profile.screen.width);
                    defineGetter(window.screen, 'height', profile.screen.height);
                    defineGetter(window.screen, 'availWidth', profile.screen.avail_width);
                    defineGetter(window.screen, 'availHeight', profile.screen.avail_height);
                    defineGetter(window.screen, 'colorDepth', profile.colorDepth);
                    defineGetter(window.screen, 'pixelDepth', profile.pixelDepth);
                }}

                const patchWebGL = (proto) => {{
                    if (!proto || typeof proto.getParameter !== 'function') return;
                    const originalGetParameter = proto.getParameter;
                    proto.getParameter = function(parameter) {{
                        if (parameter === 37445 && profile.webglVendor) return profile.webglVendor;
                        if (parameter === 37446 && profile.webglRenderer) return profile.webglRenderer;
                        return originalGetParameter.apply(this, arguments);
                    }};
                    if (typeof proto.getExtension === 'function') {{
                        const originalGetExtension = proto.getExtension;
                        proto.getExtension = function(name) {{
                            if (name === 'WEBGL_debug_renderer_info') {{
                                return {{
                                    UNMASKED_VENDOR_WEBGL: 37445,
                                    UNMASKED_RENDERER_WEBGL: 37446
                                }};
                            }}
                            return originalGetExtension.apply(this, arguments);
                        }};
                    }}
                }};
                patchWebGL(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype);
                patchWebGL(window.WebGL2RenderingContext && window.WebGL2RenderingContext.prototype);
            }})()
        """

    async def _apply_tab_network_fingerprint_profile(
        self,
        tab,
        profile: Optional[Dict[str, Any]] = None,
        *,
        label: str = "apply_tab_network_fingerprint_profile",
    ):
        if not tab:
            return
        effective_profile = profile or self._fingerprint_profile or {}
        user_agent = str(effective_profile.get("user_agent") or "").strip()
        if not user_agent:
            return

        accept_language = str(effective_profile.get("lang") or "").strip()
        if not accept_language:
            languages = effective_profile.get("languages") or []
            if isinstance(languages, list) and languages:
                accept_language = str(languages[0] or "").strip()
        platform = str(effective_profile.get("platform") or "Windows")
        cdp_module = getattr(uc, "cdp", None)
        network = getattr(cdp_module, "network", None) if cdp_module else None
        if network is None:
            raise RuntimeError("nodriver.cdp.network 不可用，无法设置网络层 UA override")

        send_method = getattr(tab, "send", None)
        if send_method is None:
            raise RuntimeError("nodriver tab.send 不可用，无法设置标签页网络层 UA override")

        await self._run_with_timeout(
            send_method(network.enable()),
            self._command_timeout_seconds,
            f"{label}:enable",
        )
        await self._run_with_timeout(
            send_method(
                network.set_user_agent_override(
                    user_agent=user_agent,
                    accept_language=accept_language or None,
                    platform=platform,
                    user_agent_metadata=self._build_cdp_user_agent_metadata(effective_profile),
                )
            ),
            self._command_timeout_seconds,
            f"{label}:override",
        )
        debug_logger.log_info(
            "[BrowserCaptcha] tab_network_fingerprint_applied: "
            f"label={label}, "
            f"ua={user_agent[:160]}, "
            f"accept_language={accept_language or '<empty>'}, "
            f"platform={platform}, "
            f"brands={json.dumps(self._build_user_agent_metadata(effective_profile).get('brands', []), ensure_ascii=False)[:220]}, "
            f"full_versions={json.dumps(self._build_user_agent_metadata(effective_profile).get('fullVersionList', []), ensure_ascii=False)[:220]}"
        )

    async def _apply_tab_fingerprint_profile(
        self,
        tab,
        label: str,
        fingerprint_profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        profile = self._ensure_tab_fingerprint_profile(tab, fingerprint_profile)
        try:
            await self._apply_tab_network_fingerprint_profile(
                tab,
                profile,
                label=f"{label}:network",
            )
        except Exception as network_error:
            debug_logger.log_warning(
                f"[BrowserCaptcha] tab_network_fingerprint_failed: label={label}, error={network_error}"
            )
        await self._tab_evaluate(
            tab,
            self._build_fingerprint_injection_script(profile),
            label=label,
            timeout_seconds=5.0,
        )
        try:
            page_snapshot_raw = await self._tab_evaluate(
                tab,
                """
                (async () => JSON.stringify({
                    user_agent: navigator.userAgent || "",
                    language: navigator.language || "",
                    languages: Array.isArray(navigator.languages) ? navigator.languages : [],
                    ua_data_brands: Array.isArray(navigator.userAgentData?.brands) ? navigator.userAgentData.brands : [],
                    ua_data_mobile: typeof navigator.userAgentData?.mobile === "boolean" ? navigator.userAgentData.mobile : null,
                    ua_data_platform: navigator.userAgentData?.platform || ""
                }))()
                """,
                label=f"{label}:snapshot",
                timeout_seconds=5.0,
            )
            page_snapshot = json.loads(page_snapshot_raw) if isinstance(page_snapshot_raw, str) and page_snapshot_raw else {}
            if isinstance(page_snapshot, dict):
                debug_logger.log_info(
                    "[BrowserCaptcha] tab_fingerprint_applied: "
                    f"label={label}, "
                    f"profile_ua={str(profile.get('user_agent') or '')[:160]}, "
                    f"page_ua={str(page_snapshot.get('user_agent') or '')[:160]}, "
                    f"page_lang={str(page_snapshot.get('language') or '')}, "
                    f"page_languages={json.dumps(page_snapshot.get('languages') or [], ensure_ascii=False)[:160]}, "
                    f"page_brands={json.dumps(page_snapshot.get('ua_data_brands') or [], ensure_ascii=False)[:220]}, "
                    f"page_platform={str(page_snapshot.get('ua_data_platform') or '')}, "
                    f"page_mobile={page_snapshot.get('ua_data_mobile')}"
                )
        except Exception as snapshot_error:
            debug_logger.log_warning(
                f"[BrowserCaptcha] tab_fingerprint_snapshot_failed: label={label}, error={snapshot_error}"
            )
        return profile

    async def reload_config(self):
        """热更新配置（从数据库重新加载）"""
        from ..core.config import config
        old_max_tabs = self._max_resident_tabs
        old_idle_ttl = self._idle_tab_ttl_seconds
        old_max_use_count = self._resident_max_use_count
        old_fingerprint_cooldown = self._resident_fingerprint_cooldown_seconds
        old_unhealthy_threshold = self._resident_unhealthy_health_threshold
        old_rebuild_health_threshold = self._resident_rebuild_health_threshold
        old_slot_wait_timeout = self._slot_wait_timeout_seconds
        old_window_seconds = self._fingerprint_window_seconds
        old_window_max_uses = self._fingerprint_max_uses_per_window

        self._max_resident_tabs = config.personal_max_resident_tabs
        self._idle_tab_ttl_seconds = config.personal_idle_tab_ttl_seconds
        self._resident_max_use_count = int(
            max(1, getattr(config, "personal_resident_max_use_count", old_max_use_count) or old_max_use_count)
        )
        self._resident_fingerprint_cooldown_seconds = float(
            max(
                0.0,
                getattr(config, "personal_resident_fingerprint_cooldown_seconds", old_fingerprint_cooldown)
                or old_fingerprint_cooldown,
            )
        )
        self._resident_runtime_expand_enabled = bool(
            getattr(config, "personal_resident_runtime_expand_enabled", self._resident_runtime_expand_enabled)
        )
        self._pool_restart_unhealthy_ratio_threshold = float(
            min(
                1.0,
                max(
                    0.1,
                    getattr(
                        config,
                        "personal_pool_restart_unhealthy_ratio_threshold",
                        self._pool_restart_unhealthy_ratio_threshold,
                    )
                    or self._pool_restart_unhealthy_ratio_threshold,
                ),
            )
        )
        self._pool_restart_min_unhealthy_slots = int(
            max(
                2,
                getattr(
                    config,
                    "personal_pool_restart_min_unhealthy_slots",
                    self._pool_restart_min_unhealthy_slots,
                )
                or self._pool_restart_min_unhealthy_slots,
            )
        )
        self._pool_restart_cooldown_seconds = float(
            max(
                5.0,
                getattr(
                    config,
                    "personal_pool_restart_cooldown_seconds",
                    self._pool_restart_cooldown_seconds,
                )
                or self._pool_restart_cooldown_seconds,
            )
        )
        self._resident_unhealthy_health_threshold = int(
            min(
                -1,
                getattr(config, "personal_resident_unhealthy_health_threshold", old_unhealthy_threshold)
                or old_unhealthy_threshold,
            )
        )
        self._resident_rebuild_health_threshold = int(
            min(
                self._resident_unhealthy_health_threshold,
                getattr(config, "personal_resident_rebuild_health_threshold", old_rebuild_health_threshold)
                or old_rebuild_health_threshold,
            )
        )
        self._slot_wait_timeout_seconds = float(
            max(1.0, getattr(config, "personal_slot_wait_timeout_seconds", old_slot_wait_timeout) or old_slot_wait_timeout)
        )
        self._fingerprint_window_seconds = float(
            max(1.0, getattr(config, "personal_fingerprint_window_seconds", old_window_seconds) or old_window_seconds)
        )
        self._fingerprint_max_uses_per_window = int(
            max(1, getattr(config, "personal_fingerprint_max_uses_per_window", old_window_max_uses) or old_window_max_uses)
        )

        debug_logger.log_info(
            f"[BrowserCaptcha] Personal 配置已热更新: "
            f"max_tabs {old_max_tabs}->{self._max_resident_tabs}, "
            f"idle_ttl {old_idle_ttl}s->{self._idle_tab_ttl_seconds}s, "
            f"max_use_count {old_max_use_count}->{self._resident_max_use_count}, "
            f"fingerprint_cooldown {old_fingerprint_cooldown}s->{self._resident_fingerprint_cooldown_seconds}s, "
            f"runtime_expand {self._resident_runtime_expand_enabled}, "
            f"pool_restart_ratio {self._pool_restart_unhealthy_ratio_threshold}, "
            f"pool_restart_min_unhealthy {self._pool_restart_min_unhealthy_slots}, "
            f"pool_restart_cooldown {self._pool_restart_cooldown_seconds}s, "
            f"unhealthy_threshold {old_unhealthy_threshold}->{self._resident_unhealthy_health_threshold}, "
            f"rebuild_health_threshold {old_rebuild_health_threshold}->{self._resident_rebuild_health_threshold}, "
            f"slot_wait_timeout {old_slot_wait_timeout}s->{self._slot_wait_timeout_seconds}s, "
            f"window_seconds {old_window_seconds}s->{self._fingerprint_window_seconds}s, "
            f"window_max_uses {old_window_max_uses}->{self._fingerprint_max_uses_per_window}"
        )

    def _check_available(self):
        """检查服务是否可用"""
        if DOCKER_HEADED_BLOCKED:
            raise RuntimeError(
                "检测到 Docker 环境，默认禁用内置浏览器打码。"
                "如需启用请设置环境变量 ALLOW_DOCKER_HEADED_CAPTCHA=true，并提供 DISPLAY/Xvfb。"
            )
        if IS_DOCKER and not os.environ.get("DISPLAY"):
            raise RuntimeError(
                "Docker 内置浏览器打码已启用，但 DISPLAY 未设置。"
                "请设置 DISPLAY（例如 :99）并启动 Xvfb。"
            )
        if not NODRIVER_AVAILABLE or uc is None:
            raise RuntimeError(
                "nodriver 未安装或不可用。"
                "请手动安装: pip install nodriver"
            )

    async def _run_with_timeout(self, awaitable, timeout_seconds: float, label: str):
        """统一收口 nodriver 操作超时，避免单次卡死拖住整条请求链路。"""
        effective_timeout = max(0.5, float(timeout_seconds or 0))
        try:
            return await asyncio.wait_for(awaitable, timeout=effective_timeout)
        except asyncio.TimeoutError as e:
            raise TimeoutError(f"{label} 超时 ({effective_timeout:.1f}s)") from e

    async def _tab_evaluate(self, tab, script: str, label: str, timeout_seconds: Optional[float] = None):
        return await self._run_with_timeout(
            tab.evaluate(script),
            timeout_seconds or self._command_timeout_seconds,
            label,
        )

    async def _tab_get(self, tab, url: str, label: str, timeout_seconds: Optional[float] = None):
        return await self._run_with_timeout(
            tab.get(url),
            timeout_seconds or self._navigation_timeout_seconds,
            label,
        )

    async def _browser_get(self, url: str, label: str, new_tab: bool = False, timeout_seconds: Optional[float] = None):
        await self._await_browser_ready(timeout_seconds=max(5.0, timeout_seconds or self._navigation_timeout_seconds))
        try:
            return await self._run_with_timeout(
                self.browser.get(url, new_tab=new_tab),
                timeout_seconds or self._navigation_timeout_seconds,
                label,
            )
        except Exception as e:
            if not self._is_no_browser_open_error(e):
                raise
            debug_logger.log_warning(
                f"[BrowserCaptcha] browser.get failed with browser-down error, recover and retry once: "
                f"pool={self._pool_key}, label={label}, new_tab={new_tab}, error={e}"
            )
            recovered = await self._recover_browser_runtime_after_tab_failure(
                reason=str(e),
                project_id=None,
                token_id=None,
            )
            if not recovered:
                raise
            await self._await_browser_ready(timeout_seconds=max(5.0, timeout_seconds or self._navigation_timeout_seconds))
            return await self._run_with_timeout(
                self.browser.get(url, new_tab=new_tab),
                timeout_seconds or self._navigation_timeout_seconds,
                f"{label}:after_recover",
            )

    async def _tab_reload(self, tab, label: str, timeout_seconds: Optional[float] = None):
        return await self._run_with_timeout(
            tab.reload(),
            timeout_seconds or self._navigation_timeout_seconds,
            label,
        )

    async def _get_browser_cookies(self, label: str, timeout_seconds: Optional[float] = None):
        await self._await_browser_ready(timeout_seconds=max(5.0, timeout_seconds or self._command_timeout_seconds))
        return await self._run_with_timeout(
            self.browser.cookies.get_all(),
            timeout_seconds or self._command_timeout_seconds,
            label,
        )

    async def _browser_send_command(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        label: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ):
        await self._await_browser_ready(timeout_seconds=max(5.0, timeout_seconds or self._command_timeout_seconds))
        return await self._run_with_timeout(
            self.browser.connection.send(method, params) if params else self.browser.connection.send(method),
            timeout_seconds or self._command_timeout_seconds,
            label or method,
        )

    async def _await_browser_ready(self, timeout_seconds: float = 10.0):
        effective_timeout = max(1.0, float(timeout_seconds or 10.0))
        if not self._browser_ready_event.is_set():
            await asyncio.wait_for(self._browser_ready_event.wait(), timeout=effective_timeout)
        if not self.browser or not self._initialized:
            raise RuntimeError("browser not initialized")
        try:
            if self.browser.stopped:
                raise RuntimeError("browser stopped")
        except Exception as e:
            raise RuntimeError(f"browser unavailable: {e}") from e

    def _is_no_browser_open_error(self, error: Exception) -> bool:
        message = str(error or "").lower()
        return "no browser is open" in message or "browser unavailable" in message

    def _is_recaptcha_not_ready_error(self, error: Optional[str]) -> bool:
        message = str(error or "").lower()
        return (
            "grecaptcha is not defined" in message
            or "grecaptcha is undefined" in message
            or "cannot read properties of undefined" in message
            or "execute is not a function" in message
            or "ready is not a function" in message
        )

    async def _recover_browser_runtime_after_tab_failure(
        self,
        *,
        reason: str,
        project_id: Optional[str] = None,
        token_id: Optional[int] = None,
    ) -> bool:
        debug_logger.log_warning(
            f"[BrowserCaptcha] browser runtime recovery start: pool={self._pool_key}, "
            f"project={project_id}, token_id={token_id}, reason={reason}"
        )
        try:
            async with self._browser_lock:
                await self._shutdown_browser_runtime_locked(reason=f"tab_failure:{reason}")
            await self.initialize()
            debug_logger.log_info(
                f"[BrowserCaptcha] browser runtime recovery success: pool={self._pool_key}, "
                f"project={project_id}, token_id={token_id}"
            )
            return True
        except Exception as e:
            debug_logger.log_error(
                f"[BrowserCaptcha] browser runtime recovery failed: pool={self._pool_key}, "
                f"project={project_id}, token_id={token_id}, error={e}"
            )
            return False

    async def _probe_browser_ready_after_start(self, browser_instance, timeout_seconds: float = 10.0):
        deadline = time.time() + max(1.0, float(timeout_seconds or 10.0))
        last_error: Optional[Exception] = None

        while time.time() < deadline:
            if browser_instance is not self.browser:
                raise RuntimeError("browser instance replaced during startup")
            try:
                if getattr(browser_instance, "stopped", False):
                    raise RuntimeError("browser stopped during startup")
                connection = getattr(browser_instance, "connection", None)
                if connection is None:
                    raise RuntimeError("browser connection missing during startup")
                try:
                    tabs = list(getattr(browser_instance, "tabs", []) or [])
                except TypeError:
                    tabs = []
                if tabs:
                    await asyncio.sleep(0.2)
                    return
                # 某些 nodriver/Chrome 组合下，浏览器已可用但 tabs 列表会稍后才填充。
                # 这里不要把“没有 seed tab”当成启动失败，否则会直接导致整池拿不到 token。
                await asyncio.sleep(0.35)
                return
            except Exception as e:
                last_error = e
            await asyncio.sleep(0.25)

        raise RuntimeError(
            "browser ready probe timed out"
            + (f": {last_error}" if last_error else " (no seed tab)")
        )

    async def _probe_browser_ready_after_start(self, browser_instance, timeout_seconds: float = 10.0):
        deadline = time.time() + max(1.0, float(timeout_seconds or 10.0))
        last_error: Optional[Exception] = None

        while time.time() < deadline:
            if browser_instance is not self.browser:
                raise RuntimeError("browser instance replaced during startup")
            try:
                if getattr(browser_instance, "stopped", False):
                    raise RuntimeError("browser stopped during startup")
                connection = getattr(browser_instance, "connection", None)
                if connection is None:
                    raise RuntimeError("browser connection missing during startup")
                try:
                    tabs = list(getattr(browser_instance, "tabs", []) or [])
                except TypeError:
                    tabs = []
                if tabs:
                    await asyncio.sleep(0.2)
                    return
                await asyncio.sleep(0.35)
                return
            except Exception as e:
                last_error = e
            await asyncio.sleep(0.25)

        raise RuntimeError(
            "browser ready probe timed out"
            + (f": {last_error}" if last_error else " (no seed tab)")
        )

    async def _idle_tab_reaper_loop(self):
        """空闲标签页回收循环"""
        while True:
            try:
                await asyncio.sleep(30)  # 每30秒检查一次
                current_time = time.time()
                tabs_to_close = []

                async with self._resident_lock:
                    for slot_id, resident_info in list(self._resident_tabs.items()):
                        if resident_info.solve_lock.locked():
                            continue
                        idle_seconds = current_time - resident_info.last_used_at
                        if idle_seconds >= self._idle_tab_ttl_seconds:
                            tabs_to_close.append(slot_id)
                            debug_logger.log_info(
                                f"[BrowserCaptcha] slot={slot_id} 空闲 {idle_seconds:.0f}s，准备回收"
                            )

                for slot_id in tabs_to_close:
                    await self._close_resident_tab(slot_id)

            except asyncio.CancelledError:
                return
            except Exception as e:
                debug_logger.log_warning(f"[BrowserCaptcha] 空闲标签页回收异常: {e}")

    async def _evict_lru_tab_if_needed(self) -> bool:
        """如果达到共享池上限，使用 LRU 策略淘汰最久未使用的空闲标签页。"""
        async with self._resident_lock:
            if len(self._resident_tabs) < self._max_resident_tabs:
                return True

            lru_slot_id = None
            lru_project_hint = None
            lru_last_used = float('inf')

            for slot_id, resident_info in self._resident_tabs.items():
                if resident_info.solve_lock.locked():
                    continue
                if resident_info.last_used_at < lru_last_used:
                    lru_last_used = resident_info.last_used_at
                    lru_slot_id = slot_id
                    lru_project_hint = resident_info.project_id

        if lru_slot_id:
            debug_logger.log_info(
                f"[BrowserCaptcha] 标签页数量达到上限({self._max_resident_tabs})，"
                f"淘汰最久未使用的 slot={lru_slot_id}, project_hint={lru_project_hint}"
            )
            await self._close_resident_tab(lru_slot_id)
            return True

        debug_logger.log_warning(
            f"[BrowserCaptcha] 标签页数量达到上限({self._max_resident_tabs})，"
            "但当前没有可安全淘汰的空闲标签页"
        )
        return False

    async def _get_reserved_tab_ids(self) -> set[int]:
        """收集当前被 resident/custom 池占用的标签页，legacy 模式不得复用。"""
        reserved_tab_ids: set[int] = set()

        async with self._resident_lock:
            for resident_info in self._resident_tabs.values():
                if resident_info and resident_info.tab:
                    reserved_tab_ids.add(id(resident_info.tab))

        async with self._custom_lock:
            for item in self._custom_tabs.values():
                tab = item.get("tab") if isinstance(item, dict) else None
                if tab:
                    reserved_tab_ids.add(id(tab))

        return reserved_tab_ids

    def _next_resident_slot_id(self) -> str:
        self._resident_slot_seq += 1
        return f"slot-{self._resident_slot_seq}"

    def _forget_project_affinity_for_slot_locked(self, slot_id: Optional[str]):
        if not slot_id:
            return
        stale_projects = [
            project_id
            for project_id, mapped_slot_id in self._project_resident_affinity.items()
            if mapped_slot_id == slot_id
        ]
        for project_id in stale_projects:
            self._project_resident_affinity.pop(project_id, None)
            mapped_pool_key = self.__class__._project_pool_keys.get(project_id)
            if mapped_pool_key == self._pool_key:
                self.__class__._project_pool_keys.pop(project_id, None)

    def _resolve_affinity_slot_locked(self, project_id: Optional[str]) -> Optional[str]:
        normalized_project_id = str(project_id or "").strip()
        if not normalized_project_id:
            return None
        slot_id = self._project_resident_affinity.get(normalized_project_id)
        if slot_id and slot_id in self._resident_tabs:
            return slot_id
        if slot_id:
            self._project_resident_affinity.pop(normalized_project_id, None)
        return None

    def _assign_slot_to_token_locked(
        self,
        resident_info: Optional[ResidentTabInfo],
        token_id: Optional[int],
    ) -> None:
        if resident_info is None or not token_id:
            return
        resident_info.token_id = int(token_id)

    def _get_token_scoped_candidates_locked(
        self,
        token_id: Optional[int],
    ) -> list[tuple[str, ResidentTabInfo]]:
        candidates = [
            (slot_id, resident_info)
            for slot_id, resident_info in self._resident_tabs.items()
            if resident_info and resident_info.tab
        ]
        if not token_id:
            return candidates

        owned_candidates = [
            (slot_id, resident_info)
            for slot_id, resident_info in candidates
            if resident_info.token_id == token_id
        ]
        if owned_candidates:
            return owned_candidates

        unassigned_candidates = [
            (slot_id, resident_info)
            for slot_id, resident_info in candidates
            if resident_info.token_id is None
        ]
        if unassigned_candidates:
            return unassigned_candidates

        return []

    def _count_token_slots_locked(self, token_id: Optional[int]) -> int:
        if not token_id:
            return len(self._resident_tabs)
        return sum(1 for resident_info in self._resident_tabs.values() if resident_info and resident_info.token_id == token_id)

    def _remember_project_affinity(self, project_id: Optional[str], slot_id: Optional[str], resident_info: Optional[ResidentTabInfo]):
        normalized_project_id = str(project_id or "").strip()
        if not normalized_project_id or not slot_id or resident_info is None:
            return
        self._project_resident_affinity[normalized_project_id] = slot_id
        resident_info.project_id = normalized_project_id
        self.__class__._project_pool_keys[normalized_project_id] = self._pool_key

    def _is_resident_slot_rotation_due(
        self,
        resident_info: Optional[ResidentTabInfo],
    ) -> bool:
        if resident_info is None:
            return False
        return resident_info.use_count >= self._resident_max_use_count

    def _is_resident_slot_selection_blocked(
        self,
        slot_id: Optional[str],
        resident_info: Optional[ResidentTabInfo],
    ) -> bool:
        if resident_info is None:
            return False
        if self._is_resident_slot_rotation_due(resident_info):
            return True
        if resident_info.health_score <= self._resident_unhealthy_health_threshold:
            return True
        if slot_id and self._resident_error_streaks.get(slot_id, 0) >= self._flow_recover_threshold:
            return True
        return False

    def _should_rebuild_resident_slot(
        self,
        slot_id: Optional[str],
        resident_info: Optional[ResidentTabInfo],
    ) -> bool:
        if resident_info is None:
            return False
        if self._is_resident_slot_rotation_due(resident_info):
            return True
        if resident_info.health_score <= self._resident_rebuild_health_threshold:
            return True
        if slot_id and self._resident_error_streaks.get(slot_id, 0) >= self._flow_recover_threshold:
            return True
        return False

    def _can_create_runtime_resident_tab(self) -> bool:
        if self._resident_runtime_expand_enabled:
            return True
        return len(self._resident_tabs) == 0

    def _should_restart_pool_locked(self, snapshot: Optional[Dict[str, int]]) -> bool:
        if not snapshot:
            return False
        total = int(snapshot.get("total", 0) or 0)
        unhealthy = int(snapshot.get("unhealthy", 0) or 0)
        if total < self._pool_restart_min_unhealthy_slots:
            return False
        if unhealthy < self._pool_restart_min_unhealthy_slots:
            return False
        if (unhealthy / max(1, total)) < self._pool_restart_unhealthy_ratio_threshold:
            return False
        if time.time() < self._pool_restart_cooldown_until:
            return False
        return True

    def _pick_forced_rebuild_candidate_locked(
        self,
        token_id: Optional[int],
    ) -> tuple[Optional[str], Optional[ResidentTabInfo]]:
        candidates = self._get_token_scoped_candidates_locked(token_id)
        blocked_candidates = [
            (slot_id, resident_info)
            for slot_id, resident_info in candidates
            if self._is_resident_slot_selection_blocked(slot_id, resident_info)
        ]
        if not blocked_candidates:
            blocked_candidates = [
                (slot_id, resident_info)
                for slot_id, resident_info in self._resident_tabs.items()
                if resident_info
                and resident_info.tab
                and self._is_resident_slot_selection_blocked(slot_id, resident_info)
            ]
        if not blocked_candidates:
            return None, None
        return min(
            blocked_candidates,
            key=lambda item: (
                item[1].health_score,
                -self._resident_error_streaks.get(item[0], 0),
                item[1].last_used_at,
                item[0],
            ),
        )

    def _is_resident_slot_cooling_down(
        self,
        resident_info: Optional[ResidentTabInfo],
    ) -> bool:
        if resident_info is None:
            return False
        now_value = time.time()
        if resident_info.cooldown_until > now_value:
            return True
        if self._resident_fingerprint_cooldown_seconds <= 0:
            return False
        return (now_value - resident_info.last_used_at) < self._resident_fingerprint_cooldown_seconds

    def _prune_slot_activity(self, resident_info: Optional[ResidentTabInfo], now_value: Optional[float] = None):
        if resident_info is None:
            return
        current_time = now_value or time.time()
        cutoff = current_time - self._fingerprint_window_seconds
        while resident_info.recent_token_timestamps and resident_info.recent_token_timestamps[0] < cutoff:
            resident_info.recent_token_timestamps.popleft()
        while resident_info.recent_upstream_success_timestamps and resident_info.recent_upstream_success_timestamps[0] < cutoff:
            resident_info.recent_upstream_success_timestamps.popleft()
        if resident_info.cooldown_until and resident_info.cooldown_until <= current_time:
            resident_info.cooldown_until = 0.0

    def _is_resident_slot_rate_limited(
        self,
        resident_info: Optional[ResidentTabInfo],
        *,
        now_value: Optional[float] = None,
    ) -> bool:
        if resident_info is None:
            return False
        current_time = now_value or time.time()
        self._prune_slot_activity(resident_info, current_time)
        if resident_info.cooldown_until > current_time:
            return True
        return len(resident_info.recent_token_timestamps) >= self._fingerprint_max_uses_per_window

    def _mark_slot_token_issued(self, resident_info: Optional[ResidentTabInfo]):
        if resident_info is None:
            return
        now_value = time.time()
        self._prune_slot_activity(resident_info, now_value)
        resident_info.last_used_at = now_value
        resident_info.last_token_at = now_value
        resident_info.recent_token_timestamps.append(now_value)
        if len(resident_info.recent_token_timestamps) >= self._fingerprint_max_uses_per_window:
            resident_info.cooldown_until = max(
                resident_info.cooldown_until,
                now_value + self._fingerprint_rate_limit_cooldown_seconds,
            )

    def _mark_slot_upstream_success(self, resident_info: Optional[ResidentTabInfo]):
        if resident_info is None:
            return
        now_value = time.time()
        self._prune_slot_activity(resident_info, now_value)
        resident_info.upstream_success_count += 1
        resident_info.last_upstream_success_at = now_value
        resident_info.recent_upstream_success_timestamps.append(now_value)
        resident_info.health_score = min(20, resident_info.health_score + 2)

    def _mark_slot_upstream_error(self, resident_info: Optional[ResidentTabInfo]):
        if resident_info is None:
            return
        now_value = time.time()
        self._prune_slot_activity(resident_info, now_value)
        resident_info.upstream_error_count += 1
        resident_info.health_score = max(-20, resident_info.health_score - 3)
        resident_info.cooldown_until = max(
            resident_info.cooldown_until,
            now_value + min(30.0, max(3.0, self._fingerprint_rate_limit_cooldown_seconds / 2)),
        )

    def _resident_slot_priority_locked(
        self,
        item: tuple[str, ResidentTabInfo],
    ) -> tuple[int, int, float, float, str]:
        slot_id, resident_info = item
        now_value = time.time()
        self._prune_slot_activity(resident_info, now_value)
        return (
            resident_info.health_score,
            -len(resident_info.recent_token_timestamps),
            resident_info.cooldown_until if resident_info.cooldown_until > now_value else 0.0,
            resident_info.last_used_at,
            slot_id,
        )

    def _pick_resident_slot_round_robin_locked(
        self,
        pool: list[tuple[str, ResidentTabInfo]],
    ) -> tuple[Optional[str], Optional[ResidentTabInfo]]:
        if not pool:
            return None, None

        prioritized_pool = [
            (item, self._resident_slot_priority_locked(item))
            for item in pool
        ]
        ordered_pool = sorted(
            prioritized_pool,
            key=lambda entry: (
                -entry[1][0],
                entry[1][1],
                entry[1][2],
                entry[1][3],
                entry[0][0],
            ),
        )
        start_index = 0
        if self._resident_last_selected_order_key is not None:
            for index, (item, _priority) in enumerate(ordered_pool):
                slot_id, resident_info = item
                if (resident_info.created_at, slot_id) > self._resident_last_selected_order_key:
                    start_index = index
                    break

        selected = ordered_pool[start_index][0]
        self._resident_last_selected_order_key = (selected[1].created_at, selected[0])
        return selected

    def _get_resident_pool_snapshot_locked(self) -> Dict[str, int]:
        total = len(self._resident_tabs)
        ready_idle = 0
        ready_busy = 0
        cooling = 0
        rate_limited = 0
        unhealthy = 0
        cold_idle = 0
        rotating = 0

        for slot_id, resident_info in self._resident_tabs.items():
            if resident_info is None or not resident_info.tab:
                continue
            if self._is_resident_slot_rotation_due(resident_info):
                rotating += 1
            if self._is_resident_slot_selection_blocked(slot_id, resident_info):
                unhealthy += 1
            if self._is_resident_slot_cooling_down(resident_info):
                cooling += 1
            if self._is_resident_slot_rate_limited(resident_info):
                rate_limited += 1
            if resident_info.recaptcha_ready and not resident_info.solve_lock.locked():
                ready_idle += 1
            elif resident_info.recaptcha_ready and resident_info.solve_lock.locked():
                ready_busy += 1
            elif not resident_info.solve_lock.locked():
                cold_idle += 1

        return {
            "total": total,
            "ready_idle": ready_idle,
            "ready_busy": ready_busy,
            "cooling": cooling,
            "rate_limited": rate_limited,
            "unhealthy": unhealthy,
            "cold_idle": cold_idle,
            "rotating": rotating,
            "capacity_left": max(0, self._max_resident_tabs - total),
        }

    def _resolve_resident_slot_for_project_locked(
        self,
        project_id: Optional[str] = None,
        token_id: Optional[int] = None,
    ) -> tuple[Optional[str], Optional[ResidentTabInfo]]:
        """优先走最近映射；没有映射时退化到共享池全局挑选。"""
        slot_id = self._resolve_affinity_slot_locked(project_id)
        if slot_id:
            resident_info = self._resident_tabs.get(slot_id)
            if resident_info and resident_info.tab:
                if self._is_resident_slot_selection_blocked(slot_id, resident_info):
                    return None, None
                if not token_id or resident_info.token_id in (None, token_id):
                    return slot_id, resident_info
                return None, None
        return self._select_resident_slot_locked(project_id, token_id=token_id)

    def _select_resident_slot_locked(
        self,
        project_id: Optional[str] = None,
        token_id: Optional[int] = None,
        *,
        allow_busy: bool = True,
    ) -> tuple[Optional[str], Optional[ResidentTabInfo]]:
        candidates = self._get_token_scoped_candidates_locked(token_id)
        if not candidates:
            return None, None

        # 共享打码池不再按 project_id 绑定；这里只根据“是否就绪 / 是否空闲 / 使用历史”
        # 做全局选择，避免 4 token/4 project 时把请求硬绑定到固定 tab。
        fresh_candidates = [
            (slot_id, resident_info)
            for slot_id, resident_info in candidates
            if not self._is_resident_slot_selection_blocked(slot_id, resident_info)
        ]
        rate_limited_free_candidates = [
            (slot_id, resident_info)
            for slot_id, resident_info in fresh_candidates
            if not self._is_resident_slot_rate_limited(resident_info)
        ]
        cooldown_free_candidates = [
            (slot_id, resident_info)
            for slot_id, resident_info in rate_limited_free_candidates
            if not self._is_resident_slot_cooling_down(resident_info)
        ]
        effective_candidates = cooldown_free_candidates or rate_limited_free_candidates or fresh_candidates

        ready_idle = [
            (slot_id, resident_info)
            for slot_id, resident_info in effective_candidates
            if resident_info.recaptcha_ready and not resident_info.solve_lock.locked()
        ]
        ready_busy = [
            (slot_id, resident_info)
            for slot_id, resident_info in effective_candidates
            if resident_info.recaptcha_ready and resident_info.solve_lock.locked()
        ]
        cold_idle = [
            (slot_id, resident_info)
            for slot_id, resident_info in effective_candidates
            if not resident_info.recaptcha_ready and not resident_info.solve_lock.locked()
        ]
        ready_busy = [
            (slot_id, resident_info)
            for slot_id, resident_info in effective_candidates
            if resident_info.recaptcha_ready and resident_info.solve_lock.locked()
        ]
        cold_busy = [
            (slot_id, resident_info)
            for slot_id, resident_info in effective_candidates
            if not resident_info.recaptcha_ready and resident_info.solve_lock.locked()
        ]

        pool = ready_idle or cold_idle
        if not pool and allow_busy:
            pool = ready_busy or cold_busy
        if not pool:
            return None, None
        return self._pick_resident_slot_round_robin_locked(pool)

    async def _ensure_resident_tab(
        self,
        project_id: Optional[str] = None,
        token_id: Optional[int] = None,
        *,
        force_create: bool = False,
        return_slot_key: bool = False,
    ):
        """确保共享打码标签页池中有可用 tab。

        逻辑：
        - 优先复用空闲 tab
        - 如果所有 tab 都忙且未到上限，继续扩容
        - 到达上限后允许请求排队等待已有 tab
        """
        def wrap(slot_id: Optional[str], resident_info: Optional[ResidentTabInfo]):
            if return_slot_key:
                return slot_id, resident_info
            return resident_info

        rebuild_slot_id: Optional[str] = None
        rebuild_token_id: Optional[int] = None

        async with self._resident_lock:
            token_candidates = self._get_token_scoped_candidates_locked(token_id)
            healthy_candidates = [
                (candidate_slot_id, info)
                for candidate_slot_id, info in token_candidates
                if not self._is_resident_slot_selection_blocked(candidate_slot_id, info)
            ]
            slot_id, resident_info = self._select_resident_slot_locked(project_id, token_id=token_id, allow_busy=False)
            if healthy_candidates:
                all_busy = all(info.solve_lock.locked() for _, info in healthy_candidates)
            else:
                all_busy = True

            can_runtime_create = self._can_create_runtime_resident_tab()
            should_create = force_create or (
                can_runtime_create and (not resident_info or (all_busy and len(self._resident_tabs) < self._max_resident_tabs))
            )
            if not should_create:
                if resident_info is None and len(self._resident_tabs) >= self._max_resident_tabs:
                    rebuild_slot_id, rebuild_info = self._pick_forced_rebuild_candidate_locked(token_id)
                    if rebuild_slot_id and rebuild_info:
                        rebuild_token_id = rebuild_info.token_id or token_id
                    else:
                        return wrap(slot_id, resident_info)
                else:
                    self._assign_slot_to_token_locked(resident_info, token_id)
                    return wrap(slot_id, resident_info)

            if rebuild_slot_id:
                debug_logger.log_warning(
                    f"[BrowserCaptcha] pool={self._pool_key}, project_id={project_id}, slot={rebuild_slot_id} "
                    "pool saturated with unhealthy tabs, forcing in-place rebuild while keeping affinity"
                )
                rebuilt_slot_id, rebuilt_info = await self._rebuild_resident_tab(
                    project_id,
                    token_id=rebuild_token_id,
                    slot_id=rebuild_slot_id,
                    return_slot_key=True,
                )
                if rebuilt_info is not None:
                    return wrap(rebuilt_slot_id, rebuilt_info)
                return wrap(None, None)

            if len(self._resident_tabs) >= self._max_resident_tabs:
                rebuild_slot_id, rebuild_info = self._pick_forced_rebuild_candidate_locked(token_id)
                if rebuild_slot_id and rebuild_info:
                    rebuild_token_id = rebuild_info.token_id or token_id
                else:
                    return wrap(slot_id, resident_info)

        if rebuild_slot_id:
            debug_logger.log_warning(
                f"[BrowserCaptcha] pool={self._pool_key}, project_id={project_id}, slot={rebuild_slot_id} "
                "pool saturated with unhealthy tabs, forcing in-place rebuild while keeping affinity"
            )
            rebuilt_slot_id, rebuilt_info = await self._rebuild_resident_tab(
                project_id,
                token_id=rebuild_token_id,
                slot_id=rebuild_slot_id,
                return_slot_key=True,
            )
            if rebuilt_info is not None:
                return wrap(rebuilt_slot_id, rebuilt_info)
            return wrap(None, None)

        async with self._tab_build_semaphore:
            async with self._resident_lock:
                token_candidates = self._get_token_scoped_candidates_locked(token_id)
                healthy_candidates = [
                    (candidate_slot_id, info)
                    for candidate_slot_id, info in token_candidates
                    if not self._is_resident_slot_selection_blocked(candidate_slot_id, info)
                ]
                slot_id, resident_info = self._select_resident_slot_locked(project_id, token_id=token_id, allow_busy=False)
                if healthy_candidates:
                    all_busy = all(info.solve_lock.locked() for _, info in healthy_candidates)
                else:
                    all_busy = True

                can_runtime_create = self._can_create_runtime_resident_tab()
                should_create = force_create or (
                    can_runtime_create and (not resident_info or (all_busy and len(self._resident_tabs) < self._max_resident_tabs))
                )
                if not should_create:
                    if resident_info is None and len(self._resident_tabs) >= self._max_resident_tabs:
                        rebuild_slot_id, rebuild_info = self._pick_forced_rebuild_candidate_locked(token_id)
                        if rebuild_slot_id and rebuild_info:
                            rebuild_token_id = rebuild_info.token_id or token_id
                        else:
                            return wrap(slot_id, resident_info)
                    else:
                        self._assign_slot_to_token_locked(resident_info, token_id)
                        return wrap(slot_id, resident_info)

                if len(self._resident_tabs) >= self._max_resident_tabs:
                    rebuild_slot_id, rebuild_info = self._pick_forced_rebuild_candidate_locked(token_id)
                    if rebuild_slot_id and rebuild_info:
                        rebuild_token_id = rebuild_info.token_id or token_id
                    else:
                        return wrap(slot_id, resident_info)

                new_slot_id = self._next_resident_slot_id()

            if rebuild_slot_id:
                debug_logger.log_warning(
                    f"[BrowserCaptcha] pool={self._pool_key}, project_id={project_id}, slot={rebuild_slot_id} "
                    "pool saturated with unhealthy tabs, forcing in-place rebuild while keeping affinity"
                )
                rebuilt_slot_id, rebuilt_info = await self._rebuild_resident_tab(
                    project_id,
                    token_id=rebuild_token_id,
                    slot_id=rebuild_slot_id,
                    return_slot_key=True,
                )
                if rebuilt_info is not None:
                    return wrap(rebuilt_slot_id, rebuilt_info)
                return wrap(None, None)

            resident_info = await self._create_resident_tab(new_slot_id, project_id=project_id, token_id=token_id)
            if resident_info is None:
                async with self._resident_lock:
                    slot_id, fallback_info = self._select_resident_slot_locked(project_id, token_id=token_id)
                    self._assign_slot_to_token_locked(fallback_info, token_id)
                return wrap(slot_id, fallback_info)

            async with self._resident_lock:
                self._assign_slot_to_token_locked(resident_info, token_id)
                self._resident_tabs[new_slot_id] = resident_info
                self._sync_compat_resident_state()
                return wrap(new_slot_id, resident_info)

    async def _rebuild_resident_tab(
        self,
        project_id: Optional[str] = None,
        token_id: Optional[int] = None,
        *,
        slot_id: Optional[str] = None,
        return_slot_key: bool = False,
    ):
        """重建共享池中的一个标签页。优先重建当前项目最近使用的 slot。"""
        def wrap(actual_slot_id: Optional[str], resident_info: Optional[ResidentTabInfo]):
            if return_slot_key:
                return actual_slot_id, resident_info
            return resident_info

        async with self._tab_build_semaphore:
            async with self._resident_lock:
                actual_slot_id = slot_id
                if actual_slot_id is None:
                    actual_slot_id, _ = self._resolve_resident_slot_for_project_locked(project_id, token_id=token_id)

                old_resident = self._resident_tabs.pop(actual_slot_id, None) if actual_slot_id else None
                self._forget_project_affinity_for_slot_locked(actual_slot_id)
                if actual_slot_id:
                    self._resident_error_streaks.pop(actual_slot_id, None)
                self._sync_compat_resident_state()

            if old_resident:
                try:
                    async with old_resident.solve_lock:
                        await self._close_tab_quietly(old_resident.tab)
                except Exception:
                    await self._close_tab_quietly(old_resident.tab)

            actual_slot_id = actual_slot_id or self._next_resident_slot_id()
            effective_token_id = token_id or (old_resident.token_id if old_resident else None)
            resident_info = await self._create_resident_tab(
                actual_slot_id,
                project_id=project_id,
                token_id=effective_token_id,
            )
            if resident_info is None:
                debug_logger.log_warning(
                    f"[BrowserCaptcha] slot={actual_slot_id}, project_id={project_id} 重建共享标签页失败"
                )
                return wrap(actual_slot_id, None)

            async with self._resident_lock:
                self._assign_slot_to_token_locked(resident_info, effective_token_id)
                self._resident_tabs[actual_slot_id] = resident_info
                self._remember_project_affinity(project_id, actual_slot_id, resident_info)
                self._sync_compat_resident_state()
                return wrap(actual_slot_id, resident_info)

    async def _acquire_resident_slot_for_solve(
        self,
        project_id: Optional[str],
        token_id: Optional[int] = None,
    ) -> tuple[Optional[str], Optional[ResidentTabInfo]]:
        deadline = time.time() + self._slot_wait_timeout_seconds
        last_busy_slot_id: Optional[str] = None

        while time.time() < deadline:
            slot_id, resident_info = await self._ensure_resident_tab(project_id, token_id=token_id, return_slot_key=True)
            if resident_info is None or not slot_id:
                return None, None

            if resident_info.recaptcha_ready and not resident_info.solve_lock.locked():
                try:
                    await asyncio.wait_for(resident_info.solve_lock.acquire(), timeout=0.2)
                    self._assign_slot_to_token_locked(resident_info, token_id)
                    return slot_id, resident_info
                except asyncio.TimeoutError:
                    last_busy_slot_id = slot_id
            else:
                last_busy_slot_id = slot_id

            async with self._resident_lock:
                pool_snapshot = self._get_resident_pool_snapshot_locked()
                can_expand = len(self._resident_tabs) < self._max_resident_tabs

            if can_expand and self._resident_runtime_expand_enabled:
                await self._ensure_resident_tab(project_id, token_id=token_id, force_create=True, return_slot_key=True)

            await asyncio.sleep(random.uniform(0.15, 0.35))

        async with self._resident_lock:
            fallback_slot_id, fallback_resident_info = self._select_resident_slot_locked(
                project_id,
                token_id=token_id,
                allow_busy=True,
            )
            self._assign_slot_to_token_locked(fallback_resident_info, token_id)
            pool_snapshot = self._get_resident_pool_snapshot_locked()

        if fallback_resident_info is None or not fallback_slot_id:
            return None, None

        debug_logger.log_warning(
            "[BrowserCaptcha] resident slot queue timeout, waiting for busy slot: "
            f"project={project_id}, preferred_slot={last_busy_slot_id}, selected_slot={fallback_slot_id}, "
            f"pool={pool_snapshot}, wait_timeout={self._slot_wait_timeout_seconds:.1f}s"
        )
        await asyncio.wait_for(
            fallback_resident_info.solve_lock.acquire(),
            timeout=max(1.0, min(3.0, self._slot_wait_timeout_seconds / 2)),
        )
        return fallback_slot_id, fallback_resident_info

    async def _enter_queue_gate(self):
        await asyncio.wait_for(
            self._queue_semaphore.acquire(),
            timeout=self._queue_acquire_timeout_seconds,
        )

    def _leave_queue_gate(self):
        try:
            self._queue_semaphore.release()
        except Exception:
            pass

    def _schedule_standby_fill(self):
        if self._standby_target_count <= 0:
            return
        if self._standby_fill_task and not self._standby_fill_task.done():
            return
        self._standby_fill_task = asyncio.create_task(self._ensure_standby_capacity())

    async def _ensure_standby_capacity(self):
        try:
            await self.initialize()
            for _ in range(self._standby_target_count + 1):
                async with self._resident_lock:
                    snapshot = self._get_resident_pool_snapshot_locked()
                    ready_spares = max(0, snapshot["ready_idle"] - 1)
                    can_expand = len(self._resident_tabs) < self._max_resident_tabs
                if ready_spares >= self._standby_target_count or not can_expand:
                    return
                await self._ensure_resident_tab(None, force_create=True, return_slot_key=True)
        except Exception as e:
            debug_logger.log_warning(f"[BrowserCaptcha] standby fill failed: {e}")

    def _sync_compat_resident_state(self):
        """同步旧版单 resident 兼容属性。"""
        first_resident = next(iter(self._resident_tabs.values()), None)
        if first_resident:
            self.resident_project_id = first_resident.project_id
            self.resident_tab = first_resident.tab
            self._running = True
            self._recaptcha_ready = bool(first_resident.recaptcha_ready)
        else:
            self.resident_project_id = None
            self.resident_tab = None
            self._running = False
            self._recaptcha_ready = False

    async def _close_tab_quietly(self, tab):
        if not tab:
            return
        self._clear_tab_fingerprint_profile(tab)
        try:
            await self._run_with_timeout(
                tab.close(),
                timeout_seconds=5.0,
                label="tab.close",
            )
        except Exception:
            pass

    async def _stop_browser_process(self, browser_instance):
        """兼容 nodriver 同步 stop API，安全停止浏览器进程。"""
        if not browser_instance:
            return
        stop_method = getattr(browser_instance, "stop", None)
        if stop_method is None:
            return
        result = stop_method()
        if inspect.isawaitable(result):
            await self._run_with_timeout(
                result,
                timeout_seconds=10.0,
                label="browser.stop",
            )

    async def _shutdown_browser_runtime_locked(self, reason: str):
        """在持有 _browser_lock 的前提下，彻底清理当前浏览器运行态。"""
        browser_instance = self.browser
        self.browser = None
        self._initialized = False
        self._browser_ready_event.clear()
        self._last_fingerprint = None
        self._tab_fingerprint_profiles.clear()
        self._cleanup_proxy_extension()
        self._proxy_url = None
        self._project_flow_error_streaks.clear()

        async with self._resident_lock:
            resident_items = list(self._resident_tabs.values())
            stale_projects = list(self._project_resident_affinity.keys())
            self._resident_tabs.clear()
            self._project_resident_affinity.clear()
            self._resident_error_streaks.clear()
            self._sync_compat_resident_state()
        for project_id in stale_projects:
            if self.__class__._project_pool_keys.get(project_id) == self._pool_key:
                self.__class__._project_pool_keys.pop(project_id, None)

        custom_items = list(self._custom_tabs.values())
        self._custom_tabs.clear()

        closed_tabs = set()

        async def close_once(tab):
            if not tab:
                return
            tab_key = id(tab)
            if tab_key in closed_tabs:
                return
            closed_tabs.add(tab_key)
            await self._close_tab_quietly(tab)

        for resident_info in resident_items:
            await close_once(resident_info.tab)

        for item in custom_items:
            tab = item.get("tab") if isinstance(item, dict) else None
            await close_once(tab)

        if browser_instance:
            try:
                await self._stop_browser_process(browser_instance)
            except Exception as e:
                debug_logger.log_warning(
                    f"[BrowserCaptcha] 停止浏览器实例失败 ({reason}): {e}"
                )

    async def _resolve_personal_proxy(self):
        """Read proxy config for personal captcha browser.
        Priority: captcha browser_proxy > request proxy."""
        if self._proxy_url_override:
            debug_logger.log_info(f"[BrowserCaptcha] Personal 使用池级固定代理: {self._proxy_url_override}")
            return _parse_proxy_url(self._proxy_url_override)
        if not self.db:
            return None, None, None, None, None
        try:
            captcha_cfg = await self.db.get_captcha_config()
            if captcha_cfg.browser_proxy_enabled and captcha_cfg.browser_proxy_url:
                url = captcha_cfg.browser_proxy_url.strip()
                if url:
                    debug_logger.log_info(f"[BrowserCaptcha] Personal 使用验证码代理: {url}")
                    return _parse_proxy_url(url)
        except Exception as e:
            debug_logger.log_warning(f"[BrowserCaptcha] 读取验证码代理配置失败: {e}")
        try:
            proxy_cfg = await self.db.get_proxy_config()
            if proxy_cfg and proxy_cfg.enabled and proxy_cfg.proxy_url:
                url = proxy_cfg.proxy_url.strip()
                if url:
                    debug_logger.log_info(f"[BrowserCaptcha] Personal 回退使用请求代理: {url}")
                    return _parse_proxy_url(url)
        except Exception as e:
            debug_logger.log_warning(f"[BrowserCaptcha] 读取请求代理配置失败: {e}")
        return None, None, None, None, None

    def _cleanup_proxy_extension(self):
        """Remove temporary proxy auth extension directory."""
        if self._proxy_ext_dir and os.path.isdir(self._proxy_ext_dir):
            try:
                shutil.rmtree(self._proxy_ext_dir, ignore_errors=True)
            except Exception:
                pass
            self._proxy_ext_dir = None

    async def initialize(self):
        """初始化 nodriver 浏览器"""
        self._check_available()

        async with self._browser_lock:
            browser_needs_restart = False
            browser_executable_path = None
            display_value = os.environ.get("DISPLAY", "").strip()
            browser_args = []

            if self._initialized and self.browser:
                try:
                    if self.browser.stopped:
                        debug_logger.log_warning("[BrowserCaptcha] 浏览器已停止，准备重新初始化...")
                        browser_needs_restart = True
                    else:
                        if not self._browser_ready_event.is_set():
                            await self._probe_browser_ready_after_start(self.browser, timeout_seconds=5.0)
                            self._browser_ready_event.set()
                        if self._idle_reaper_task is None or self._idle_reaper_task.done():
                            self._idle_reaper_task = asyncio.create_task(self._idle_tab_reaper_loop())
                        return
                except Exception as e:
                    debug_logger.log_warning(f"[BrowserCaptcha] 浏览器状态检查异常，准备重新初始化: {e}")
                    browser_needs_restart = True
            elif self.browser is not None or self._initialized:
                browser_needs_restart = True

            if browser_needs_restart:
                await self._shutdown_browser_runtime_locked(reason="initialize_recovery")

            try:
                self._browser_ready_event.clear()
                self._fingerprint_profile = self._build_fingerprint_profile()
                if self.user_data_dir:
                    debug_logger.log_info(f"[BrowserCaptcha] 正在启动 nodriver 浏览器 (用户数据目录: {self.user_data_dir})...")
                    os.makedirs(self.user_data_dir, exist_ok=True)
                else:
                    debug_logger.log_info(f"[BrowserCaptcha] 正在启动 nodriver 浏览器 (使用临时目录)...")

                browser_executable_path = os.environ.get("BROWSER_EXECUTABLE_PATH", "").strip() or None
                if browser_executable_path and not os.path.exists(browser_executable_path):
                    debug_logger.log_warning(
                        f"[BrowserCaptcha] 指定浏览器不存在，改为自动发现: {browser_executable_path}"
                    )
                    browser_executable_path = None
                if browser_executable_path:
                    debug_logger.log_info(
                        f"[BrowserCaptcha] 使用指定浏览器可执行文件: {browser_executable_path}"
                    )
                    try:
                        version_result = subprocess.run(
                            [browser_executable_path, "--version"],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        version_output = (
                            (version_result.stdout or "").strip()
                            or (version_result.stderr or "").strip()
                            or "<empty>"
                        )
                        debug_logger.log_info(
                            "[BrowserCaptcha] 浏览器版本探测: "
                            f"rc={version_result.returncode}, output={version_output[:200]}"
                        )
                    except Exception as version_error:
                        debug_logger.log_warning(
                            f"[BrowserCaptcha] 浏览器版本探测失败: {version_error}"
                        )

                # 解析代理配置
                self._cleanup_proxy_extension()
                self._proxy_url = None
                protocol, host, port, username, password = await self._resolve_personal_proxy()
                proxy_server_arg = None
                if protocol and host and port:
                    if username and password:
                        self._proxy_ext_dir = _create_proxy_auth_extension(protocol, host, port, username, password)
                        debug_logger.log_info(
                            f"[BrowserCaptcha] Personal 代理需要认证，已创建扩展: {self._proxy_ext_dir}"
                        )
                    proxy_server_arg = f"--proxy-server={protocol}://{host}:{port}"
                    self._proxy_url = f"{protocol}://{host}:{port}"
                    debug_logger.log_info(f"[BrowserCaptcha] Personal 浏览器代理: {self._proxy_url}")

                profile = self._fingerprint_profile
                viewport = profile.get("viewport") or {"width": 1280, "height": 720}
                window_position = profile.get("window_position") or {"x": 3000, "y": 3000}
                profile_lang = str(profile.get("lang") or "").strip() or "en-US"
                profile_user_agent = str(profile.get("user_agent") or "").strip()

                browser_args = [
                    '--disable-quic',
                    '--disable-features=UseDnsHttpsSvcb',
                    '--disable-dev-shm-usage',
                    '--disable-setuid-sandbox',
                    '--disable-gpu',
                    '--disable-infobars',
                    '--hide-scrollbars',
                    f"--window-size={int(viewport.get('width', 1280))},{int(viewport.get('height', 720))}",
                    f"--window-position={int(window_position.get('x', 3000))},{int(window_position.get('y', 3000))}",
                    '--profile-directory=Default',
                    '--disable-background-networking',
                    '--disable-sync',
                    '--disable-translate',
                    '--disable-default-apps',
                    '--no-first-run',
                    '--no-default-browser-check',
                    '--no-zygote',
                ]
                if proxy_server_arg:
                    browser_args.append(proxy_server_arg)
                if self._proxy_ext_dir:
                    browser_args.append(f'--load-extension={self._proxy_ext_dir}')
                else:
                    browser_args.append('--disable-extensions')

                effective_uid = "n/a"
                if hasattr(os, "geteuid"):
                    try:
                        effective_uid = str(os.geteuid())
                    except Exception:
                        effective_uid = "unknown"
                debug_logger.log_info(
                    "[BrowserCaptcha] nodriver 启动上下文: "
                    f"docker={IS_DOCKER}, display={display_value or '<empty>'}, "
                    f"uid={effective_uid}, headless={self.headless}, sandbox=False, "
                    f"profile_seed={profile.get('seed')}, "
                    f"profile_ua={profile_user_agent[:120] if profile_user_agent else '<empty>'}, "
                    f"profile_lang={profile_lang}, "
                    f"profile_viewport={viewport.get('width')}x{viewport.get('height')}, "
                    f"executable={browser_executable_path or '<auto>'}, "
                    f"args={' '.join(browser_args)}"
                )

                # 启动 nodriver 浏览器（后台启动，不占用前台）
                config = uc.Config(
                    headless=self.headless,
                    user_data_dir=self.user_data_dir,
                    browser_executable_path=browser_executable_path,
                    sandbox=False,
                    browser_args=browser_args,
                )
                self.browser = await self._run_with_timeout(
                    uc.start(config),
                    timeout_seconds=30.0,
                    label="nodriver.start",
                )
                await self._probe_browser_ready_after_start(self.browser, timeout_seconds=10.0)
                self._initialized = True
                self._browser_ready_event.set()
                if self._idle_reaper_task is None or self._idle_reaper_task.done():
                    self._idle_reaper_task = asyncio.create_task(self._idle_tab_reaper_loop())
                debug_logger.log_info(f"[BrowserCaptcha] ✅ nodriver 浏览器已启动 (Profile: {self.user_data_dir})")

            except Exception as e:
                self.browser = None
                self._initialized = False
                self._browser_ready_event.clear()
                traceback_text = traceback.format_exc()
                debug_logger.log_error(
                    "[BrowserCaptcha] nodriver.start traceback:\n"
                    f"{traceback_text}"
                )
                debug_logger.log_error(
                    "[BrowserCaptcha] ❌ 浏览器启动失败: "
                    f"{type(e).__name__}: {str(e)} | "
                    f"display={display_value or '<empty>'} | "
                    f"executable={browser_executable_path or '<auto>'} | "
                    f"args={' '.join(browser_args) if browser_args else '<none>'}"
                )
                raise

    async def warmup_resident_tabs(self, project_ids: Iterable[str], limit: Optional[int] = None) -> list[str]:
        """预热共享打码标签页池，减少首个请求的冷启动抖动。"""
        normalized_project_ids: list[str] = []
        seen_projects = set()
        for raw_project_id in project_ids:
            project_id = str(raw_project_id or "").strip()
            if not project_id or project_id in seen_projects:
                continue
            seen_projects.add(project_id)
            normalized_project_ids.append(project_id)

        await self.initialize()

        try:
            warm_limit = self._max_resident_tabs if limit is None else max(1, min(self._max_resident_tabs, int(limit)))
        except Exception:
            warm_limit = self._max_resident_tabs

        warmed_slots: list[str] = []
        for index in range(warm_limit):
            warm_project_id = normalized_project_ids[index] if index < len(normalized_project_ids) else f"warmup-{index + 1}"
            slot_id, resident_info = await self._ensure_resident_tab(
                warm_project_id,
                force_create=True,
                return_slot_key=True,
            )
            if resident_info and resident_info.tab and slot_id:
                if slot_id not in warmed_slots:
                    warmed_slots.append(slot_id)
                self._remember_project_affinity(warm_project_id, slot_id, resident_info)
                continue
            debug_logger.log_warning(f"[BrowserCaptcha] 预热共享标签页失败 (seed={warm_project_id})")

        self._schedule_standby_fill()
        return warmed_slots

    async def warmup_resident_tabs_for_tokens(
        self,
        token_projects: Iterable[tuple[int, str]],
        limit: Optional[int] = None,
    ) -> list[str]:
        """按 token 轮转预热常驻 tab，避免 tab 数被 token 数卡死。"""
        normalized_targets: list[tuple[int, str]] = []
        seen_targets = set()
        for raw_token_id, raw_project_id in token_projects:
            try:
                token_id = int(raw_token_id)
            except Exception:
                continue
            project_id = str(raw_project_id or "").strip()
            if token_id <= 0 or not project_id:
                continue
            dedupe_key = (token_id, project_id)
            if dedupe_key in seen_targets:
                continue
            seen_targets.add(dedupe_key)
            normalized_targets.append((token_id, project_id))

        if not normalized_targets:
            return []

        await self.initialize()

        try:
            warm_limit = self._max_resident_tabs if limit is None else max(1, min(self._max_resident_tabs, int(limit)))
        except Exception:
            warm_limit = self._max_resident_tabs

        warmed_slots: list[str] = []
        target_count = len(normalized_targets)
        for index in range(warm_limit):
            token_id, project_id = normalized_targets[index % target_count]
            slot_id, resident_info = await self._ensure_resident_tab(
                project_id,
                token_id=token_id,
                force_create=True,
                return_slot_key=True,
            )
            if resident_info and resident_info.tab and slot_id:
                self._assign_slot_to_token_locked(resident_info, token_id)
                if slot_id not in warmed_slots:
                    warmed_slots.append(slot_id)
                self._remember_project_affinity(project_id, slot_id, resident_info)
                continue
            debug_logger.log_warning(
                f"[BrowserCaptcha] 预热 token 常驻标签页失败 (pool={self._pool_key}, token_id={token_id}, seed={project_id})"
            )

        self._schedule_standby_fill()
        return warmed_slots

    # ========== 常驻模式 API ==========

    async def start_resident_mode(self, project_id: str):
        """启动常驻模式
        
        Args:
            project_id: 用于常驻的项目 ID
        """
        if not str(project_id or "").strip():
            debug_logger.log_warning("[BrowserCaptcha] 启动常驻模式失败：project_id 为空")
            return

        warmed_slots = await self.warmup_resident_tabs([project_id], limit=1)
        if warmed_slots:
            debug_logger.log_info(f"[BrowserCaptcha] ✅ 共享常驻打码池已启动 (seed_project: {project_id})")
            return

        debug_logger.log_error(f"[BrowserCaptcha] 常驻模式启动失败 (seed_project: {project_id})")

    async def stop_resident_mode(self, project_id: Optional[str] = None):
        """停止常驻模式
        
        Args:
            project_id: 指定 project_id 或 slot_id；如果为 None 则关闭所有常驻标签页
        """
        target_slot_id = None
        if project_id:
            async with self._resident_lock:
                target_slot_id = project_id if project_id in self._resident_tabs else self._resolve_affinity_slot_locked(project_id)

        if target_slot_id:
            await self._close_resident_tab(target_slot_id)
            self._resident_error_streaks.pop(target_slot_id, None)
            debug_logger.log_info(f"[BrowserCaptcha] 已关闭共享标签页 slot={target_slot_id} (request={project_id})")
            return

        async with self._resident_lock:
            slot_ids = list(self._resident_tabs.keys())
            resident_items = list(self._resident_tabs.values())
            self._resident_tabs.clear()
            self._project_resident_affinity.clear()
            self._resident_error_streaks.clear()
            self._sync_compat_resident_state()

        for resident_info in resident_items:
            if resident_info and resident_info.tab:
                await self._close_tab_quietly(resident_info.tab)
        debug_logger.log_info(f"[BrowserCaptcha] 已关闭所有共享常驻标签页 (共 {len(slot_ids)} 个)")

    async def _wait_for_document_ready(self, tab, retries: int = 30, interval_seconds: float = 1.0) -> bool:
        """等待页面文档加载完成。"""
        for _ in range(retries):
            try:
                ready_state = await self._tab_evaluate(
                    tab,
                    "document.readyState",
                    label="document.readyState",
                    timeout_seconds=2.0,
                )
                if ready_state == "complete":
                    return True
            except Exception:
                pass
            await asyncio.sleep(interval_seconds)
        return False

    def _is_server_side_flow_error(self, error_text: str) -> bool:
        error_lower = (error_text or "").lower()
        return any(keyword in error_lower for keyword in [
            "http error 500",
            "public_error",
            "internal error",
            "reason=internal",
            "reason: internal",
            "\"reason\":\"internal\"",
            "server error",
            "upstream error",
        ])

    async def _clear_tab_site_storage(self, tab) -> Dict[str, Any]:
        """清理当前站点的本地存储状态，但保留 cookies 登录态。"""
        result = await self._tab_evaluate(tab, """
            (async () => {
                const summary = {
                    local_storage_cleared: false,
                    session_storage_cleared: false,
                    cache_storage_deleted: [],
                    indexed_db_deleted: [],
                    indexed_db_errors: [],
                    service_worker_unregistered: 0,
                };

                try {
                    window.localStorage.clear();
                    summary.local_storage_cleared = true;
                } catch (e) {
                    summary.local_storage_error = String(e);
                }

                try {
                    window.sessionStorage.clear();
                    summary.session_storage_cleared = true;
                } catch (e) {
                    summary.session_storage_error = String(e);
                }

                try {
                    if (typeof caches !== 'undefined') {
                        const cacheKeys = await caches.keys();
                        for (const key of cacheKeys) {
                            const deleted = await caches.delete(key);
                            if (deleted) {
                                summary.cache_storage_deleted.push(key);
                            }
                        }
                    }
                } catch (e) {
                    summary.cache_storage_error = String(e);
                }

                try {
                    if (navigator.serviceWorker) {
                        const registrations = await navigator.serviceWorker.getRegistrations();
                        for (const registration of registrations) {
                            const ok = await registration.unregister();
                            if (ok) {
                                summary.service_worker_unregistered += 1;
                            }
                        }
                    }
                } catch (e) {
                    summary.service_worker_error = String(e);
                }

                try {
                    if (typeof indexedDB !== 'undefined' && typeof indexedDB.databases === 'function') {
                        const dbs = await indexedDB.databases();
                        const names = Array.from(new Set(
                            dbs
                                .map((item) => item && item.name)
                                .filter((name) => typeof name === 'string' && name)
                        ));
                        for (const name of names) {
                            try {
                                await new Promise((resolve) => {
                                    const request = indexedDB.deleteDatabase(name);
                                    request.onsuccess = () => resolve(true);
                                    request.onerror = () => resolve(false);
                                    request.onblocked = () => resolve(false);
                                });
                                summary.indexed_db_deleted.push(name);
                            } catch (e) {
                                summary.indexed_db_errors.push(`${name}: ${String(e)}`);
                            }
                        }
                    } else {
                        summary.indexed_db_unsupported = true;
                    }
                } catch (e) {
                    summary.indexed_db_errors.push(String(e));
                }

                return summary;
            })()
        """, label="clear_tab_site_storage", timeout_seconds=15.0)
        return result if isinstance(result, dict) else {}

    async def _clear_resident_storage_and_reload(self, project_id: str) -> bool:
        """清理常驻标签页的站点数据并刷新，尝试原地自愈。"""
        async with self._resident_lock:
            slot_id, resident_info = self._resolve_resident_slot_for_project_locked(project_id)

        if not resident_info or not resident_info.tab:
            debug_logger.log_warning(f"[BrowserCaptcha] project_id={project_id} 没有可清理的共享标签页")
            return False

        try:
            async with resident_info.solve_lock:
                cleanup_summary = await self._clear_tab_site_storage(resident_info.tab)
                debug_logger.log_warning(
                    f"[BrowserCaptcha] project_id={project_id}, slot={slot_id} 已清理站点存储，准备刷新恢复: {cleanup_summary}"
                )

                resident_info.recaptcha_ready = False
                await self._tab_reload(
                    resident_info.tab,
                    label=f"clear_resident_reload:{slot_id or project_id}",
                )

                if not await self._wait_for_document_ready(resident_info.tab, retries=30, interval_seconds=1.0):
                    debug_logger.log_warning(f"[BrowserCaptcha] project_id={project_id}, slot={slot_id} 清理后页面加载超时")
                    return False

                await self._apply_tab_fingerprint_profile(
                    resident_info.tab,
                    label=f"clear_resident_apply_fingerprint:{slot_id or project_id}",
                )

                resident_info.recaptcha_ready = await self._wait_for_recaptcha(resident_info.tab)
                if resident_info.recaptcha_ready:
                    resident_info.last_used_at = time.time()
                    self._remember_project_affinity(project_id, slot_id, resident_info)
                    self._resident_error_streaks.pop(slot_id, None)
                    debug_logger.log_warning(f"[BrowserCaptcha] project_id={project_id}, slot={slot_id} 清理后已恢复 reCAPTCHA")
                    return True

                debug_logger.log_warning(f"[BrowserCaptcha] project_id={project_id}, slot={slot_id} 清理后仍无法恢复 reCAPTCHA")
                return False
        except Exception as e:
            debug_logger.log_warning(f"[BrowserCaptcha] project_id={project_id}, slot={slot_id} 清理或刷新失败: {e}")
            return False

    async def _recreate_resident_tab(self, project_id: str) -> bool:
        """关闭并重建常驻标签页。"""
        slot_id, resident_info = await self._rebuild_resident_tab(project_id, return_slot_key=True)
        if resident_info is None:
            debug_logger.log_warning(f"[BrowserCaptcha] project_id={project_id} 重建共享标签页失败")
            return False
        debug_logger.log_warning(f"[BrowserCaptcha] project_id={project_id} 已重建共享标签页 slot={slot_id}")
        return True

    async def _restart_browser_for_project(self, project_id: str) -> bool:
        """重启整个 nodriver 浏览器，并恢复共享打码池。"""
        async with self._resident_lock:
            restore_slots = max(1, min(self._max_resident_tabs, len(self._resident_tabs) or 1))
            restore_project_ids: list[str] = []
            seen_projects = set()
            for candidate in [project_id, *self._project_resident_affinity.keys()]:
                normalized_project_id = str(candidate or "").strip()
                if not normalized_project_id or normalized_project_id in seen_projects:
                    continue
                seen_projects.add(normalized_project_id)
                restore_project_ids.append(normalized_project_id)
                if len(restore_project_ids) >= restore_slots:
                    break

        debug_logger.log_warning(f"[BrowserCaptcha] project_id={project_id} 准备重启 nodriver 浏览器以恢复")
        await self._shutdown_browser_runtime(cancel_idle_reaper=False, reason=f"restart_project:{project_id}")

        warmed_slots = await self.warmup_resident_tabs(restore_project_ids, limit=restore_slots)
        if not warmed_slots:
            debug_logger.log_warning(f"[BrowserCaptcha] project_id={project_id} 浏览器重启后恢复共享标签页失败")
            return False

        slot_id, resident_info = await self._ensure_resident_tab(project_id, return_slot_key=True)
        if resident_info is None or not slot_id:
            debug_logger.log_warning(f"[BrowserCaptcha] project_id={project_id} 浏览器重启后无法定位可用共享标签页")
            return False

        self._remember_project_affinity(project_id, slot_id, resident_info)
        self._resident_error_streaks.pop(slot_id, None)
        debug_logger.log_warning(
            f"[BrowserCaptcha] project_id={project_id} 浏览器重启后已恢复共享标签页池 "
            f"(slots={len(warmed_slots)}, active_slot={slot_id})"
        )
        return True

    async def _restart_browser_pool(self, project_id: Optional[str] = None) -> bool:
        async with self._resident_lock:
            restore_slots = max(1, min(self._max_resident_tabs, len(self._resident_tabs) or 1))
            restore_targets: list[tuple[int, str]] = []
            seen_targets = set()
            seed_candidates: list[str] = []

            for resident_info in self._resident_tabs.values():
                if resident_info is None:
                    continue
                token_id = int(resident_info.token_id or 0)
                resident_project_id = str(resident_info.project_id or "").strip()
                if token_id > 0 and resident_project_id:
                    dedupe_key = (token_id, resident_project_id)
                    if dedupe_key not in seen_targets:
                        seen_targets.add(dedupe_key)
                        restore_targets.append(dedupe_key)
                elif resident_project_id:
                    seed_candidates.append(resident_project_id)

            if project_id:
                normalized_project_id = str(project_id).strip()
                if normalized_project_id:
                    seed_candidates.insert(0, normalized_project_id)

        self._pool_restart_cooldown_until = time.time() + self._pool_restart_cooldown_seconds
        debug_logger.log_warning(
            f"[BrowserCaptcha] pool={self._pool_key} unhealthy ratio exceeded threshold, restarting browser pool "
            f"(restore_slots={restore_slots}, restore_targets={len(restore_targets)})"
        )
        await self._shutdown_browser_runtime(cancel_idle_reaper=False, reason=f"restart_pool:{self._pool_key}")

        if restore_targets:
            warmed_slots = await self.warmup_resident_tabs_for_tokens(restore_targets, limit=restore_slots)
        else:
            if not seed_candidates:
                seed_candidates = [f"pool-restart-{index + 1}" for index in range(restore_slots)]
            warmed_slots = await self.warmup_resident_tabs(seed_candidates, limit=restore_slots)

        if not warmed_slots:
            debug_logger.log_warning(
                f"[BrowserCaptcha] pool={self._pool_key} browser pool restart finished without warmed slots"
            )
            return False

        debug_logger.log_warning(
            f"[BrowserCaptcha] pool={self._pool_key} browser pool restarted successfully "
            f"(slots={len(warmed_slots)})"
        )
        return True

    async def report_request_finished(self, project_id: Optional[str], success: bool = True):
        """上游请求结束后回传结果，用于更新 slot 健康分。"""
        normalized_project_id = str(project_id or "").strip()
        if not normalized_project_id:
            return
        rebuild_slot_id: Optional[str] = None
        rebuild_token_id: Optional[int] = None
        restart_pool = False

        async with self._resident_lock:
            slot_id = self._resolve_affinity_slot_locked(normalized_project_id)
            resident_info = self._resident_tabs.get(slot_id) if slot_id else None
            if resident_info is None:
                slot_id, resident_info = self._resolve_resident_slot_for_project_locked(normalized_project_id)
            if resident_info is None or not slot_id:
                return
            if success:
                self._mark_slot_upstream_success(resident_info)
                self._resident_error_streaks.pop(slot_id, None)
            else:
                self._mark_slot_upstream_error(resident_info)
                if self._should_rebuild_resident_slot(slot_id, resident_info):
                    rebuild_slot_id = slot_id
                    rebuild_token_id = resident_info.token_id
            snapshot = self._get_resident_pool_snapshot_locked()
            if not success and self._should_restart_pool_locked(snapshot):
                restart_pool = True

        debug_logger.log_info(
            "[BrowserCaptcha] report_request_finished: "
            f"pool={self._pool_key}, project_id={normalized_project_id}, slot={slot_id}, success={success}, "
            f"health={resident_info.health_score}, upstream_success={resident_info.upstream_success_count}, "
            f"upstream_error={resident_info.upstream_error_count}, pool={snapshot}"
        )
        if restart_pool:
            debug_logger.log_warning(
                f"[BrowserCaptcha] pool={self._pool_key}, project_id={normalized_project_id} "
                f"unhealthy_ratio={snapshot.get('unhealthy', 0)}/{snapshot.get('total', 0)}, restarting browser pool"
            )
            await self._restart_browser_pool(normalized_project_id)
            return
        if rebuild_slot_id and not success:
            debug_logger.log_warning(
                f"[BrowserCaptcha] project_id={normalized_project_id}, slot={rebuild_slot_id} "
                f"reached unhealthy threshold, rebuilding while keeping token/proxy-pool affinity"
            )
            await self._rebuild_resident_tab(
                normalized_project_id,
                token_id=rebuild_token_id,
                slot_id=rebuild_slot_id,
            )

    async def report_flow_error(self, project_id: str, error_reason: str, error_message: str = ""):
        """上游生成接口异常时，对常驻标签页执行自愈恢复。"""
        if not project_id:
            return

        async with self._resident_lock:
            slot_id, resident_info = self._resolve_resident_slot_for_project_locked(project_id)

        if not slot_id:
            return

        streak = self._resident_error_streaks.get(slot_id, 0) + 1
        self._resident_error_streaks[slot_id] = streak
        self._mark_slot_upstream_error(resident_info)
        error_text = f"{error_reason or ''} {error_message or ''}".strip()
        error_lower = error_text.lower()
        debug_logger.log_warning(
            f"[BrowserCaptcha] project_id={project_id}, slot={slot_id} 收到上游异常，streak={streak}, "
            f"health={resident_info.health_score if resident_info else 'n/a'}, reason={error_reason}, detail={error_message[:200]}"
        )

        if not self._initialized or not self.browser:
            return

        # 403 错误：先清理缓存再重建
        if "403" in error_text or "forbidden" in error_lower or "recaptcha" in error_lower:
            if streak < self._flow_recover_threshold:
                debug_logger.log_warning(
                    f"[BrowserCaptcha] project_id={project_id}, slot={slot_id} 暂不恢复，等待更多同类错误 "
                    f"(streak={streak}, threshold={self._flow_recover_threshold})"
                )
                return
            debug_logger.log_warning(
                f"[BrowserCaptcha] project_id={project_id} 检测到 403/reCAPTCHA 错误，清理缓存并重建"
            )
            await self._recreate_resident_tab(project_id)
            return

        # 服务端错误：根据连续失败次数决定恢复策略
        if self._is_server_side_flow_error(error_text):
            recreate_threshold = max(2, int(getattr(config, "browser_personal_recreate_threshold", 2) or 2))
            restart_threshold = max(3, int(getattr(config, "browser_personal_restart_threshold", 3) or 3))

            if streak >= restart_threshold:
                await self._restart_browser_for_project(project_id)
                return
            if streak >= recreate_threshold:
                await self._recreate_resident_tab(project_id)
                return

            healed = await self._clear_resident_storage_and_reload(project_id)
            if not healed:
                await self._recreate_resident_tab(project_id)
            return

        # 其他错误：直接重建标签页
        await self._recreate_resident_tab(project_id)

    async def _wait_for_recaptcha(self, tab) -> bool:
        """等待 reCAPTCHA 加载

        Returns:
            True if reCAPTCHA loaded successfully
        """
        debug_logger.log_info("[BrowserCaptcha] 注入 reCAPTCHA 脚本...")

        # 注入 reCAPTCHA Enterprise 脚本
        await self._tab_evaluate(tab, f"""
            (() => {{
                if (document.querySelector('script[src*="recaptcha"]')) return;
                const script = document.createElement('script');
                script.src = 'https://www.google.com/recaptcha/enterprise.js?render={self.website_key}';
                script.async = true;
                document.head.appendChild(script);
            }})()
        """, label="inject_recaptcha_script", timeout_seconds=5.0)

        # 等待 reCAPTCHA 加载（减少等待时间）
        for i in range(15):  # 减少到15次，最多7.5秒
            try:
                is_ready = await self._tab_evaluate(
                    tab,
                    "typeof grecaptcha !== 'undefined' && "
                    "typeof grecaptcha.enterprise !== 'undefined' && "
                    "typeof grecaptcha.enterprise.execute === 'function'",
                    label="check_recaptcha_ready",
                    timeout_seconds=2.5,
                )

                if is_ready:
                    debug_logger.log_info(f"[BrowserCaptcha] reCAPTCHA 已就绪 (等待了 {i * 0.5}s)")
                    return True

                await tab.sleep(0.5)
            except Exception as e:
                debug_logger.log_warning(f"[BrowserCaptcha] 检查 reCAPTCHA 时异常: {e}")
                await tab.sleep(0.3)  # 异常时减少等待时间

        debug_logger.log_warning("[BrowserCaptcha] reCAPTCHA 加载超时")
        return False

    async def _wait_for_custom_recaptcha(
        self,
        tab,
        website_key: str,
        enterprise: bool = False,
    ) -> bool:
        """等待任意站点的 reCAPTCHA 加载，用于分数测试。"""
        debug_logger.log_info("[BrowserCaptcha] 检测自定义 reCAPTCHA...")

        ready_check = (
            "typeof grecaptcha !== 'undefined' && typeof grecaptcha.enterprise !== 'undefined' && "
            "typeof grecaptcha.enterprise.execute === 'function'"
        ) if enterprise else (
            "typeof grecaptcha !== 'undefined' && typeof grecaptcha.execute === 'function'"
        )
        script_path = "recaptcha/enterprise.js" if enterprise else "recaptcha/api.js"
        label = "Enterprise" if enterprise else "V3"

        is_ready = await self._tab_evaluate(
            tab,
            ready_check,
            label="check_custom_recaptcha_preloaded",
            timeout_seconds=2.5,
        )
        if is_ready:
            debug_logger.log_info(f"[BrowserCaptcha] 自定义 reCAPTCHA {label} 已加载")
            return True

        debug_logger.log_info("[BrowserCaptcha] 未检测到自定义 reCAPTCHA，注入脚本...")
        await self._tab_evaluate(tab, f"""
            (() => {{
                if (document.querySelector('script[src*="recaptcha"]')) return;
                const script = document.createElement('script');
                script.src = 'https://www.google.com/{script_path}?render={website_key}';
                script.async = true;
                document.head.appendChild(script);
            }})()
        """, label="inject_custom_recaptcha_script", timeout_seconds=5.0)

        await tab.sleep(3)
        for i in range(20):
            is_ready = await self._tab_evaluate(
                tab,
                ready_check,
                label="check_custom_recaptcha_ready",
                timeout_seconds=2.5,
            )
            if is_ready:
                debug_logger.log_info(f"[BrowserCaptcha] 自定义 reCAPTCHA {label} 已加载（等待了 {i * 0.5} 秒）")
                return True
            await tab.sleep(0.5)

        debug_logger.log_warning("[BrowserCaptcha] 自定义 reCAPTCHA 加载超时")
        return False

    async def _execute_recaptcha_on_tab(
        self,
        tab,
        action: str = "IMAGE_GENERATION",
        *,
        allow_recaptcha_recover: bool = True,
    ) -> Optional[str]:
        """在指定标签页执行 reCAPTCHA 获取 token

        Args:
            tab: nodriver 标签页对象
            action: reCAPTCHA action类型 (IMAGE_GENERATION 或 VIDEO_GENERATION)

        Returns:
            reCAPTCHA token 或 None
        """
        # 生成唯一变量名避免冲突
        ts = int(time.time() * 1000)
        token_var = f"_recaptcha_token_{ts}"
        error_var = f"_recaptcha_error_{ts}"

        execute_script = f"""
            (() => {{
                window.{token_var} = null;
                window.{error_var} = null;

                try {{
                    grecaptcha.enterprise.ready(function() {{
                        grecaptcha.enterprise.execute('{self.website_key}', {{action: '{action}'}})
                            .then(function(token) {{
                                window.{token_var} = token;
                            }})
                            .catch(function(err) {{
                                window.{error_var} = err.message || 'execute failed';
                            }});
                    }});
                }} catch (e) {{
                    window.{error_var} = e.message || 'exception';
                }}
            }})()
        """

        # 注入执行脚本
        await self._tab_evaluate(
            tab,
            execute_script,
            label=f"execute_recaptcha:{action}",
            timeout_seconds=5.0,
        )

        # 轮询等待结果（最多 30 秒）
        token = None
        last_error: Optional[str] = None
        for i in range(60):
            await tab.sleep(0.5)
            token = await self._tab_evaluate(
                tab,
                f"window.{token_var}",
                label=f"poll_recaptcha_token:{action}",
                timeout_seconds=2.0,
            )
            if token:
                break
            error = await self._tab_evaluate(
                tab,
                f"window.{error_var}",
                label=f"poll_recaptcha_error:{action}",
                timeout_seconds=2.0,
            )
            if error:
                last_error = str(error)
                debug_logger.log_error(f"[BrowserCaptcha] reCAPTCHA 错误: {error}")
                break

        # 清理临时变量
        try:
            await self._tab_evaluate(
                tab,
                f"delete window.{token_var}; delete window.{error_var};",
                label="cleanup_recaptcha_temp_vars",
                timeout_seconds=5.0,
            )
        except:
            pass

        if token:
            debug_logger.log_info(f"[BrowserCaptcha] ✅ Token 获取成功 (长度: {len(token)})")
        else:
            if allow_recaptcha_recover and self._is_recaptcha_not_ready_error(last_error):
                debug_logger.log_warning(
                    "[BrowserCaptcha] reCAPTCHA runtime not ready on resident tab, retrying after reinject/wait"
                )
                ready = await self._wait_for_recaptcha(tab)
                if ready:
                    return await self._execute_recaptcha_on_tab(
                        tab,
                        action,
                        allow_recaptcha_recover=False,
                    )
            debug_logger.log_warning("[BrowserCaptcha] Token 获取失败，交由上层执行标签页恢复")

        return token

    async def _execute_custom_recaptcha_on_tab(
        self,
        tab,
        website_key: str,
        action: str = "homepage",
        enterprise: bool = False,
    ) -> Optional[str]:
        """在指定标签页执行任意站点的 reCAPTCHA。"""
        ts = int(time.time() * 1000)
        token_var = f"_custom_recaptcha_token_{ts}"
        error_var = f"_custom_recaptcha_error_{ts}"
        execute_target = "grecaptcha.enterprise.execute" if enterprise else "grecaptcha.execute"

        execute_script = f"""
            (() => {{
                window.{token_var} = null;
                window.{error_var} = null;

                try {{
                    grecaptcha.ready(function() {{
                        {execute_target}('{website_key}', {{action: '{action}'}})
                            .then(function(token) {{
                                window.{token_var} = token;
                            }})
                            .catch(function(err) {{
                                window.{error_var} = err.message || 'execute failed';
                            }});
                    }});
                }} catch (e) {{
                    window.{error_var} = e.message || 'exception';
                }}
            }})()
        """

        await self._tab_evaluate(
            tab,
            execute_script,
            label=f"execute_custom_recaptcha:{action}",
            timeout_seconds=5.0,
        )

        token = None
        for _ in range(30):
            await tab.sleep(0.5)
            token = await self._tab_evaluate(
                tab,
                f"window.{token_var}",
                label=f"poll_custom_recaptcha_token:{action}",
                timeout_seconds=2.0,
            )
            if token:
                break
            error = await self._tab_evaluate(
                tab,
                f"window.{error_var}",
                label=f"poll_custom_recaptcha_error:{action}",
                timeout_seconds=2.0,
            )
            if error:
                debug_logger.log_error(f"[BrowserCaptcha] 自定义 reCAPTCHA 错误: {error}")
                break

        try:
            await self._tab_evaluate(
                tab,
                f"delete window.{token_var}; delete window.{error_var};",
                label="cleanup_custom_recaptcha_temp_vars",
                timeout_seconds=5.0,
            )
        except:
            pass

        if token:
            post_wait_seconds = 3
            try:
                post_wait_seconds = float(getattr(config, "browser_recaptcha_settle_seconds", 3) or 3)
            except Exception:
                pass
            if post_wait_seconds > 0:
                debug_logger.log_info(
                    f"[BrowserCaptcha] 自定义 reCAPTCHA 已完成，额外等待 {post_wait_seconds:.1f}s 后返回 token"
                )
                await tab.sleep(post_wait_seconds)

        return token

    async def _verify_score_on_tab(self, tab, token: str, verify_url: str) -> Dict[str, Any]:
        """直接读取测试页面展示的分数，避免 verify.php 与页面显示口径不一致。"""
        _ = token
        _ = verify_url
        started_at = time.time()
        timeout_seconds = 25.0
        refresh_clicked = False
        last_snapshot: Dict[str, Any] = {}

        try:
            timeout_seconds = float(getattr(config, "browser_score_dom_wait_seconds", 25) or 25)
        except Exception:
            pass

        while (time.time() - started_at) < timeout_seconds:
            try:
                result = await self._tab_evaluate(tab, """
                    (() => {
                        const bodyText = ((document.body && document.body.innerText) || "")
                            .replace(/\\u00a0/g, " ")
                            .replace(/\\r/g, "");
                        const patterns = [
                            { source: "current_score", regex: /Your score is:\\s*([01](?:\\.\\d+)?)/i },
                            { source: "selected_score", regex: /Selected Score Test:[\\s\\S]{0,400}?Score:\\s*([01](?:\\.\\d+)?)/i },
                            { source: "history_score", regex: /(?:^|\\n)\\s*Score:\\s*([01](?:\\.\\d+)?)\\s*;/i },
                        ];
                        let score = null;
                        let source = "";
                        for (const item of patterns) {
                            const match = bodyText.match(item.regex);
                            if (!match) continue;
                            const parsed = Number(match[1]);
                            if (!Number.isNaN(parsed) && parsed >= 0 && parsed <= 1) {
                                score = parsed;
                                source = item.source;
                                break;
                            }
                        }
                        const uaMatch = bodyText.match(/Current User Agent:\\s*([^\\n]+)/i);
                        const ipMatch = bodyText.match(/Current IP Address:\\s*([^\\n]+)/i);
                        return {
                            score,
                            source,
                            raw_text: bodyText.slice(0, 4000),
                            current_user_agent: uaMatch ? uaMatch[1].trim() : "",
                            current_ip_address: ipMatch ? ipMatch[1].trim() : "",
                            title: document.title || "",
                            url: location.href || "",
                        };
                    })()
                """, label="verify_score_dom", timeout_seconds=10.0)
            except Exception as e:
                result = {"error": f"{type(e).__name__}: {str(e)[:200]}"}

            if isinstance(result, dict):
                last_snapshot = result
                score = result.get("score")
                if isinstance(score, (int, float)):
                    elapsed_ms = int((time.time() - started_at) * 1000)
                    return {
                        "verify_mode": "browser_page_dom",
                        "verify_elapsed_ms": elapsed_ms,
                        "verify_http_status": None,
                        "verify_result": {
                            "success": True,
                            "score": score,
                            "source": result.get("source") or "antcpt_dom",
                            "raw_text": result.get("raw_text") or "",
                            "current_user_agent": result.get("current_user_agent") or "",
                            "current_ip_address": result.get("current_ip_address") or "",
                            "page_title": result.get("title") or "",
                            "page_url": result.get("url") or "",
                        },
                    }

            if not refresh_clicked and (time.time() - started_at) >= 2:
                refresh_clicked = True
                try:
                    await self._tab_evaluate(tab, """
                        (() => {
                            const nodes = Array.from(
                                document.querySelectorAll('button, input[type="button"], input[type="submit"], a')
                            );
                            const target = nodes.find((node) => {
                                const text = (node.innerText || node.textContent || node.value || "").trim();
                                return /Refresh score now!?/i.test(text);
                            });
                            if (target) {
                                target.click();
                                return true;
                            }
                            return false;
                        })()
                    """, label="verify_score_click_refresh", timeout_seconds=5.0)
                except Exception:
                    pass

            await tab.sleep(0.5)

        elapsed_ms = int((time.time() - started_at) * 1000)
        if not isinstance(last_snapshot, dict):
            last_snapshot = {"raw": last_snapshot}

        return {
            "verify_mode": "browser_page_dom",
            "verify_elapsed_ms": elapsed_ms,
            "verify_http_status": None,
            "verify_result": {
                "success": False,
                "score": None,
                "source": "antcpt_dom_timeout",
                "raw_text": last_snapshot.get("raw_text") or "",
                "current_user_agent": last_snapshot.get("current_user_agent") or "",
                "current_ip_address": last_snapshot.get("current_ip_address") or "",
                "page_title": last_snapshot.get("title") or "",
                "page_url": last_snapshot.get("url") or "",
                "error": last_snapshot.get("error") or "未在页面中读取到分数",
            },
        }

    async def _extract_tab_fingerprint(self, tab) -> Optional[Dict[str, Any]]:
        """从 nodriver 标签页提取浏览器指纹信息。"""
        try:
            fingerprint = None
            raw_fingerprint = await self._tab_evaluate(tab, """
                (async () => {
                    const ua = navigator.userAgent || "";
                    const lang = navigator.language || "";
                    const languages = Array.isArray(navigator.languages) ? navigator.languages : [];
                    const uaData = navigator.userAgentData || null;
                    let highEntropy = null;
                    if (uaData && typeof uaData.getHighEntropyValues === "function") {
                        try {
                            highEntropy = await uaData.getHighEntropyValues([
                                "architecture",
                                "bitness",
                                "formFactors",
                                "fullVersionList",
                                "model",
                                "platform",
                                "platformVersion",
                                "uaFullVersion",
                                "wow64"
                            ]);
                        } catch (error) {
                            highEntropy = {
                                _error: String(error && error.message ? error.message : error || "")
                            };
                        }
                    }
                    return JSON.stringify({
                        user_agent: ua,
                        accept_language: lang,
                        languages,
                        brands: Array.isArray(uaData?.brands) ? uaData.brands : [],
                        mobile: typeof uaData?.mobile === "boolean" ? uaData.mobile : null,
                        platform: uaData?.platform || "",
                        architecture: highEntropy?.architecture || "",
                        bitness: highEntropy?.bitness || "",
                        model: highEntropy?.model || "",
                        platform_version: highEntropy?.platformVersion || "",
                        wow64: typeof highEntropy?.wow64 === "boolean" ? highEntropy.wow64 : null,
                        full_version_list: Array.isArray(highEntropy?.fullVersionList) ? highEntropy.fullVersionList : [],
                        ua_full_version: highEntropy?.uaFullVersion || "",
                        high_entropy_error: highEntropy?._error || "",
                    });
                })()
            """, label="extract_tab_fingerprint", timeout_seconds=8.0)
            if isinstance(raw_fingerprint, str) and raw_fingerprint:
                try:
                    fingerprint = json.loads(raw_fingerprint)
                except Exception as parse_error:
                    debug_logger.log_warning(
                        f"[BrowserCaptcha] extract_tab_fingerprint JSON 解析失败: {parse_error}, raw={raw_fingerprint[:300]}"
                    )
            if not isinstance(fingerprint, dict):
                debug_logger.log_warning(
                    f"[BrowserCaptcha] extract_tab_fingerprint 返回非 dict: type={type(raw_fingerprint).__name__}, value={str(raw_fingerprint)[:300]}"
                )
                try:
                    fallback_ua = await self._tab_evaluate(
                        tab,
                        "navigator.userAgent || ''",
                        label="extract_fingerprint_fallback_ua",
                        timeout_seconds=3.0,
                    )
                    fallback_lang = await self._tab_evaluate(
                        tab,
                        "navigator.language || ''",
                        label="extract_fingerprint_fallback_lang",
                        timeout_seconds=3.0,
                    )
                    fingerprint = {
                        "user_agent": fallback_ua or "",
                        "accept_language": fallback_lang or "",
                    }
                except Exception as fallback_error:
                    debug_logger.log_warning(
                        f"[BrowserCaptcha] extract_tab_fingerprint fallback 失败: {fallback_error}"
                    )
                    return None

            if config.debug_enabled:
                raw_full_version_list = fingerprint.get("full_version_list")
                raw_platform_version = fingerprint.get("platform_version")
                raw_brands = fingerprint.get("brands")
                high_entropy_error = fingerprint.get("high_entropy_error")
                debug_logger.log_info(
                    "[BrowserCaptcha] high_entropy_raw: "
                    f"brands={json.dumps(raw_brands, ensure_ascii=False)[:300]}, "
                    f"full_version_list={json.dumps(raw_full_version_list, ensure_ascii=False)[:300]}, "
                    f"platform_version={raw_platform_version!r}, "
                    f"arch={fingerprint.get('architecture', '')!r}, "
                    f"bitness={fingerprint.get('bitness', '')!r}, "
                    f"model={fingerprint.get('model', '')!r}, "
                    f"wow64={fingerprint.get('wow64', None)!r}, "
                    f"error={high_entropy_error!r}"
                )

            preferred_profile = self._get_tab_fingerprint_profile(tab) or self._fingerprint_profile or {}
            merged_fingerprint = dict(fingerprint)
            for key in (
                "user_agent",
                "brands",
                "full_version_list",
                "mobile",
                "platform",
                "architecture",
                "bitness",
                "model",
                "platform_version",
                "wow64",
            ):
                profile_value = preferred_profile.get(key)
                if profile_value not in (None, "", [], {}):
                    merged_fingerprint[key] = profile_value

            result: Dict[str, Any] = self._normalize_fingerprint_payload(merged_fingerprint)
            result["proxy_url"] = self._proxy_url
            for key in (
                "user_agent",
                "accept_language",
                "sec_ch_ua",
                "sec_ch_ua_mobile",
                "sec_ch_ua_platform",
                "sec_ch_ua_full_version_list",
                "sec_ch_ua_arch",
                "sec_ch_ua_bitness",
                "sec_ch_ua_model",
                "sec_ch_ua_platform_version",
                "sec_ch_ua_wow64",
            ):
                value = merged_fingerprint.get(key)
                if isinstance(value, str) and value:
                    result[key] = value
            if len(result) <= 1:
                debug_logger.log_warning(
                    f"[BrowserCaptcha] extract_tab_fingerprint 结果为空: raw={str(merged_fingerprint)[:300]}"
                )
                return None
            debug_logger.log_info(
                f"[BrowserCaptcha] extract_tab_fingerprint 成功: ua={result.get('user_agent', '')[:120]}, "
                f"lang={result.get('accept_language', '')}, sec_ch_ua={'yes' if result.get('sec_ch_ua') else 'no'}, "
                f"sec_ch_mobile={result.get('sec_ch_ua_mobile', '')}, sec_ch_platform={result.get('sec_ch_ua_platform', '')}, "
                f"full_version={'yes' if result.get('sec_ch_ua_full_version_list') else 'no'}"
            )
            return result
        except Exception as e:
            debug_logger.log_warning(f"[BrowserCaptcha] 提取 nodriver 指纹失败: {e}")
            return None

    def _normalize_fingerprint_payload(self, fingerprint: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize raw browser data into request-ready client hints."""
        if not isinstance(fingerprint, dict):
            return {}

        result: Dict[str, Any] = {}
        user_agent = fingerprint.get("user_agent")
        if isinstance(user_agent, str) and user_agent:
            result["user_agent"] = user_agent

        accept_language = fingerprint.get("accept_language")
        if isinstance(accept_language, str) and accept_language:
            result["accept_language"] = accept_language

        brands = fingerprint.get("brands")
        if isinstance(brands, list) and brands:
            sec_ch_ua = self._format_sec_ch_brands(brands)
            if sec_ch_ua:
                result["sec_ch_ua"] = sec_ch_ua

        full_version_list = fingerprint.get("full_version_list")
        if isinstance(full_version_list, list) and full_version_list:
            rendered_full_version_list = self._format_sec_ch_brands(full_version_list)
            if rendered_full_version_list:
                result["sec_ch_ua_full_version_list"] = rendered_full_version_list

        mobile = fingerprint.get("mobile")
        if isinstance(mobile, bool):
            result["sec_ch_ua_mobile"] = "?1" if mobile else "?0"

        platform = fingerprint.get("platform")
        if isinstance(platform, str) and platform:
            result["sec_ch_ua_platform"] = json.dumps(platform)

        architecture = fingerprint.get("architecture")
        if isinstance(architecture, str) and architecture:
            result["sec_ch_ua_arch"] = json.dumps(architecture)

        bitness = fingerprint.get("bitness")
        if isinstance(bitness, str) and bitness:
            result["sec_ch_ua_bitness"] = json.dumps(bitness)

        model = fingerprint.get("model")
        if isinstance(model, str):
            result["sec_ch_ua_model"] = json.dumps(model)

        platform_version = fingerprint.get("platform_version")
        if isinstance(platform_version, str) and platform_version:
            result["sec_ch_ua_platform_version"] = json.dumps(platform_version)

        wow64 = fingerprint.get("wow64")
        if isinstance(wow64, bool):
            result["sec_ch_ua_wow64"] = "?1" if wow64 else "?0"

        self._fill_missing_client_hints_from_ua(result)
        return result

    def _format_sec_ch_brands(self, brands: Any) -> str:
        if not isinstance(brands, list):
            return ""
        rendered = []
        for item in brands:
            if not isinstance(item, dict):
                continue
            brand = str(item.get("brand") or "").strip()
            version = str(item.get("version") or "").strip()
            if not brand or not version:
                continue
            rendered.append(f"\"{brand}\";v=\"{version}\"")
        return ", ".join(rendered)

    def _fill_missing_client_hints_from_ua(self, result: Dict[str, Any]):
        """Derive conservative Chromium client hints from UA when JS APIs are unavailable."""
        user_agent = str(result.get("user_agent") or "")
        if not user_agent:
            return

        platform = ""
        platform_version = ""
        mobile = "?0"
        arch = ""
        bitness = ""
        model = ""
        wow64 = "?0"

        chrome_match = re.search(r"Chrome/([0-9.]+)", user_agent)
        edge_match = re.search(r"Edg/([0-9.]+)", user_agent)
        chrome_version = chrome_match.group(1) if chrome_match else ""
        edge_version = edge_match.group(1) if edge_match else ""
        major_version = (edge_version or chrome_version).split(".")[0] if (edge_version or chrome_version) else ""

        if "Windows NT" in user_agent:
            platform = "Windows"
            nt_match = re.search(r"Windows NT ([0-9.]+)", user_agent)
            if nt_match:
                platform_version = nt_match.group(1)
            if "WOW64" in user_agent:
                wow64 = "?1"
        elif "Android" in user_agent:
            platform = "Android"
            mobile = "?1"
            android_match = re.search(r"Android ([0-9.]+)", user_agent)
            if android_match:
                platform_version = android_match.group(1)
            model_match = re.search(r"Android [^;]+; ([^)]+)\)", user_agent)
            if model_match:
                model = model_match.group(1).strip()
        elif "Mac OS X" in user_agent:
            platform = "macOS"
            mac_match = re.search(r"Mac OS X ([0-9_]+)", user_agent)
            if mac_match:
                platform_version = mac_match.group(1).replace("_", ".")
        elif "iPhone" in user_agent or "iPad" in user_agent:
            platform = "iOS"
            mobile = "?1"
            ios_match = re.search(r"OS ([0-9_]+)", user_agent)
            if ios_match:
                platform_version = ios_match.group(1).replace("_", ".")
        elif "Linux" in user_agent:
            platform = "Linux"

        ua_lower = user_agent.lower()
        if "arm64" in ua_lower or "aarch64" in ua_lower:
            arch = "arm"
            bitness = "64"
        elif "x86_64" in ua_lower or "win64" in ua_lower or "x64" in ua_lower:
            arch = "x86"
            bitness = "64"
        elif "i686" in ua_lower or "i386" in ua_lower:
            arch = "x86"
            bitness = "32"

        if major_version:
            if edge_version:
                result.setdefault(
                    "sec_ch_ua",
                    f"\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"{major_version}\", \"Microsoft Edge\";v=\"{major_version}\""
                )
                result.setdefault(
                    "sec_ch_ua_full_version_list",
                    f"\"Not.A/Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"{chrome_version or edge_version}\", \"Microsoft Edge\";v=\"{edge_version}\""
                )
            elif chrome_version:
                result.setdefault(
                    "sec_ch_ua",
                    f"\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"{major_version}\", \"Google Chrome\";v=\"{major_version}\""
                )
                result.setdefault(
                    "sec_ch_ua_full_version_list",
                    f"\"Not.A/Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"{chrome_version}\", \"Google Chrome\";v=\"{chrome_version}\""
                )

        if platform:
            result.setdefault("sec_ch_ua_platform", json.dumps(platform))
        if platform_version:
            result.setdefault("sec_ch_ua_platform_version", json.dumps(platform_version))
        if mobile:
            result.setdefault("sec_ch_ua_mobile", mobile)
        if arch:
            result.setdefault("sec_ch_ua_arch", json.dumps(arch))
        if bitness:
            result.setdefault("sec_ch_ua_bitness", json.dumps(bitness))
        result.setdefault("sec_ch_ua_model", json.dumps(model))
        result.setdefault("sec_ch_ua_wow64", wow64)

    # ========== 主要 API ==========

    async def get_token(
        self,
        project_id: str,
        action: str = "IMAGE_GENERATION",
        token_id: Optional[int] = None,
    ) -> Optional[str]:
        """获取 reCAPTCHA token

        使用全局共享打码标签页池。标签页不再按 project_id 一对一绑定，
        谁拿到空闲 tab 就用谁的；只有 Session Token 刷新/故障恢复会优先参考最近一次映射。

        Args:
            project_id: Flow项目ID
            action: reCAPTCHA action类型
                - IMAGE_GENERATION: 图片生成和2K/4K图片放大 (默认)
                - VIDEO_GENERATION: 视频生成和视频放大

        Returns:
            reCAPTCHA token字符串，如果获取失败返回None
        """
        debug_logger.log_info(
            f"[BrowserCaptcha] get_token 开始: pool={self._pool_key}, token_id={token_id}, "
            f"project_id={project_id}, action={action}, 当前标签页数={len(self._resident_tabs)}/{self._max_resident_tabs}"
        )

        # 确保浏览器已初始化
        await self.initialize()
        self._last_fingerprint = None
        try:
            await self._enter_queue_gate()
        except asyncio.TimeoutError:
            debug_logger.log_warning(
                f"[BrowserCaptcha] personal queue gate timeout, reject request: project={project_id}, "
                f"queue_limit={self._queue_limit}, queue_timeout={self._queue_acquire_timeout_seconds:.1f}s"
            )
            return None

        try:
            debug_logger.log_info(
                f"[BrowserCaptcha] 开始从共享打码池获取标签页 (project: {project_id}, 当前: {len(self._resident_tabs)}/{self._max_resident_tabs})"
            )
            try:
                slot_id, resident_info = await self._acquire_resident_slot_for_solve(project_id, token_id=token_id)
            except asyncio.TimeoutError:
                debug_logger.log_warning(
                    f"[BrowserCaptcha] 获取共享标签页锁超时，回退 legacy 模式 (project: {project_id}, "
                    f"wait_timeout={self._slot_wait_timeout_seconds:.1f}s)"
                )
                return await self._get_token_legacy(project_id, action)
            if resident_info is None or not slot_id:
                debug_logger.log_warning(
                    f"[BrowserCaptcha] 共享标签页池不可用，fallback 到传统模式 (project: {project_id})"
                )
                return await self._get_token_legacy(project_id, action)

            debug_logger.log_info(
                f"[BrowserCaptcha] ✅ 共享标签页可用 (slot={slot_id}, project={project_id}, use_count={resident_info.use_count}, "
                f"health={resident_info.health_score}, recent_tokens={len(resident_info.recent_token_timestamps)})"
            )

            if resident_info and resident_info.tab and self._is_resident_slot_rotation_due(resident_info):
                if resident_info.solve_lock.locked():
                    resident_info.solve_lock.release()
                debug_logger.log_info(
                    f"[BrowserCaptcha] 共享标签页达到指纹轮换阈值，准备重建 "
                    f"(slot={slot_id}, project={project_id}, use_count={resident_info.use_count}, "
                    f"max_use_count={self._resident_max_use_count})"
                )
                slot_id, resident_info = await self._rebuild_resident_tab(
                    project_id,
                    token_id=token_id,
                    slot_id=slot_id,
                    return_slot_key=True,
                )

            if resident_info and resident_info.tab and not resident_info.recaptcha_ready:
                if resident_info.solve_lock.locked():
                    resident_info.solve_lock.release()
                debug_logger.log_warning(
                    f"[BrowserCaptcha] 共享标签页未就绪，准备重建 cold slot={slot_id}, project={project_id}"
                )
                slot_id, resident_info = await self._rebuild_resident_tab(
                    project_id,
                    token_id=token_id,
                    slot_id=slot_id,
                    return_slot_key=True,
                )

            # 使用常驻标签页生成 token（在锁外执行，避免阻塞）
            if resident_info and resident_info.recaptcha_ready and resident_info.tab:
                start_time = time.time()
                debug_logger.log_info(
                    f"[BrowserCaptcha] 从共享常驻标签页即时生成 token (slot={slot_id}, project={project_id}, action={action})..."
                )
                try:
                    try:
                        token = await self._run_with_timeout(
                            self._execute_recaptcha_on_tab(resident_info.tab, action),
                            timeout_seconds=self._solve_timeout_seconds,
                            label=f"resident_solve:{slot_id}:{project_id}:{action}",
                        )
                    finally:
                        if resident_info.solve_lock.locked():
                            resident_info.solve_lock.release()
                    duration_ms = (time.time() - start_time) * 1000
                    if token:
                        resident_info.use_count += 1
                        self._mark_slot_token_issued(resident_info)
                        self._remember_project_affinity(project_id, slot_id, resident_info)
                        self._resident_error_streaks.pop(slot_id, None)
                        self._last_fingerprint = await self._extract_tab_fingerprint(resident_info.tab)
                        if isinstance(self._last_fingerprint, dict):
                            debug_logger.log_info(
                                "[BrowserCaptcha] token_success_fingerprint: "
                                f"slot={slot_id}, "
                                f"ua={str(self._last_fingerprint.get('user_agent') or '')[:160]}, "
                                f"accept_language={str(self._last_fingerprint.get('accept_language') or '')}, "
                                f"sec_ch_ua={str(self._last_fingerprint.get('sec_ch_ua') or '')[:220]}, "
                                f"sec_ch_ua_platform={str(self._last_fingerprint.get('sec_ch_ua_platform') or '')}, "
                                f"proxy={self._last_fingerprint.get('proxy_url')}"
                            )
                        debug_logger.log_info(
                            f"[BrowserCaptcha] ✅ Token生成成功（slot={slot_id}, 耗时 {duration_ms:.0f}ms, 使用次数: {resident_info.use_count}, "
                            f"recent_tokens={len(resident_info.recent_token_timestamps)}, health={resident_info.health_score}）"
                        )
                        self._schedule_standby_fill()
                        return token
                    else:
                        debug_logger.log_warning(
                            f"[BrowserCaptcha] 共享标签页生成失败 (slot={slot_id}, project={project_id})，尝试重建..."
                        )
                except Exception as e:
                    debug_logger.log_warning(f"[BrowserCaptcha] 共享标签页异常 (slot={slot_id}): {e}，尝试重建...")

                # 常驻标签页失效，尝试重建
                debug_logger.log_info(f"[BrowserCaptcha] 开始重建共享标签页 (slot={slot_id}, project={project_id})")
                slot_id, resident_info = await self._rebuild_resident_tab(
                    project_id,
                    token_id=token_id,
                    slot_id=slot_id,
                    return_slot_key=True,
                )
                debug_logger.log_info(f"[BrowserCaptcha] 共享标签页重建结束 (slot={slot_id}, project={project_id})")

                # 重建后立即尝试生成（在锁外执行）
                if resident_info:
                    try:
                        await asyncio.wait_for(
                            resident_info.solve_lock.acquire(),
                            timeout=max(1.0, min(3.0, self._slot_wait_timeout_seconds / 2)),
                        )
                        try:
                            token = await self._run_with_timeout(
                                self._execute_recaptcha_on_tab(resident_info.tab, action),
                                timeout_seconds=self._solve_timeout_seconds,
                                label=f"resident_resolve_after_rebuild:{slot_id}:{project_id}:{action}",
                            )
                        finally:
                            if resident_info.solve_lock.locked():
                                resident_info.solve_lock.release()
                        if token:
                            resident_info.use_count += 1
                            self._mark_slot_token_issued(resident_info)
                            self._remember_project_affinity(project_id, slot_id, resident_info)
                            self._resident_error_streaks.pop(slot_id, None)
                            self._last_fingerprint = await self._extract_tab_fingerprint(resident_info.tab)
                            if isinstance(self._last_fingerprint, dict):
                                debug_logger.log_info(
                                    "[BrowserCaptcha] token_success_fingerprint: "
                                    f"slot={slot_id}, "
                                    f"ua={str(self._last_fingerprint.get('user_agent') or '')[:160]}, "
                                    f"accept_language={str(self._last_fingerprint.get('accept_language') or '')}, "
                                    f"sec_ch_ua={str(self._last_fingerprint.get('sec_ch_ua') or '')[:220]}, "
                                    f"sec_ch_ua_platform={str(self._last_fingerprint.get('sec_ch_ua_platform') or '')}, "
                                    f"proxy={self._last_fingerprint.get('proxy_url')}"
                                )
                            debug_logger.log_info(f"[BrowserCaptcha] ✅ 重建后 Token生成成功 (slot={slot_id})")
                            self._schedule_standby_fill()
                            return token
                    except Exception:
                        pass

            # 最终 Fallback: 使用传统模式
            debug_logger.log_warning(f"[BrowserCaptcha] 所有常驻方式失败，fallback 到传统模式 (project: {project_id})")
            legacy_token = await self._get_token_legacy(project_id, action)
            if legacy_token:
                if slot_id:
                    self._resident_error_streaks.pop(slot_id, None)
            return legacy_token
        finally:
            self._leave_queue_gate()

    async def _create_resident_tab(
        self,
        slot_id: str,
        project_id: Optional[str] = None,
        token_id: Optional[int] = None,
    ) -> Optional[ResidentTabInfo]:
        """创建一个共享常驻打码标签页

        Args:
            slot_id: 共享标签页槽位 ID
            project_id: 触发创建的项目 ID，仅用于日志和最近映射

        Returns:
            ResidentTabInfo 对象，或 None（创建失败）
        """
        try:
            # 使用 Flow API 地址作为基础页面
            await self._await_browser_ready(timeout_seconds=15.0)
            website_url = "https://labs.google/fx/api/auth/providers"
            debug_logger.log_info(
                f"[BrowserCaptcha] 创建共享常驻标签页 slot={slot_id}, seed_project={project_id}, token_id={token_id}"
            )

            async with self._resident_lock:
                existing_tabs = [info.tab for info in self._resident_tabs.values() if info.tab]

            # 获取或创建标签页
            tabs = self.browser.tabs
            available_tab = None

            # 查找未被占用的标签页
            for tab in tabs:
                if tab not in existing_tabs:
                    available_tab = tab
                    break

            if available_tab:
                tab = available_tab
                debug_logger.log_info(f"[BrowserCaptcha] 复用未占用的标签页")
                await self._tab_get(
                    tab,
                    website_url,
                    label=f"resident_tab_get:{slot_id}",
                )
            else:
                debug_logger.log_info(f"[BrowserCaptcha] 创建新标签页")
                tab = await self._browser_get(
                    website_url,
                    label=f"resident_browser_get:{slot_id}",
                    new_tab=True,
                )

            # 等待页面加载完成（减少等待时间）
            page_loaded = False
            for retry in range(10):  # 减少到10次，最多5秒
                try:
                    await asyncio.sleep(0.5)
                    ready_state = await self._tab_evaluate(
                        tab,
                        "document.readyState",
                        label=f"resident_document_ready:{slot_id}",
                        timeout_seconds=2.0,
                    )
                    if ready_state == "complete":
                        page_loaded = True
                        debug_logger.log_info(f"[BrowserCaptcha] 页面已加载")
                        break
                except Exception as e:
                    debug_logger.log_warning(f"[BrowserCaptcha] 等待页面异常: {e}，重试 {retry + 1}/10...")
                    await asyncio.sleep(0.3)  # 减少重试间隔

            if not page_loaded:
                debug_logger.log_error(
                    f"[BrowserCaptcha] 页面加载超时 (slot={slot_id}, project={project_id}, token_id={token_id})"
                )
                await self._close_tab_quietly(tab)
                return None

            await self._apply_tab_fingerprint_profile(
                tab,
                label=f"resident_apply_fingerprint:{slot_id}",
            )

            # 等待 reCAPTCHA 加载
            recaptcha_ready = await self._wait_for_recaptcha(tab)

            if not recaptcha_ready:
                debug_logger.log_error(
                    f"[BrowserCaptcha] reCAPTCHA 加载失败 (slot={slot_id}, project={project_id}, token_id={token_id})"
                )
                await self._close_tab_quietly(tab)
                return None

            # 创建常驻信息对象
            resident_info = ResidentTabInfo(tab, slot_id, project_id=project_id, token_id=token_id)
            resident_info.recaptcha_ready = True

            debug_logger.log_info(
                f"[BrowserCaptcha] ✅ 共享常驻标签页创建成功 (slot={slot_id}, project={project_id}, token_id={token_id})"
            )
            return resident_info

        except Exception as e:
            debug_logger.log_error(
                f"[BrowserCaptcha] 创建共享常驻标签页异常 (slot={slot_id}, project={project_id}, token_id={token_id}): {e}"
            )
            return None

    async def _close_resident_tab(self, slot_id: str):
        """关闭指定 slot 的共享常驻标签页

        Args:
            slot_id: 共享标签页槽位 ID
        """
        async with self._resident_lock:
            resident_info = self._resident_tabs.pop(slot_id, None)
            self._forget_project_affinity_for_slot_locked(slot_id)
            self._resident_error_streaks.pop(slot_id, None)
            self._sync_compat_resident_state()

        if resident_info and resident_info.tab:
            try:
                await self._close_tab_quietly(resident_info.tab)
                debug_logger.log_info(f"[BrowserCaptcha] 已关闭共享常驻标签页 slot={slot_id}")
            except Exception as e:
                debug_logger.log_warning(f"[BrowserCaptcha] 关闭标签页时异常: {e}")

    async def invalidate_token(self, project_id: str):
        """当检测到 token 无效时调用，重建当前项目最近映射的共享标签页。

        Args:
            project_id: 项目 ID
        """
        debug_logger.log_warning(
            f"[BrowserCaptcha] Token 被标记为无效 (project: {project_id})，仅重建共享池中的对应标签页，避免清空全局浏览器状态"
        )

        # 重建标签页
        slot_id, resident_info = await self._rebuild_resident_tab(project_id, return_slot_key=True)
        if resident_info and slot_id:
            debug_logger.log_info(f"[BrowserCaptcha] ✅ 标签页已重建 (project: {project_id}, slot={slot_id})")
        else:
            debug_logger.log_error(f"[BrowserCaptcha] 标签页重建失败 (project: {project_id})")

    async def _get_token_legacy(self, project_id: str, action: str = "IMAGE_GENERATION") -> Optional[str]:
        """传统模式获取 reCAPTCHA token（每次创建新标签页）

        Args:
            project_id: Flow项目ID
            action: reCAPTCHA action类型 (IMAGE_GENERATION 或 VIDEO_GENERATION)

        Returns:
            reCAPTCHA token字符串，如果获取失败返回None
        """
        # 确保浏览器已启动
        if not self._initialized or not self.browser:
            await self.initialize()

        start_time = time.time()
        tab = None

        async with self._legacy_lock:
            try:
                website_url = "https://labs.google/fx/api/auth/providers"
                debug_logger.log_info(
                    f"[BrowserCaptcha] [Legacy] 创建独立临时标签页执行验证，避免污染 resident/custom 页面: {website_url}"
                )
                tab = await self._browser_get(
                    website_url,
                    label=f"legacy_browser_get:{project_id}",
                    new_tab=True,
                )

                # 等待页面完全加载（增加等待时间）
                debug_logger.log_info("[BrowserCaptcha] [Legacy] 等待页面加载...")
                await tab.sleep(3)

                # 等待页面 DOM 完成
                for _ in range(10):
                    ready_state = await self._tab_evaluate(
                        tab,
                        "document.readyState",
                        label=f"legacy_document_ready:{project_id}",
                        timeout_seconds=2.0,
                    )
                    if ready_state == "complete":
                        break
                    await tab.sleep(0.5)

                await self._apply_tab_fingerprint_profile(
                    tab,
                    label=f"legacy_apply_fingerprint:{project_id}",
                )

                # 等待 reCAPTCHA 加载
                recaptcha_ready = await self._wait_for_recaptcha(tab)

                if not recaptcha_ready:
                    debug_logger.log_error("[BrowserCaptcha] [Legacy] reCAPTCHA 无法加载")
                    return None

                # 执行 reCAPTCHA
                debug_logger.log_info(f"[BrowserCaptcha] [Legacy] 执行 reCAPTCHA 验证 (action: {action})...")
                token = await self._run_with_timeout(
                    self._execute_recaptcha_on_tab(tab, action),
                    timeout_seconds=self._solve_timeout_seconds,
                    label=f"legacy_solve:{project_id}:{action}",
                )

                duration_ms = (time.time() - start_time) * 1000

                if token:
                    self._last_fingerprint = await self._extract_tab_fingerprint(tab)
                    if isinstance(self._last_fingerprint, dict):
                        debug_logger.log_info(
                            "[BrowserCaptcha] token_success_fingerprint: "
                            f"slot=legacy:{project_id}, "
                            f"ua={str(self._last_fingerprint.get('user_agent') or '')[:160]}, "
                            f"accept_language={str(self._last_fingerprint.get('accept_language') or '')}, "
                            f"sec_ch_ua={str(self._last_fingerprint.get('sec_ch_ua') or '')[:220]}, "
                            f"sec_ch_ua_platform={str(self._last_fingerprint.get('sec_ch_ua_platform') or '')}, "
                            f"proxy={self._last_fingerprint.get('proxy_url')}"
                        )
                    debug_logger.log_info(f"[BrowserCaptcha] [Legacy] ✅ Token获取成功（耗时 {duration_ms:.0f}ms）")
                    return token

                debug_logger.log_error("[BrowserCaptcha] [Legacy] Token获取失败（返回null）")
                return None

            except Exception as e:
                debug_logger.log_error(f"[BrowserCaptcha] [Legacy] 获取token异常: {str(e)}")
                return None
            finally:
                # 关闭 legacy 临时标签页（但保留浏览器）
                if tab:
                    await self._close_tab_quietly(tab)

    def get_last_fingerprint(self) -> Optional[Dict[str, Any]]:
        """返回最近一次打码时的浏览器指纹快照。"""
        if not self._last_fingerprint:
            return None
        return dict(self._last_fingerprint)

    async def _clear_browser_cache(self):
        """清理浏览器全部缓存"""
        if not self.browser:
            return

        try:
            debug_logger.log_info("[BrowserCaptcha] 开始清理浏览器缓存...")

            # 使用 Chrome DevTools Protocol 清理缓存
            # 清理所有类型的缓存数据
            await self._browser_send_command(
                "Network.clearBrowserCache",
                label="clear_browser_cache",
            )

            # 清理 Cookies
            await self._browser_send_command(
                "Network.clearBrowserCookies",
                label="clear_browser_cookies",
            )

            # 清理存储数据（localStorage, sessionStorage, IndexedDB 等）
            await self._browser_send_command(
                "Storage.clearDataForOrigin",
                {
                    "origin": "https://www.google.com",
                    "storageTypes": "all"
                },
                label="clear_browser_origin_storage",
            )

            debug_logger.log_info("[BrowserCaptcha] ✅ 浏览器缓存已清理")

        except Exception as e:
            debug_logger.log_warning(f"[BrowserCaptcha] 清理缓存时异常: {e}")

    async def _shutdown_browser_runtime(self, cancel_idle_reaper: bool = False, reason: str = "shutdown"):
        if cancel_idle_reaper and self._idle_reaper_task and not self._idle_reaper_task.done():
            self._idle_reaper_task.cancel()
            try:
                await self._idle_reaper_task
            except asyncio.CancelledError:
                pass
            finally:
                self._idle_reaper_task = None

        async with self._browser_lock:
            try:
                await self._shutdown_browser_runtime_locked(reason=reason)
                debug_logger.log_info(f"[BrowserCaptcha] 浏览器运行态已清理 ({reason})")
            except Exception as e:
                debug_logger.log_error(f"[BrowserCaptcha] 清理浏览器运行态异常 ({reason}): {str(e)}")

    async def close(self):
        """关闭浏览器"""
        await self._shutdown_browser_runtime(cancel_idle_reaper=True, reason="service_close")

    async def open_login_window(self):
        """打开登录窗口供用户手动登录 Google"""
        await self.initialize()
        tab = await self._browser_get(
            "https://accounts.google.com/",
            label="open_login_window",
            new_tab=True,
        )
        debug_logger.log_info("[BrowserCaptcha] 请在打开的浏览器中登录账号。登录完成后，无需关闭浏览器，脚本下次运行时会自动使用此状态。")
        print("请在打开的浏览器中登录账号。登录完成后，无需关闭浏览器，脚本下次运行时会自动使用此状态。")

    # ========== Session Token 刷新 ==========

    async def refresh_session_token(self, project_id: str) -> Optional[str]:
        """从常驻标签页获取最新的 Session Token
        
        复用共享打码标签页，通过刷新页面并从 cookies 中提取
        __Secure-next-auth.session-token
        
        Args:
            project_id: 项目ID，用于定位常驻标签页
            
        Returns:
            新的 Session Token，如果获取失败返回 None
        """
        # 确保浏览器已初始化
        await self.initialize()
        
        start_time = time.time()
        debug_logger.log_info(f"[BrowserCaptcha] 开始刷新 Session Token (project: {project_id})...")

        async with self._resident_lock:
            slot_id = self._resolve_affinity_slot_locked(project_id)
            resident_info = self._resident_tabs.get(slot_id) if slot_id else None

        if resident_info is None or not slot_id:
            slot_id, resident_info = await self._ensure_resident_tab(project_id, return_slot_key=True)

        if resident_info is None or not slot_id:
            debug_logger.log_warning(f"[BrowserCaptcha] 无法为 project_id={project_id} 获取共享常驻标签页")
            return None
        
        if not resident_info or not resident_info.tab:
            debug_logger.log_error(f"[BrowserCaptcha] 无法获取常驻标签页")
            return None
        
        tab = resident_info.tab
        
        try:
            async with resident_info.solve_lock:
                # 刷新页面以获取最新的 cookies
                debug_logger.log_info(f"[BrowserCaptcha] 刷新常驻标签页以获取最新 cookies...")
                resident_info.recaptcha_ready = False
                await self._run_with_timeout(
                    self._tab_reload(
                        tab,
                        label=f"refresh_session_reload:{slot_id}",
                    ),
                    timeout_seconds=self._session_refresh_timeout_seconds,
                    label=f"refresh_session_reload_total:{slot_id}",
                )
                
                # 等待页面加载完成
                for i in range(30):
                    await asyncio.sleep(1)
                    try:
                        ready_state = await self._tab_evaluate(
                            tab,
                            "document.readyState",
                            label=f"refresh_session_ready_state:{slot_id}",
                            timeout_seconds=2.0,
                        )
                        if ready_state == "complete":
                            break
                    except Exception:
                        pass

                await self._apply_tab_fingerprint_profile(
                    tab,
                    label=f"refresh_session_apply_fingerprint:{slot_id}",
                )

                resident_info.recaptcha_ready = await self._wait_for_recaptcha(tab)
                if not resident_info.recaptcha_ready:
                    debug_logger.log_warning(
                        f"[BrowserCaptcha] 刷新 Session Token 后 reCAPTCHA 未恢复就绪 (slot={slot_id})"
                    )
                
                # 额外等待确保 cookies 已设置
                await asyncio.sleep(2)
                
                # 从 cookies 中提取 __Secure-next-auth.session-token
                # nodriver 可以通过 browser 获取 cookies
                session_token = None
                
                try:
                    # 使用 nodriver 的 cookies API 获取所有 cookies
                    cookies = await self._get_browser_cookies(
                        label=f"refresh_session_get_cookies:{slot_id}",
                    )
                    
                    for cookie in cookies:
                        if cookie.name == "__Secure-next-auth.session-token":
                            session_token = cookie.value
                            break
                            
                except Exception as e:
                    debug_logger.log_warning(f"[BrowserCaptcha] 通过 cookies API 获取失败: {e}，尝试从 document.cookie 获取...")
                    
                    # 备选方案：通过 JavaScript 获取 (注意：HttpOnly cookies 可能无法通过此方式获取)
                    try:
                        all_cookies = await self._tab_evaluate(
                            tab,
                            "document.cookie",
                            label=f"refresh_session_document_cookie:{slot_id}",
                        )
                        if all_cookies:
                            for part in all_cookies.split(";"):
                                part = part.strip()
                                if part.startswith("__Secure-next-auth.session-token="):
                                    session_token = part.split("=", 1)[1]
                                    break
                    except Exception as e2:
                        debug_logger.log_error(f"[BrowserCaptcha] document.cookie 获取失败: {e2}")
            
            duration_ms = (time.time() - start_time) * 1000
            
            if session_token:
                resident_info.last_used_at = time.time()
                self._remember_project_affinity(project_id, slot_id, resident_info)
                self._resident_error_streaks.pop(slot_id, None)
                debug_logger.log_info(f"[BrowserCaptcha] ✅ Session Token 获取成功（耗时 {duration_ms:.0f}ms）")
                return session_token
            else:
                debug_logger.log_error(f"[BrowserCaptcha] ❌ 未找到 __Secure-next-auth.session-token cookie")
                return None
                
        except Exception as e:
            debug_logger.log_error(f"[BrowserCaptcha] 刷新 Session Token 异常: {str(e)}")
            
            # 共享标签页可能已失效，尝试重建
            slot_id, resident_info = await self._rebuild_resident_tab(project_id, slot_id=slot_id, return_slot_key=True)
            if resident_info and slot_id:
                # 重建后再次尝试获取
                try:
                    async with resident_info.solve_lock:
                        cookies = await self._get_browser_cookies(
                            label=f"refresh_session_get_cookies_after_rebuild:{slot_id}",
                        )
                    for cookie in cookies:
                        if cookie.name == "__Secure-next-auth.session-token":
                            resident_info.last_used_at = time.time()
                            self._remember_project_affinity(project_id, slot_id, resident_info)
                            self._resident_error_streaks.pop(slot_id, None)
                            debug_logger.log_info(f"[BrowserCaptcha] ✅ 重建后 Session Token 获取成功")
                            return cookie.value
                except Exception:
                    pass
            
            return None

    # ========== 状态查询 ==========

    def is_resident_mode_active(self) -> bool:
        """检查是否有任何常驻标签页激活"""
        return len(self._resident_tabs) > 0 or self._running

    def get_resident_count(self) -> int:
        """获取当前常驻标签页数量"""
        return len(self._resident_tabs)

    def get_resident_project_ids(self) -> list[str]:
        """获取所有当前共享常驻标签页的 slot_id 列表。"""
        return list(self._resident_tabs.keys())

    def get_resident_project_id(self) -> Optional[str]:
        """获取当前共享池中的第一个 slot_id（向后兼容）。"""
        if self._resident_tabs:
            return next(iter(self._resident_tabs.keys()))
        return self.resident_project_id

    async def get_custom_token(
        self,
        website_url: str,
        website_key: str,
        action: str = "homepage",
        enterprise: bool = False,
    ) -> Optional[str]:
        """为任意站点执行 reCAPTCHA，用于分数测试等场景。

        与普通 legacy 模式不同，这里会复用同一个常驻标签页，避免每次冷启动新 tab。
        """
        await self.initialize()
        self._last_fingerprint = None

        cache_key = f"{website_url}|{website_key}|{1 if enterprise else 0}"
        warmup_seconds = float(getattr(config, "browser_score_test_warmup_seconds", 12) or 12)
        per_request_settle_seconds = float(
            getattr(config, "browser_score_test_settle_seconds", 2.5) or 2.5
        )
        max_retries = 2

        async with self._custom_lock:
            for attempt in range(max_retries):
                start_time = time.time()
                custom_info = self._custom_tabs.get(cache_key)
                tab = custom_info.get("tab") if isinstance(custom_info, dict) else None

                try:
                    if tab is None:
                        debug_logger.log_info(f"[BrowserCaptcha] [Custom] 创建常驻测试标签页: {website_url}")
                        tab = await self._browser_get(
                            website_url,
                            label="custom_browser_get",
                            new_tab=True,
                        )
                        custom_info = {
                            "tab": tab,
                            "recaptcha_ready": False,
                            "warmed_up": False,
                            "created_at": time.time(),
                        }
                        self._custom_tabs[cache_key] = custom_info

                    page_loaded = False
                    for _ in range(20):
                        ready_state = await self._tab_evaluate(
                            tab,
                            "document.readyState",
                            label="custom_document_ready",
                            timeout_seconds=2.0,
                        )
                        if ready_state == "complete":
                            page_loaded = True
                            break
                        await tab.sleep(0.5)

                    if not page_loaded:
                        raise RuntimeError("自定义页面加载超时")

                    await self._apply_tab_fingerprint_profile(
                        tab,
                        label="custom_apply_fingerprint",
                    )

                    if not custom_info.get("recaptcha_ready"):
                        recaptcha_ready = await self._wait_for_custom_recaptcha(
                            tab=tab,
                            website_key=website_key,
                            enterprise=enterprise,
                        )
                        if not recaptcha_ready:
                            raise RuntimeError("自定义 reCAPTCHA 无法加载")
                        custom_info["recaptcha_ready"] = True

                    try:
                        await self._tab_evaluate(tab, """
                            (() => {
                                try {
                                    const body = document.body || document.documentElement;
                                    const width = window.innerWidth || 1280;
                                    const height = window.innerHeight || 720;
                                    const x = Math.max(24, Math.floor(width * 0.38));
                                    const y = Math.max(24, Math.floor(height * 0.32));
                                    const moveEvent = new MouseEvent('mousemove', {
                                        bubbles: true,
                                        clientX: x,
                                        clientY: y
                                    });
                                    const overEvent = new MouseEvent('mouseover', {
                                        bubbles: true,
                                        clientX: x,
                                        clientY: y
                                    });
                                    window.focus();
                                    window.dispatchEvent(new Event('focus'));
                                    document.dispatchEvent(moveEvent);
                                    document.dispatchEvent(overEvent);
                                    if (body) {
                                        body.dispatchEvent(moveEvent);
                                        body.dispatchEvent(overEvent);
                                    }
                                    window.scrollTo(0, Math.min(320, document.body?.scrollHeight || 320));
                                } catch (e) {}
                            })()
                        """, label="custom_pre_warm_interaction", timeout_seconds=6.0)
                    except Exception:
                        pass

                    if not custom_info.get("warmed_up"):
                        if warmup_seconds > 0:
                            debug_logger.log_info(
                                f"[BrowserCaptcha] [Custom] 首次预热测试页面 {warmup_seconds:.1f}s 后再执行 token"
                            )
                            try:
                                await self._tab_evaluate(tab, """
                                    (() => {
                                        try {
                                            window.scrollTo(0, Math.min(240, document.body.scrollHeight || 240));
                                            window.dispatchEvent(new Event('mousemove'));
                                            window.dispatchEvent(new Event('focus'));
                                        } catch (e) {}
                                    })()
                                """, label="custom_warmup_interaction", timeout_seconds=6.0)
                            except Exception:
                                pass
                            await tab.sleep(warmup_seconds)
                        custom_info["warmed_up"] = True
                    elif per_request_settle_seconds > 0:
                        debug_logger.log_info(
                            f"[BrowserCaptcha] [Custom] 复用测试标签页，执行前额外等待 {per_request_settle_seconds:.1f}s"
                        )
                        await tab.sleep(per_request_settle_seconds)

                    debug_logger.log_info(f"[BrowserCaptcha] [Custom] 使用常驻测试标签页执行验证 (action: {action})...")
                    token = await self._execute_custom_recaptcha_on_tab(
                        tab=tab,
                        website_key=website_key,
                        action=action,
                        enterprise=enterprise,
                    )

                    duration_ms = (time.time() - start_time) * 1000
                    if token:
                        extracted_fingerprint = await self._extract_tab_fingerprint(tab)
                        if not extracted_fingerprint:
                            try:
                                fallback_ua = await self._tab_evaluate(
                                    tab,
                                    "navigator.userAgent || ''",
                                    label="custom_fallback_ua",
                                )
                                fallback_lang = await self._tab_evaluate(
                                    tab,
                                    "navigator.language || ''",
                                    label="custom_fallback_lang",
                                )
                                extracted_fingerprint = {
                                    "user_agent": fallback_ua or "",
                                    "accept_language": fallback_lang or "",
                                    "proxy_url": self._proxy_url,
                                }
                                extracted_fingerprint = self._normalize_fingerprint_payload(extracted_fingerprint)
                                extracted_fingerprint["proxy_url"] = self._proxy_url
                            except Exception:
                                extracted_fingerprint = None
                        self._last_fingerprint = extracted_fingerprint
                        debug_logger.log_info(
                            f"[BrowserCaptcha] [Custom] ✅ 常驻测试标签页 Token获取成功（耗时 {duration_ms:.0f}ms）"
                        )
                        return token

                    raise RuntimeError("自定义 token 获取失败（返回 null）")
                except Exception as e:
                    debug_logger.log_warning(
                        f"[BrowserCaptcha] [Custom] 尝试 {attempt + 1}/{max_retries} 失败: {str(e)}"
                    )
                    stale_info = self._custom_tabs.pop(cache_key, None)
                    stale_tab = stale_info.get("tab") if isinstance(stale_info, dict) else None
                    if stale_tab:
                        await self._close_tab_quietly(stale_tab)
                    if attempt >= max_retries - 1:
                        debug_logger.log_error(f"[BrowserCaptcha] [Custom] 获取token异常: {str(e)}")
                        return None

            return None

    async def get_custom_score(
        self,
        website_url: str,
        website_key: str,
        verify_url: str,
        action: str = "homepage",
        enterprise: bool = False,
    ) -> Dict[str, Any]:
        """在同一个常驻标签页里获取 token 并直接校验页面分数。"""
        token_started_at = time.time()
        token = await self.get_custom_token(
            website_url=website_url,
            website_key=website_key,
            action=action,
            enterprise=enterprise,
        )
        token_elapsed_ms = int((time.time() - token_started_at) * 1000)

        if not token:
            return {
                "token": None,
                "token_elapsed_ms": token_elapsed_ms,
                "verify_mode": "browser_page",
                "verify_elapsed_ms": 0,
                "verify_http_status": None,
                "verify_result": {},
            }

        cache_key = f"{website_url}|{website_key}|{1 if enterprise else 0}"
        async with self._custom_lock:
            custom_info = self._custom_tabs.get(cache_key)
            tab = custom_info.get("tab") if isinstance(custom_info, dict) else None
            if tab is None:
                raise RuntimeError("页面分数测试标签页不存在")
            verify_payload = await self._verify_score_on_tab(tab, token, verify_url)

        return {
            "token": token,
            "token_elapsed_ms": token_elapsed_ms,
            **verify_payload,
        }
