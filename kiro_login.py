"""
Kiro 手动登录模块 - 通过浏览器交互式登录并获取 Token
支持: Google, Github, AWS Builder ID, IAM Identity Center
"""
import asyncio
import base64
import hashlib
import json
import os
import secrets
import socket
import stat
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse


# 常量 (与 main.py 共享)
REG_OIDC = "https://oidc.us-east-1.amazonaws.com"
REG_SCOPES = [
    "codewhisperer:completions", "codewhisperer:analysis",
    "codewhisperer:conversations", "codewhisperer:transformations",
    "codewhisperer:taskassist",
]
REG_REDIRECT_URI = "http://127.0.0.1:3128"
KIRO_SIGNIN_URL = "https://app.kiro.dev/signin"
ISSUER_URL = "https://view.awsapps.com/start/"
REG_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _sha1_hash(value: str) -> str:
    return hashlib.sha1(value.encode()).hexdigest()


def clear_old_session(log=print):
    """清除旧的 AWS SSO 登录数据"""
    cache_dir = Path.home() / ".aws" / "sso" / "cache"
    if not cache_dir.exists():
        return
    for f in cache_dir.iterdir():
        if f.name.startswith("kiro-") or f.suffix == ".json":
            try:
                f.unlink()
                log(f"  已删除: {f.name}", "dbg")
            except Exception:
                pass
    log("旧登录数据已清除", "ok")


def persist_tokens(client_id, client_secret, access_token, refresh_token, expires_in, log=print):
    """写入 token 到本地实现自动登录"""
    cache_dir = Path.home() / ".aws" / "sso" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    client_id_hash = _sha1_hash(client_id)
    expires_at_str = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    token_data = {
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": expires_at_str,
        "clientIdHash": client_id_hash,
        "authMethod": "IdC",
        "provider": "BuilderId",
        "region": "us-east-1",
    }
    token_path = cache_dir / "kiro-auth-token.json"
    token_path.write_text(json.dumps(token_data, indent=2), encoding="utf-8")
    try:
        os.chmod(token_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    log("Token 已写入本地", "ok")

    client_data = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "expiresAt": (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }
    client_path = cache_dir / f"{client_id_hash}.json"
    client_path.write_text(json.dumps(client_data, indent=2), encoding="utf-8")
    try:
        os.chmod(client_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    log("客户端信息已保存", "ok")


async def manual_login(method, headless=False, auto_login=True, clear_session=True,
                       log=print, cancel_check=None):
    """
    打开浏览器让用户手动登录，获取 OAuth token 并导入。

    Args:
        method: 登录方式 ("google", "github", "builderid", "iam")
        headless: 是否无头模式 (手动登录通常为 False)
        auto_login: 是否注入本地 token
        clear_session: 是否清除旧登录数据
        log: 日志回调 log(msg, level)
        cancel_check: 取消检查回调，返回 True 表示取消
    Returns:
        dict with account info or None
    """
    from curl_cffi import requests as curl_requests
    from playwright.async_api import async_playwright
    from playwright_stealth import Stealth

    if cancel_check and cancel_check():
        return None

    if clear_session:
        log("清除旧登录数据...", "info")
        clear_old_session(log)

    s = curl_requests.Session(impersonate="chrome131")

    # Phase 1: OIDC 客户端注册
    log("Phase 1: OIDC 客户端注册", "info")
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    state_val = secrets.token_urlsafe(32)

    reg_resp = s.post(f"{REG_OIDC}/client/register", json={
        "clientName": "Kiro IDE", "clientType": "public",
        "grantTypes": ["authorization_code", "refresh_token"],
        "issuerUrl": ISSUER_URL,
        "redirectUris": [REG_REDIRECT_URI], "scopes": REG_SCOPES,
    }, timeout=25, verify=False)
    reg = reg_resp.json()
    if "clientId" not in reg:
        log(f"OIDC register failed: {reg}", "err")
        return None
    client_id = reg["clientId"]
    client_secret = reg["clientSecret"]
    log("OIDC 客户端注册成功", "ok")

    signin_url = f"{KIRO_SIGNIN_URL}?" + urlencode({
        "state": state_val,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REG_REDIRECT_URI,
        "redirect_from": "KiroIDE",
    })

    # Phase 2: 本地回调服务器 + 浏览器
    log(f"Phase 2: 启动浏览器 (headless={headless})", "info")
    authorization_code = ""

    class ReuseHTTPServer(HTTPServer):
        allow_reuse_address = True

    class CallbackHandler(BaseHTTPRequestHandler):
        signin_callback_params = {}

        def do_GET(self_h):
            nonlocal authorization_code
            parsed = urlparse(self_h.path)
            qs = parse_qs(parsed.query)
            code = qs.get("code", [""])[0]
            if code:
                authorization_code = code
                log("已收到授权回调", "ok")
                self_h.send_response(200)
                self_h.send_header("Content-Type", "text/html")
                self_h.end_headers()
                self_h.wfile.write(b"<html><body><h2>Login complete!</h2></body></html>")
            elif "signin/callback" in parsed.path or qs.get("login_option"):
                CallbackHandler.signin_callback_params = {k: v[0] for k, v in qs.items()}
                log("收到登录回调", "ok")
                self_h.send_response(200)
                self_h.send_header("Content-Type", "text/html")
                self_h.end_headers()
                self_h.wfile.write(b"<html><body><p>Redirecting...</p></body></html>")
            else:
                self_h.send_response(200)
                self_h.send_header("Content-Type", "text/html")
                self_h.end_headers()
                self_h.wfile.write(b"<html><body><p>OK</p></body></html>")

        def log_message(self_h, *args):
            pass

    # 确保端口可用
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", 3128))
        sock.close()
    except OSError:
        sock.close()
        try:
            import subprocess
            r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if ":3128" in line and "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    if pid.isdigit() and int(pid) != os.getpid():
                        subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
            await asyncio.sleep(1)
        except Exception:
            pass

    callback_server = ReuseHTTPServer(("127.0.0.1", 3128), CallbackHandler)
    callback_server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_thread = threading.Thread(target=callback_server.serve_forever, daemon=True)
    srv_thread.start()
    log("本地回调服务器已启动 (127.0.0.1:3128)", "ok")

    try:
        async with async_playwright() as p:
            launch_args = [
                "--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process",
                "--no-first-run",
            ]
            if headless:
                launch_args += ["--disable-gpu", "--no-sandbox",
                                "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            browser = await p.chromium.launch(headless=headless, args=launch_args, executable_path="/usr/bin/chromium")
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800}, locale="en-US", user_agent=REG_UA)
            page = await context.new_page()
            await Stealth().apply_stealth_async(page)

            await page.goto(signin_url, timeout=60000)
            await page.wait_for_load_state("networkidle", timeout=30000)
            await asyncio.sleep(3)

            # 点击对应登录方式按钮
            if "app.kiro.dev" in page.url:
                log("在 Kiro 登录页，选择登录方式...", "info")
                await asyncio.sleep(2)
                await _click_login_method(page, method, log)

                for _ in range(20):
                    if CallbackHandler.signin_callback_params:
                        break
                    await asyncio.sleep(1)

            # 构造 OIDC authorize URL
            if CallbackHandler.signin_callback_params and not authorization_code:
                log("构造 OIDC authorize URL...", "info")
                authorize_url = f"{REG_OIDC}/authorize?" + urlencode({
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": REG_REDIRECT_URI,
                    "scopes": ",".join(REG_SCOPES),
                    "state": state_val,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                })
                await page.goto(authorize_url, timeout=60000)
                await page.wait_for_load_state("networkidle", timeout=30000)
                await asyncio.sleep(3)

            # 等待用户在浏览器中完成登录 (最长 5 分钟)
            log("Phase 3: 请在浏览器中完成登录...", "info")
            log("等待用户操作 (最长 5 分钟)...", "info")

            for i in range(150):
                if cancel_check and cancel_check():
                    log("用户取消", "err")
                    await browser.close()
                    return None
                if authorization_code:
                    break
                current_url = page.url
                # 检查回调 URL
                if "127.0.0.1:3128" in current_url or "localhost:3128" in current_url:
                    qs = parse_qs(urlparse(current_url).query)
                    authorization_code = qs.get("code", [""])[0]
                    if authorization_code:
                        break
                if "code=" in current_url and "code_challenge" not in current_url:
                    qs = parse_qs(urlparse(current_url).query)
                    code_val = qs.get("code", [""])[0]
                    if code_val and len(code_val) > 10:
                        authorization_code = code_val
                        break
                # 自动点击授权按钮
                if "awsapps.com" in current_url:
                    try:
                        await page.evaluate("""() => {
                            const buttons = Array.from(document.querySelectorAll('button'));
                            const visible = buttons.filter(b => b.offsetWidth > 0);
                            for (const b of visible) {
                                const t = (b.innerText || '').toLowerCase();
                                if (t.includes('allow') || t.includes('authorize') || t.includes('accept') || t.includes('confirm')) {
                                    b.click(); return;
                                }
                            }
                            if (visible.length > 0) visible[visible.length - 1].click();
                        }""")
                    except Exception:
                        pass
                if i > 0 and i % 30 == 0:
                    log(f"仍在等待... ({i*2}s)", "dbg")
                await asyncio.sleep(2)

            await browser.close()
    finally:
        callback_server.shutdown()

    # Phase 4: Token 交换
    if not authorization_code:
        log("未获取到授权码!", "err")
        return None

    log(f"已获取授权码", "ok")
    log("Phase 4: 交换 Token...", "info")

    token_resp = s.post(f"{REG_OIDC}/token", json={
        "clientId": client_id,
        "clientSecret": client_secret,
        "grantType": "authorization_code",
        "code": authorization_code,
        "redirectUri": REG_REDIRECT_URI,
        "codeVerifier": code_verifier,
    }, timeout=25, verify=False)

    if token_resp.status_code != 200:
        log(f"Token 交换失败: HTTP {token_resp.status_code}", "err")
        return None

    tokens = token_resp.json()
    access_token = tokens.get("accessToken", "")
    refresh_token = tokens.get("refreshToken", "")
    expires_in = tokens.get("expiresIn", 28800)

    if not access_token:
        log(f"Token 交换未返回 accessToken", "err")
        return None

    log("Token 获取成功", "ok")
    log(f"expires_in: {expires_in}s", "ok")

    # 从 JWT 提取用户邮箱
    user_email = _extract_email_from_token(access_token)
    if not user_email:
        user_email = f"{method}_user_{secrets.token_hex(4)}"
    log(f"用户: {user_email}", "ok")

    # 注入本地 Token
    if auto_login:
        log("注入本地 Token...", "info")
        persist_tokens(client_id, client_secret, access_token, refresh_token, expires_in, log)

    log("=" * 40, "ok")
    log("登录导入完成!", "ok")
    log(f"  用户: {user_email}", "ok")
    log("=" * 40, "ok")

    return {
        "email": user_email,
        "password": "",
        "provider": "BuilderId",
        "authMethod": "IdC",
        "region": "us-east-1",
        "clientId": client_id,
        "clientSecret": client_secret,
        "clientIdHash": _sha1_hash(client_id),
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).strftime("%Y/%m/%d %H:%M:%S"),
    }


async def _click_login_method(page, method, log):
    """点击 Kiro 登录页上对应的登录方式按钮"""
    method_selectors = {
        "google": [
            'xpath=//button[contains(text(),"Google")]',
            'xpath=//a[contains(text(),"Google")]',
        ],
        "github": [
            'xpath=//button[contains(text(),"GitHub")]',
            'xpath=//button[contains(text(),"Github")]',
            'xpath=//a[contains(text(),"GitHub")]',
        ],
        "builderid": [
            'xpath=//*[@id="layout-viewport"]/div/div/div/div[2]/div/div[1]/button[3]',
            'xpath=//button[contains(text(),"AWS Builder ID")]',
            'xpath=//button[contains(text(),"Builder ID")]',
        ],
        "iam": [
            'xpath=//button[contains(text(),"IAM Identity Center")]',
            'xpath=//button[contains(text(),"Identity Center")]',
        ],
    }

    selectors = method_selectors.get(method, method_selectors["builderid"])
    for sel in selectors:
        loc = page.locator(sel)
        try:
            if await loc.count() > 0 and await loc.first.is_visible():
                await loc.first.click()
                log(f"已点击 {method} 登录按钮", "ok")
                await asyncio.sleep(3)
                return
        except Exception:
            pass

    # Fallback
    for sel in ['xpath=//button[contains(text(),"Sign in")]',
                'xpath=//button[contains(text(),"Continue")]']:
        loc = page.locator(sel)
        try:
            if await loc.count() > 0 and await loc.first.is_visible():
                await loc.first.click()
                log(f"已点击备选登录按钮", "ok")
                await asyncio.sleep(3)
                return
        except Exception:
            pass

    # JS fallback
    try:
        await page.evaluate("""() => {
            const btn = document.querySelector('#layout-viewport button:nth-child(3)') ||
                        document.querySelectorAll('#layout-viewport button')[2];
            if (btn) btn.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true}));
        }""")
        await asyncio.sleep(3)
    except Exception:
        pass


def _extract_email_from_token(access_token):
    """从 JWT access_token 中提取邮箱"""
    try:
        payload_b64 = access_token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("email", "") or payload.get("sub", "") or payload.get("username", "")
    except Exception:
        return ""
