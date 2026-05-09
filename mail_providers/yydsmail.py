"""YYDS Mail (vip.215.im) 临时邮箱服务"""
import re
import time
import secrets

from .base import MailProvider


class YYDSMailProvider(MailProvider):

    name = "yydsmail"
    display_name = "YYDS Mail"

    def __init__(self, base_url: str = "", api_key: str = "", domain: str = ""):
        from curl_cffi import requests as curl_requests
        self.base_url = (base_url or "https://maliapi.215.im").rstrip("/")
        self.api_key = api_key
        self.default_domain = domain
        self.session = curl_requests.Session(impersonate="chrome131")
        self.session.verify = False
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.mailbox_id = None
        self.address = None
        self.token = None

    def create_mailbox(self) -> str:
        local_part = "k" + secrets.token_hex(7)
        body = {"localPart": local_part}
        if self.default_domain:
            body["domain"] = self.default_domain

        resp = self.session.post(
            f"{self.base_url}/v1/accounts",
            headers=self.headers,
            json=body,
            timeout=15,
        )
        data = resp.json()
        if not data.get("success"):
            raise RuntimeError(f"YYDS Mail 创建邮箱失败: {data.get('error', data)}")
        d = data["data"]
        self.mailbox_id = d["id"]
        self.address = d["address"]
        self.token = d["token"]
        return self.address

    def wait_otp(self, timeout: int = 120, poll_interval: int = 3) -> str:
        if not self.token:
            return ""
        token_headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        deadline = time.time() + timeout
        seen_ids = set()

        while time.time() < deadline:
            resp = self.session.get(
                f"{self.base_url}/v1/messages",
                headers=token_headers,
                params={"address": self.address},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    messages = data["data"].get("messages", [])
                    for msg in messages:
                        msg_id = msg["id"]
                        if msg_id in seen_ids:
                            continue
                        seen_ids.add(msg_id)

                        # Check subject first (fast path)
                        subject = msg.get("subject", "")
                        m = re.search(r'\b(\d{6})\b', subject)
                        if m:
                            return m.group(1)

                        # Get message detail for body text
                        detail_resp = self.session.get(
                            f"{self.base_url}/v1/messages/{msg_id}",
                            headers=token_headers,
                            params={"address": self.address},
                            timeout=10,
                        )
                        if detail_resp.status_code != 200:
                            continue
                        detail = detail_resp.json()
                        if not detail.get("success"):
                            continue
                        msg_data = detail["data"]
                        text = msg_data.get("text", "") or ""
                        html = " ".join(msg_data.get("html", [])) if isinstance(msg_data.get("html"), list) else (msg_data.get("html", "") or "")

                        combined = f"{text} {html}"
                        m = re.search(r'\b(\d{6})\b', combined)
                        if m:
                            return m.group(1)

                        # Fallback: try raw source
                        src_resp = self.session.get(
                            f"{self.base_url}/v1/sources/{msg_id}",
                            headers=token_headers,
                            params={"address": self.address},
                            timeout=10,
                        )
                        if src_resp.status_code == 200:
                            src_data = src_resp.json()
                            if src_data.get("success"):
                                raw = src_data["data"].get("data", "")
                                m = re.search(r'\b(\d{6})\b', raw)
                                if m:
                                    return m.group(1)
            time.sleep(poll_interval)
        return ""

    def list_domains(self) -> list[dict]:
        resp = self.session.get(
            f"{self.base_url}/v1/domains",
            headers=self.headers,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success"):
                domains = data.get("data", {}).get("domains", [])
                if isinstance(domains, list):
                    return [
                        {"id": d.get("domain", d.get("id", "")), "domain": d.get("domain", d.get("name", ""))}
                        for d in domains
                    ]
        return []
