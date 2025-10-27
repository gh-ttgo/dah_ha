from __future__ import annotations

import re
import base64
import logging

import aiohttp

from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import INDEX_PAGE, LOGIN_ENDPOINT, API_BASE

_LOGGER = logging.getLogger(__name__)


class AuthError(Exception):
    pass

class DAHDataUpdateCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, username: str, password: str):
        super().__init__(
            hass,
            _LOGGER,
            name="dahsolar",
            update_interval=timedelta(minutes=1),  # or timedelta(seconds=60)
        )
        self.hass = hass
        self.username = username
        self.password = password
        self._session = None
        self._token = None
        self._station_id = None


    async def async_prepare(self) -> None:
        await self._ensure_session()
        await self.login()

    async def _ensure_session(self) -> None:
        if self._session is None:
            self._session = aiohttp.ClientSession()

    async def _fetch_public_key(self) -> str:
        await self._ensure_session()
        _LOGGER.debug("Fetching index page for public key")
        async with self._session.get(INDEX_PAGE) as resp:
            index_html = await resp.text()
        js_paths = re.findall(r'src="(/static/js/[^"]+\.js)"', index_html)
        _LOGGER.debug("Found js bundles: %s", js_paths)
        if not js_paths:
            raise AuthError("Could not find any js bundles in index page")
        for path in js_paths:
            js_url = "https://cloud.dahsolar.com" + path
            try:
                async with self._session.get(js_url) as resp:
                    js_text = await resp.text()
            except Exception as e:
                _LOGGER.warning("Failed to fetch %s: %s", js_url, e)
                continue

            # General pattern: look for any base64-looking string used in setPublicKey
            m = re.search(
                r'setPublicKey\(["\']([A-Za-z0-9+/=]{100,})["\']\)', js_text
            )
            if not m:
                # Fallback: any long base64 string assigned to a variable near .setPublicKey
                m = re.search(
                    r'([A-Za-z0-9_]+)\s*=\s*["\']([A-Za-z0-9+/=]{100,})["\'].*?setPublicKey\(\1\)',
                    js_text,
                    re.DOTALL,
                )

            if m:
                # Group 1 or 2 may contain the base64 depending on match
                b64 = m.group(1) if len(m.groups()) == 1 else m.group(2)
                _LOGGER.debug("Extracted public key base64: %s...", b64[:40])

                pem = (
                    "-----BEGIN PUBLIC KEY-----\n"
                    + "\n".join([b64[i:i+64] for i in range(0, len(b64), 64)])
                    + "\n-----END PUBLIC KEY-----\n"
                )
                return pem

        raise AuthError("Public key not found in any js bundle")

    async def login(self) -> None:
        await self._ensure_session()
        pub_pem = await self._fetch_public_key()
        public_key = serialization.load_pem_public_key(pub_pem.encode())
        ct = public_key.encrypt(self.password.encode(), padding.PKCS1v15())
        b64 = base64.b64encode(ct).decode()

        payload = {
            "username": self.username,
            "password": b64,
            "clientId": "e5cd7e4891bf95d1d19206ce24a7b32e",
            "grantType": "terminal",
            "lang": 1,
        }
        headers = {"Content-Type": "application/json;charset=UTF-8"}
        _LOGGER.debug("Sending login request: %s", payload)
        async with self._session.post(LOGIN_ENDPOINT, json=payload, headers=headers) as resp:
            j = await resp.json()
            _LOGGER.debug("Login response: %s", j)

        data = j.get("data", {})
        token = data.get("token") or data.get("access_token") or j.get("access_token")
        if not token:
            raise AuthError("No token in login response")
        self._token = token

        headers = {
            "Authorization": f"Bearer {self._token}",
            "clientid": "e5cd7e4891bf95d1d19206ce24a7b32e",
        }
        async with self._session.get(API_BASE + "mobile/getstation?lang=1", headers=headers) as resp:
            station_list = await resp.json()
            _LOGGER.debug("stationList: %s", station_list)
        station_data = station_list.get("data") or {}
        if not station_data:
            raise AuthError("No station found for user")
        self._station_id = station_data.get("id")
        _LOGGER.debug("Using stationId=%s", self._station_id)

    async def _fetch_json(self, url: str, headers: dict) -> dict:
        async with self._session.get(url, headers=headers) as resp:
            if resp.status in (401, 403):
                _LOGGER.warning("Token expired, reauthenticating…")
                await self.login()
                headers = {"Authorization": f"Bearer {self._token}"}
                async with self._session.get(url, headers=headers) as resp2:
                    return await resp2.json()
            return await resp.json()

    async def _async_update_data(self):
        await self._ensure_session()
        if not self._token:
            await self.login()

        headers = {"Authorization": f"Bearer {self._token}"}

        async def _get(url):
            async with self._session.get(url, headers=headers) as resp:
                if resp.status in (401, 403):
                    _LOGGER.warning("Token expired, re-logging in")
                    await self.login()
                    new_headers = {"Authorization": f"Bearer {self._token}"}
                    async with self._session.get(url, headers=new_headers) as retry_resp:
                        return await retry_resp.json()
                return await resp.json()

        station_info = await _get(API_BASE + f"stationBoard/stationInfo?stationId={self._station_id}&lang=1")
        equipment_stat = await _get(API_BASE + f"stationBoard/equipmentStatistic?stationId={self._station_id}&lang=1")
        station_state = await _get(API_BASE + f"stationBoard/stationState?stationId={self._station_id}&lang=1")

        return {
            "stationInfo": station_info,
            "equipmentStatistic": equipment_stat,
            "stationState": station_state,
        }
