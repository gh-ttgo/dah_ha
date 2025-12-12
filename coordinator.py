from __future__ import annotations

import re
import base64
import logging

import aiohttp

import asyncio
from aiohttp import ClientError, ClientTimeout

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

    # replace your _ensure_session with this
    async def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=ClientTimeout(total=20))


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

    # add this helper (place next to _fetch_json or replace it entirely)
    async def _request_json(self, url: str, headers: dict | None = None, retry: bool = True) -> dict:
        await self._ensure_session()
        try:
            async with self._session.get(url, headers=headers) as resp:
                text = await resp.text()
                # token expired or HTML login page
                if resp.status in (401, 403) or text.lstrip().startswith("<!DOCTYPE html>"):
                    _LOGGER.warning("Auth expired or HTML response, re-logging in")
                    await self.login()
                    headers = {"Authorization": f"Bearer {self._token}"}
                    async with self._session.get(url, headers=headers) as r2:
                        return await r2.json(content_type=None)
                return await resp.json(content_type=None)
        except (asyncio.TimeoutError, ClientError) as e:
            if retry:
                _LOGGER.warning("Network error %s, recreating session and retrying once", e)
                try:
                    await self._session.close()
                except Exception:
                    pass
                self._session = None
                await self._ensure_session()
                # optional: re-login after long outages
                if not self._token:
                    await self.login()
                return await self._request_json(url, headers, retry=False)
            raise

    async def _async_update_data(self):
        """Fetch and update DAH Solar station data safely."""
        await self._ensure_session()

        if not self._token:
            await self.login()
        if not self._station_id:
            raise AuthError("No stationId available")

        headers = {"Authorization": f"Bearer {self._token}"}
        base = API_BASE + "stationBoard/"

        async def _get_json(url: str, retry: bool = True):
            """Helper that retries once on network or auth errors."""
            await self._ensure_session()
            try:
                async with self._session.get(url, headers=headers) as resp:
                    text = await resp.text()

                    # Token expired or HTML instead of JSON → re-login and retry once
                    if resp.status in (401, 403) or text.lstrip().startswith("<!DOCTYPE html>"):
                        _LOGGER.warning("Token expired or HTML login page received, re-logging in")
                        await self.login()
                        new_headers = {"Authorization": f"Bearer {self._token}"}
                        async with self._session.get(url, headers=new_headers) as retry_resp:
                            return await retry_resp.json(content_type=None)

                    return await resp.json(content_type=None)

            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                if retry:
                    _LOGGER.warning("Network error %s, recreating session and retrying once", e)
                    try:
                        await self._session.close()
                    except Exception:
                        pass
                    self._session = None
                    await self._ensure_session()
                    # optional re-login after long outages
                    if not self._token:
                        await self.login()
                    return await _get_json(url, retry=False)
                raise

        # --- actual API calls ---
        station_info = await _get_json(f"{base}stationInfo?stationId={self._station_id}&lang=1")
        equipment_stat = await _get_json(f"{base}equipmentStatistic?stationId={self._station_id}&lang=1")
        station_state = await _get_json(f"{base}stationState?stationId={self._station_id}&lang=1")

        _LOGGER.debug("stationInfo: %s", station_info)
        _LOGGER.debug("equipmentStatistic: %s", equipment_stat)
        _LOGGER.debug("stationState: %s", station_state)

        return {
            "stationInfo": station_info,
            "equipmentStatistic": equipment_stat,
            "stationState": station_state,
        }

