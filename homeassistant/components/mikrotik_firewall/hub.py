"""Mikrotik API encapsulation class."""
from __future__ import annotations

import logging
from typing import Any

import routeros_api

from .const import CONF_HOST, CONF_PASS, CONF_USER, MK_API_IP_FIREWALL_FILTER
from .errors import CannotConnect, InvalidAuth

_LOGGER = logging.getLogger(__name__)


class MikrotikHub:
    """Placeholder class to make tests pass.

    TODO Remove this placeholder class and replace with things from your PyPI package.
    """

    def __init__(self, config_data: dict[str, Any]) -> None:
        """Initialize."""
        self._config = config_data
        self._conn: routeros_api.RouterOsApiPool = None
        self._api: routeros_api.api.RouterOsApi = None
        self._rules_res: routeros_api.resource.RouterOsResource = None
        self._mac: str | None = None
        self._rules: dict = {
            "net_mati": {"state": True},
            "net_tv": {"state": True},
            "net_chrome": {"state": True},
        }

    def _connect(self) -> None:
        try:
            password = self._config[CONF_PASS] if CONF_PASS in self._config else ""
            connection = routeros_api.RouterOsApiPool(
                self._config[CONF_HOST],
                username=self._config[CONF_USER],
                password=password,
                plaintext_login=True,
            )
            self._conn = connection
            self._api = self._conn.get_api()
            self._rules_res = self._api.get_resource(MK_API_IP_FIREWALL_FILTER)
            self._mac = self._get_mac()
        except (Exception) as ex:
            _LOGGER.error("Connection to [%s] error: %s", self._config[CONF_HOST], ex)
            self._api = None
            if len(ex.args) > 0 and "invalid user" in ex.args[0]:
                raise InvalidAuth from ex
            raise CannotConnect from ex

    def _disconnect(self) -> None:
        if self._conn:
            self._conn.disconnect()
            self._conn = None
            self._api = None
            self._rules_res = None

    def _get_mac(self) -> str | None:
        """Return mac address of first ethernet interface."""
        if not self._api:
            return None

        res = self._api.get_resource("/interface/ethernet")
        eth = res.get()
        if len(eth) > 0:
            return eth[0]["orig-mac-address"]

        return None

    async def authenticate(self) -> bool:
        """Test if we can authenticate with the host."""
        self._connect()
        if self._api:
            self._disconnect()
            return True
        return False

    async def get_rules(self) -> list[str]:
        """Get list of firewall rules from router."""
        return ["net_mati", "net_tv", "net_chrome"]

    async def fetch_data(self):
        """Get current rules states."""
        return self._rules

    async def save_data(self, new_states: dict):
        """Update rules states."""
        if new_states:
            for rule_key in [x for x in new_states if "updated" in new_states[x]]:
                if new_states[rule_key]["updated"]:
                    self._rules[rule_key]["state"] = new_states[rule_key]["state"]
