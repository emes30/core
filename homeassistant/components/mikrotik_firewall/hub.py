"""Mikrotik API encapsulation class."""
from __future__ import annotations

import logging
import ssl
from typing import Any

import routeros_api

from .const import (
    CONF_CHAIN,
    CONF_FILTER,
    CONF_HOST,
    CONF_PASS,
    CONF_SSL,
    CONF_USER,
    MK_API_IP_FIREWALL_FILTER,
)
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
        self._rules: dict = {}

    def connect(self) -> None:
        """Connect to rotuer."""
        try:
            password = self._config[CONF_PASS] if CONF_PASS in self._config else ""
            kwargs = {}
            if CONF_SSL in self._config and self._config[CONF_SSL]:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                ssl_context.set_ciphers("ADH:ALL:@SECLEVEL=0")
                kwargs = {
                    "ssl_context": ssl_context,
                    "ssl_verify": False,
                    "ssl_verify_hostname": False,
                    "use_ssl": True,
                    "port": 8729,
                }
            kwargs["plaintext_login"] = password == ""
            connection = routeros_api.RouterOsApiPool(
                self._config[CONF_HOST],
                username=self._config[CONF_USER],
                password=password,
                **kwargs,
            )
            self._conn = connection
            self._api = self._conn.get_api()
            self._rules_res = self._api.get_resource(MK_API_IP_FIREWALL_FILTER)
            self._mac = self._get_mac()
        except (Exception) as ex:
            _LOGGER.error("Connection to [%s] error: %s", self._config[CONF_HOST], ex)
            self._api = None
            if (
                len(ex.args) > 0
                and isinstance(ex.args[0], str)
                and "invalid user" in ex.args[0]
            ):
                raise InvalidAuth from ex
            raise CannotConnect from ex

    def disconnect(self) -> None:
        """Disconnect from router."""
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

    def _can_add_rule(self, rule: dict) -> bool:
        if "comment" not in rule:
            return False

        comment = rule["comment"]

        if " " in comment:
            return False

        if CONF_FILTER in self._config:
            if not self._config[CONF_FILTER] in comment:
                return False

        chain = self._config[CONF_CHAIN] if CONF_CHAIN in self._config else ""
        if not chain:
            return True

        return rule["chain"] == chain

    def _get_rules(self, connect: bool = False) -> dict | None:
        if connect:
            self.connect()

        if not self._api:
            return None

        new_rules: dict = {}

        rules = self._rules_res.get()
        if rules:
            for rule in rules:
                if not self._can_add_rule(rule):
                    continue
                comment = rule["comment"]
                if comment not in self._rules:
                    new_rules[comment] = rule
                self._rules[comment] = rule

        if connect:
            self.disconnect()

        return new_rules

    async def authenticate(self) -> bool:
        """Test if we can authenticate with the host."""
        self.connect()
        if self._api:
            self.disconnect()
            return True
        return False

    async def get_rules(self, connect: bool = False) -> dict:
        """Get list of firewall rules from router."""
        self._get_rules(True)
        return self._rules

    async def fetch_data(self) -> dict:
        """Get current rules states."""
        self._get_rules(False)
        return self._rules

    async def _set_rule(self, rule: dict) -> None:
        if rule:
            self._rules_res.set(id=rule["id"], disabled=rule["disabled"])

    async def save_data(self, rules: dict):
        """Update rules states."""
        if rules:
            for rule_key in [x for x in rules if "updated" in rules[x]]:
                rule = rules[rule_key]
                if rule["updated"]:
                    await self._set_rule(rule)
                rule["updated"] = False
