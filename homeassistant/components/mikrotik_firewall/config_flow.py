"""Config flow for Mikrotik firewall manager integration."""
from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
import homeassistant.helpers.config_validation as cv

from .const import (
    CONF_FILTER,
    CONF_HOST,
    CONF_PASS,
    CONF_RULE_ID,
    CONF_RULE_NAME,
    CONF_RULES,
    CONF_USER,
    DOMAIN,
)
from .errors import CannotConnect, InvalidAuth
from .hub import MikrotikHub

_LOGGER = logging.getLogger(__name__)

RULE_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_RULE_ID): cv.string,
        vol.Optional(CONF_RULE_NAME): cv.string,
        vol.Optional("use_this_rule"): cv.boolean,
    }
)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        # router ip
        vol.Required(CONF_HOST): cv.string,
        # username
        vol.Required(CONF_USER): cv.string,
        # password, can be empty
        vol.Optional(CONF_PASS): cv.string,
        # rule filter, can be empty
        vol.Optional(CONF_FILTER): cv.string,
    }
)

STEP_RULES = vol.Schema(
    {
        # rules
        vol.Required(CONF_RULES): vol.All(cv.ensure_list, [RULE_SCHEMA])
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """
    Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA
    with values provided by the user.
    """

    hub = MikrotikHub(data[CONF_HOST])

    if not await hub.authenticate():
        raise InvalidAuth
    # If you cannot connect:
    # throw CannotConnect
    # If the authentication is wrong:
    # InvalidAuth

    # read available rules from router
    rules = await hub.get_rules()

    # Return info that you want to store in the config entry.
    return {"title": "Mikrotik firewall", "rules": rules}


async def validate_input2(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """
    Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA
    with values provided by the user.
    """

    hub = MikrotikHub(data)

    await hub.authenticate()
    # if not await hub.authenticate(data[CONF_USER], data[CONF_PASS]):
    #    raise InvalidAuth
    # If you cannot connect:
    # throw CannotConnect
    # If the authentication is wrong:
    # InvalidAuth

    # read available rules from router
    rules = await hub.get_rules()

    # Return info that you want to store in the config entry.
    return {"title": "Mikrotik firewall", "rules": rules}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Mikrotik firewall manager."""

    VERSION = 1

    data: Mapping[str, Any]

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """No user input. Show form."""
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=STEP_USER_DATA_SCHEMA
            )

        # Validate user input
        errors: dict[str, Any] = {}

        try:
            info = await validate_input2(self.hass, user_input)
        except CannotConnect:
            errors["base"] = "cannot_connect"
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors["base"] = "unknown"

        if not errors:
            self.data = user_input
            self.data[CONF_RULES] = info[CONF_RULES]
            return self.async_create_entry(
                title="Mikrotik Firewall",
                data=self.data,
            )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )
