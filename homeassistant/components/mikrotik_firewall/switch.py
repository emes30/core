"""Mikrotik firewall rule switch."""

from datetime import timedelta
import logging

import async_timeout
import voluptuous as vol

from homeassistant.components.switch import PLATFORM_SCHEMA, SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import (
    CONF_FILTER,
    CONF_HOST,
    CONF_PASS,
    CONF_USER,
    DISABLED_FALSE,
    DISABLED_TRUE,
    DOMAIN,
    ENTITY_NAME_PREFIX,
)
from .hub import MikrotikHub

_LOGGER = logging.getLogger(__name__)


PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        # router ip
        vol.Required(CONF_HOST): cv.string,
        # username
        vol.Required(CONF_USER): cv.string,
        # password, can be empty
        vol.Optional(CONF_PASS): cv.string,
        # rules filter
        vol.Optional(CONF_FILTER): cv.string,
    }
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Mikrotik switch platform."""
    coordinator: MikrotikCoordinator = hass.data[DOMAIN][config_entry.entry_id]
    new_rules = await coordinator.hub.get_rules(True)
    if new_rules:
        switches = [RuleSwitch(coordinator, new_rules[rule]) for rule in new_rules]
        async_add_entities(switches, update_before_add=True)


class MikrotikCoordinator(DataUpdateCoordinator):
    """Fetch rules states from router."""

    def __init__(
        self, hass: HomeAssistant, config_entry: ConfigEntry, hub: MikrotikHub
    ) -> None:
        """Initialize my coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            # Name of the data. For logging purposes.
            name="Mikrotik rule switch",
            # Polling interval. Will only be polled if there are subscribers.
            update_interval=timedelta(seconds=15),
            # Update rules state
            update_method=self._async_save,
        )
        self._config_entry = config_entry
        self._hub = hub

    async def _async_save(self):
        await self._hub.save(self.data)
        return

    async def _async_update_data(self):
        """Fetch data from API endpoint.

        This is the place to pre-process the data to lookup tables
        so entities can quickly look up their data.
        """
        # try:
        # Note: asyncio.TimeoutError and aiohttp.ClientError are already
        # handled by the data update coordinator.
        self._hub.connect()
        await self._hub.save_data(self.data)
        async with async_timeout.timeout(10):
            data = await self._hub.fetch_data()
        self._hub.disconnect()
        return data
        # except ApiAuthError as err:
        # Raising ConfigEntryAuthFailed will cancel future updates
        # and start a config flow with SOURCE_REAUTH (async_step_reauth)
        #    raise ConfigEntryAuthFailed from err
        # except ApiError as err:
        #    raise UpdateFailed(f"Error communicating with API: {err}")

    @property
    def hub(self) -> MikrotikHub:
        """Return hub object for router communication."""
        return self._hub


class RuleSwitch(CoordinatorEntity, SwitchEntity):
    """Firewall rule switch."""

    def __init__(self, coordinator: MikrotikCoordinator, rule: dict) -> None:
        """Class setup."""
        super().__init__(coordinator)
        self._rule = rule
        self._rule_comment = self._rule["comment"]
        self._attr_is_on = rule["disabled"] == DISABLED_TRUE
        self._mac = coordinator.hub.mac

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_is_on = (
            self.coordinator.data[self._rule_comment]["disabled"] == DISABLED_TRUE
        )
        self.async_write_ha_state()

    @property
    def name(self):
        """Name of the entity."""
        return f"{ ENTITY_NAME_PREFIX }_{ self._rule_comment }"

    @property
    def unique_id(self) -> str:
        """Return entity unique id."""
        return f"fw_rule_{ self._mac }_{ self._rule_comment }"

    @property
    def available(self) -> bool:
        """Check if rule is available."""
        return self._rule_comment in self.coordinator.data

    async def _update_state(self):
        if self.available:
            self._rule["disabled"] = (
                DISABLED_TRUE if self._attr_is_on else DISABLED_FALSE
            )
            self.coordinator.data[self._rule_comment]["disabled"] = self._rule[
                "disabled"
            ]
            self.coordinator.data[self._rule_comment]["updated"] = True
        await self.coordinator.async_request_refresh()

    @property
    def is_on(self):
        """If the switch is currently on or off."""
        return self._attr_is_on

    async def async_turn_on(self, **kwargs):
        """Turn the switch on."""
        self._attr_is_on = True
        await self._update_state()

    async def async_turn_off(self, **kwargs):
        """Turn the switch off."""
        self._attr_is_on = False
        await self._update_state()
