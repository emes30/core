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

from .const import CONF_FILTER, CONF_HOST, CONF_PASS, CONF_USER
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
    hass: HomeAssistant, config: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up the Mikrotik switch platform."""
    # session = async_get_clientsession(hass)
    hub = MikrotikHub(config.data[CONF_HOST])
    coordinator = MikrotikCoordinator(hass, hub)
    switches = [
        RuleSwitch(coordinator, rule)
        for rule in await hub.get_rules(config.data[CONF_FILTER])
    ]
    async_add_entities(switches, update_before_add=True)


class MikrotikCoordinator(DataUpdateCoordinator):
    """Fetch rules states from router."""

    def __init__(self, hass, hub):
        """Initialize my coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            # Name of the data. For logging purposes.
            name="Mikrotik rule switch",
            # Polling interval. Will only be polled if there are subscribers.
            update_interval=timedelta(seconds=60),
            # Update rules state
            update_method=self._async_save,
        )
        self.hub = hub

    async def _async_save(self):
        await self.hub.save(self.data)
        return

    async def _async_update_data(self):
        """Fetch data from API endpoint.

        This is the place to pre-process the data to lookup tables
        so entities can quickly look up their data.
        """
        # try:
        # Note: asyncio.TimeoutError and aiohttp.ClientError are already
        # handled by the data update coordinator.
        async with async_timeout.timeout(10):
            return await self.hub.fetch_data()
        # except ApiAuthError as err:
        # Raising ConfigEntryAuthFailed will cancel future updates
        # and start a config flow with SOURCE_REAUTH (async_step_reauth)
        #    raise ConfigEntryAuthFailed from err
        # except ApiError as err:
        #    raise UpdateFailed(f"Error communicating with API: {err}")


class RuleSwitch(CoordinatorEntity, SwitchEntity):
    """Firewall rule switch."""

    def __init__(self, coordinator, rule):
        """Class setup."""
        super().__init__(coordinator)
        self._is_on = False
        self._rule = rule

    @callback
    def _handle_coordinator_update(self) -> None:
        self._is_on = self.coordinator.data[self._rule]["state"]
        self.async_write_ha_state()

    @property
    def name(self):
        """Name of the entity."""
        return self._rule

    @property
    def unique_id(self) -> str:
        """Return entity unique id."""
        return f"fw_rule_{ self._rule }"

    async def _update_state(self):
        self.coordinator.data[self._rule]["state"] = self._is_on
        self.coordinator.data[self._rule]["updated"] = True
        await self.coordinator.async_request_refresh()

    @property
    def is_on(self):
        """If the switch is currently on or off."""
        return self._is_on

    async def async_turn_on(self, **kwargs):
        """Turn the switch on."""
        self._is_on = True
        await self._update_state()

    async def async_turn_off(self, **kwargs):
        """Turn the switch off."""
        self._is_on = False
        await self._update_state()
