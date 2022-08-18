"""The Mikrotik firewall manager integration."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import DOMAIN
from .errors import CannotConnect, InvalidAuth
from .hub import MikrotikHub
from .switch import MikrotikCoordinator

# support for switch platform
PLATFORMS: list[str] = ["switch"]


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up Mikrotik firewall from a config entry."""

    hub = MikrotikHub(dict(config_entry.data))
    coordinator = MikrotikCoordinator(hass, config_entry, hub)

    try:
        await hub.authenticate()
    except CannotConnect as api_error:
        raise ConfigEntryNotReady from api_error
    except InvalidAuth:
        return False

    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[config_entry.entry_id] = coordinator
    hass.config_entries.async_setup_platforms(config_entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok
