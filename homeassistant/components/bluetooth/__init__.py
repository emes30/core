"""The bluetooth integration."""
from __future__ import annotations

from asyncio import Future
from collections.abc import Callable
from typing import TYPE_CHECKING

import async_timeout

from homeassistant import config_entries
from homeassistant.core import HomeAssistant, callback as hass_callback
from homeassistant.helpers import discovery_flow
from homeassistant.loader import async_get_bluetooth

from .const import CONF_ADAPTER, DOMAIN, SOURCE_LOCAL
from .manager import BluetoothManager
from .match import BluetoothCallbackMatcher, IntegrationMatcher
from .models import (
    BluetoothCallback,
    BluetoothChange,
    BluetoothScanningMode,
    BluetoothServiceInfo,
    BluetoothServiceInfoBleak,
    HaBleakScannerWrapper,
    ProcessAdvertisementCallback,
)
from .util import async_get_bluetooth_adapters

if TYPE_CHECKING:
    from bleak.backends.device import BLEDevice

    from homeassistant.helpers.typing import ConfigType


__all__ = [
    "async_ble_device_from_address",
    "async_discovered_service_info",
    "async_get_scanner",
    "async_process_advertisements",
    "async_rediscover_address",
    "async_register_callback",
    "async_track_unavailable",
    "BluetoothServiceInfo",
    "BluetoothServiceInfoBleak",
    "BluetoothScanningMode",
    "BluetoothCallback",
    "SOURCE_LOCAL",
]


@hass_callback
def async_get_scanner(hass: HomeAssistant) -> HaBleakScannerWrapper:
    """Return a HaBleakScannerWrapper.

    This is a wrapper around our BleakScanner singleton that allows
    multiple integrations to share the same BleakScanner.
    """
    if DOMAIN not in hass.data:
        raise RuntimeError("Bluetooth integration not loaded")
    manager: BluetoothManager = hass.data[DOMAIN]
    return manager.async_get_scanner()


@hass_callback
def async_discovered_service_info(
    hass: HomeAssistant,
) -> list[BluetoothServiceInfoBleak]:
    """Return the discovered devices list."""
    if DOMAIN not in hass.data:
        return []
    manager: BluetoothManager = hass.data[DOMAIN]
    return manager.async_discovered_service_info()


@hass_callback
def async_ble_device_from_address(
    hass: HomeAssistant,
    address: str,
) -> BLEDevice | None:
    """Return BLEDevice for an address if its present."""
    if DOMAIN not in hass.data:
        return None
    manager: BluetoothManager = hass.data[DOMAIN]
    return manager.async_ble_device_from_address(address)


@hass_callback
def async_address_present(
    hass: HomeAssistant,
    address: str,
) -> bool:
    """Check if an address is present in the bluetooth device list."""
    if DOMAIN not in hass.data:
        return False
    manager: BluetoothManager = hass.data[DOMAIN]
    return manager.async_address_present(address)


@hass_callback
def async_register_callback(
    hass: HomeAssistant,
    callback: BluetoothCallback,
    match_dict: BluetoothCallbackMatcher | None,
    mode: BluetoothScanningMode,
) -> Callable[[], None]:
    """Register to receive a callback on bluetooth change.

    mode is currently not used as we only support active scanning.
    Passive scanning will be available in the future. The flag
    is required to be present to avoid a future breaking change
    when we support passive scanning.

    Returns a callback that can be used to cancel the registration.
    """
    manager: BluetoothManager = hass.data[DOMAIN]
    return manager.async_register_callback(callback, match_dict)


async def async_process_advertisements(
    hass: HomeAssistant,
    callback: ProcessAdvertisementCallback,
    match_dict: BluetoothCallbackMatcher,
    mode: BluetoothScanningMode,
    timeout: int,
) -> BluetoothServiceInfoBleak:
    """Process advertisements until callback returns true or timeout expires."""
    done: Future[BluetoothServiceInfoBleak] = Future()

    @hass_callback
    def _async_discovered_device(
        service_info: BluetoothServiceInfoBleak, change: BluetoothChange
    ) -> None:
        if not done.done() and callback(service_info):
            done.set_result(service_info)

    unload = async_register_callback(hass, _async_discovered_device, match_dict, mode)

    try:
        async with async_timeout.timeout(timeout):
            return await done
    finally:
        unload()


@hass_callback
def async_track_unavailable(
    hass: HomeAssistant,
    callback: Callable[[str], None],
    address: str,
) -> Callable[[], None]:
    """Register to receive a callback when an address is unavailable.

    Returns a callback that can be used to cancel the registration.
    """
    manager: BluetoothManager = hass.data[DOMAIN]
    return manager.async_track_unavailable(callback, address)


@hass_callback
def async_rediscover_address(hass: HomeAssistant, address: str) -> None:
    """Trigger discovery of devices which have already been seen."""
    manager: BluetoothManager = hass.data[DOMAIN]
    manager.async_rediscover_address(address)


async def _async_has_bluetooth_adapter() -> bool:
    """Return if the device has a bluetooth adapter."""
    return bool(await async_get_bluetooth_adapters())


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the bluetooth integration."""
    integration_matcher = IntegrationMatcher(await async_get_bluetooth(hass))
    manager = BluetoothManager(hass, integration_matcher)
    manager.async_setup()
    hass.data[DOMAIN] = manager
    # The config entry is responsible for starting the manager
    # if its enabled

    if hass.config_entries.async_entries(DOMAIN):
        return True
    if DOMAIN in config:
        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN, context={"source": config_entries.SOURCE_IMPORT}, data={}
            )
        )
    elif await _async_has_bluetooth_adapter():
        discovery_flow.async_create_flow(
            hass,
            DOMAIN,
            context={"source": config_entries.SOURCE_INTEGRATION_DISCOVERY},
            data={},
        )
    return True


async def async_setup_entry(
    hass: HomeAssistant, entry: config_entries.ConfigEntry
) -> bool:
    """Set up the bluetooth integration from a config entry."""
    manager: BluetoothManager = hass.data[DOMAIN]
    async with manager.start_stop_lock:
        await manager.async_start(
            BluetoothScanningMode.ACTIVE, entry.options.get(CONF_ADAPTER)
        )
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def _async_update_listener(
    hass: HomeAssistant, entry: config_entries.ConfigEntry
) -> None:
    """Handle options update."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(
    hass: HomeAssistant, entry: config_entries.ConfigEntry
) -> bool:
    """Unload a config entry."""
    manager: BluetoothManager = hass.data[DOMAIN]
    async with manager.start_stop_lock:
        manager.async_start_reload()
        await manager.async_stop()
    return True
