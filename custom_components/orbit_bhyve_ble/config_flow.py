"""Config flow for B-Hyve BLE integration."""

import logging
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.const import CONF_ADDRESS

from .const import DOMAIN, CONF_NETWORK_KEY, CONF_NUM_ZONES, DEFAULT_NUM_ZONES, SERVICE_UUID

_LOGGER = logging.getLogger(__name__)


class BHyveBLEConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for B-Hyve BLE."""

    VERSION = 1

    def __init__(self):
        self._discovered_devices = {}
        self._address = None

    async def async_step_bluetooth(self, discovery_info: BluetoothServiceInfoBleak):
        """Handle Bluetooth auto-discovery."""
        address = discovery_info.address
        await self.async_set_unique_id(address)
        self._abort_if_unique_id_configured()

        self._address = address
        self.context["title_placeholders"] = {"name": f"B-Hyve {address[-5:]}"}
        return await self.async_step_user()

    async def async_step_user(self, user_input=None):
        """Handle user-initiated config."""
        errors = {}

        if user_input is not None:
            address = user_input.get(CONF_ADDRESS, self._address)
            network_key = user_input[CONF_NETWORK_KEY].strip()
            num_zones = user_input.get(CONF_NUM_ZONES, DEFAULT_NUM_ZONES)

            # Validate key format
            try:
                key_bytes = bytes.fromhex(network_key)
                if len(key_bytes) != 16:
                    errors["base"] = "invalid_key"
            except ValueError:
                errors["base"] = "invalid_key"

            if not errors:
                await self.async_set_unique_id(address)
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=f"B-Hyve {address[-5:]}",
                    data={
                        CONF_ADDRESS: address,
                        CONF_NETWORK_KEY: network_key,
                        CONF_NUM_ZONES: num_zones,
                    },
                )

        # Find B-Hyve devices via Bluetooth
        if not self._discovered_devices:
            for info in async_discovered_service_info(self.hass):
                if SERVICE_UUID.lower() in [s.lower() for s in info.service_uuids]:
                    self._discovered_devices[info.address] = info.name or "B-Hyve"

        schema = vol.Schema({
            vol.Required(CONF_ADDRESS, default=self._address or ""): str,
            vol.Required(CONF_NETWORK_KEY): str,
            # Coerce before validating: when the user actively selects an option the
            # frontend returns it as a string (e.g. "1"), which a bare vol.In([1, 2, 4])
            # (ints) rejects with "value must be one of [1, 2, 4]". Coercing to int both
            # fixes that and guarantees num_zones is stored as an int in entry.data.
            vol.Optional(CONF_NUM_ZONES, default=DEFAULT_NUM_ZONES): vol.All(
                vol.Coerce(int), vol.In([1, 2, 4])
            ),
        })

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "discovered": ", ".join(
                    f"{addr} ({name})" for addr, name in self._discovered_devices.items()
                ) or "None found yet — ensure device is nearby"
            },
        )
