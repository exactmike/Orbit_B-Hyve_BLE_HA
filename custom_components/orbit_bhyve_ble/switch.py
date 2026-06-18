"""Switch platform for B-Hyve BLE sprinkler zones."""

import logging
from datetime import timedelta

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, DEFAULT_DURATION

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up B-Hyve zone switches from a config entry."""
    device = hass.data[DOMAIN][entry.entry_id]

    entities = [
        BHyveZoneSwitch(device, zone)
        for zone in range(1, device.num_zones + 1)
    ]
    async_add_entities(entities)


class BHyveZoneSwitch(SwitchEntity):
    """A single B-Hyve sprinkler zone."""

    _attr_has_entity_name = True

    def __init__(self, device, zone: int):
        self._device = device
        self._zone = zone
        self._is_on = False
        self._duration = DEFAULT_DURATION

        mac_clean = device.address.replace(":", "").lower()
        self._attr_unique_id = f"bhyve_{mac_clean}_zone_{zone}"
        self._attr_name = f"Zone {zone}"
        self._attr_icon = "mdi:sprinkler"

        # Label by zone count — the only model signal available without decoding the
        # device's RX telemetry. sw_version is intentionally omitted: firmware differs
        # per model (0107 on the XD 4-port, 111 on single-station valves) and can't be
        # read until the RX path is decoded.
        model = {
            1: "B-Hyve Single Zone Device",
            2: "B-Hyve 2 Zone Device",
            4: "B-Hyve 4 Zone Device",
        }.get(device.num_zones, f"B-Hyve {device.num_zones} Zone Device")

        self._attr_device_info = {
            "identifiers": {(DOMAIN, device.address)},
            "name": f"B-Hyve {device.address[-5:]}",
            "manufacturer": "Orbit Irrigation",
            "model": model,
        }

    @property
    def is_on(self) -> bool:
        return self._is_on

    @property
    def icon(self) -> str:
        return "mdi:sprinkler-variant" if self._is_on else "mdi:sprinkler"

    @property
    def extra_state_attributes(self):
        return {"zone": self._zone, "duration": self._duration}

    async def async_turn_on(self, **kwargs) -> None:
        """Turn on the sprinkler zone via BLE."""
        # Read duration from input_number helper if available
        duration = self._duration
        try:
            state = self.hass.states.get("input_number.bhyve_duration")
            if state and state.state not in ("unknown", "unavailable"):
                duration = int(float(state.state)) * 60  # convert minutes to seconds
        except (ValueError, AttributeError):
            pass

        success = await self._device.turn_on(self._zone, duration)
        if success:
            self._is_on = True
            self._duration = duration
            self.async_write_ha_state()

            # Schedule auto-off
            self.hass.loop.call_later(
                duration,
                lambda: self.hass.async_create_task(self._auto_off()),
            )

    async def async_turn_off(self, **kwargs) -> None:
        """Stop watering via BLE."""
        success = await self._device.turn_off()
        if success:
            self._is_on = False
            self.async_write_ha_state()

    async def _auto_off(self) -> None:
        """Auto-off callback after duration expires."""
        if self._is_on:
            self._is_on = False
            self.async_write_ha_state()
