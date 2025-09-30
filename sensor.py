from __future__ import annotations

from homeassistant.components.sensor import PLATFORM_SCHEMA, SensorEntity
import voluptuous as vol
from homeassistant.const import CONF_USERNAME, CONF_PASSWORD
from homeassistant.helpers import config_validation as cv

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_USERNAME): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
})


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    from .coordinator import DAHDataUpdateCoordinator

    username = config[CONF_USERNAME]
    password = config[CONF_PASSWORD]

    coordinator = DAHDataUpdateCoordinator(hass, username, password)
    await coordinator.async_prepare()

    sensors = [
        # existing sensors...
        DAHValueSensor(coordinator, "cumulativeElectricity", "kWh",
                       name="DAH Cumulative Energy",
                       device_class="energy", state_class="total_increasing"),

        DAHValueSensor(coordinator, "electricity", "kWh",
                       name="DAH Today Yield"),

        DAHValueSensor(coordinator, "power", "W",
                       name="DAH Power",
                       device_class="power", state_class="measurement"),

        DAHValueSensor(coordinator, "installedPower", "kWp",
                       name="DAH Installed Capacity"),

        # NEW: Station info 'days'
        DAHValueSensor(coordinator, "days", "days",
                       name="DAH Uptime Days"),

        # NEW: Station state details
        DAHValueSensor(coordinator, "normalNo", None,
                       name="DAH Normal Devices"),
        DAHValueSensor(coordinator, "offlineNo", None,
                       name="DAH Offline Devices"),
        DAHValueSensor(coordinator, "warningNo", None,
                       name="DAH Warnings"),
        DAHValueSensor(coordinator, "faultNo", None,
                       name="DAH Faults"),
    ]

    async_add_entities(sensors, True)

class DAHValueSensor(SensorEntity):
    def __init__(self, coordinator, key, unit, name=None,
                 device_class=None, state_class=None):
        self.coordinator = coordinator
        self.key = key
        self._attr_name = name or f"DAH {key}"
        self._attr_unique_id = f"dah_{key}"
        self._attr_native_unit_of_measurement = unit
        self._attr_device_class = device_class
        self._attr_state_class = state_class

        # auto-update when coordinator refreshes
        self.coordinator.async_add_listener(self.async_write_ha_state)

    @property
    def native_value(self):
        if not self.coordinator.data:
            return None
        data = {}
        data.update(self.coordinator.data.get("stationInfo", {}).get("data", {}) or {})
        data.update(self.coordinator.data.get("equipmentStatistic", {}).get("data", {}) or {})
        data.update(self.coordinator.data.get("stationState", {}).get("data", {}) or {})
        # keep this if your coordinator returns stationList
        data.update(self.coordinator.data.get("stationList", {}).get("data", {}) or {})
        return data.get(self.key)

    # remove async_update(); the listener handles state writes

