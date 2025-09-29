# Home Assistant Integration for DAH Solar (Unofficial)

Custom integration for [Home Assistant](https://www.home-assistant.io/) that connects to the **DAH Solar Cloud** API (`cloud.dahsolar.com` / `interface.dhhome-e.com`).  
It exposes production data from your DAH inverter/plant as Home Assistant sensors that you can use in dashboards and automations.

⚠️ **Disclaimer**:  
This is **not an official integration**. It was built by reverse-engineering the DAH Solar web frontend. Use at your own risk. API behavior may change at any time.

---

## ✨ Features

- Logs into DAH Solar Cloud with your account credentials  
- Automatically handles RSA password encryption used by the web app  
- Extracts the public key dynamically from the DAH Solar JS bundles (survives filename changes and key rotations)  
- Retrieves station data and exposes it as sensors:
  - **Cumulative Energy (kWh)** – lifetime production (Energy Dashboard compatible)  
  - **Today’s Yield (kWh)** – daily production (resets daily)  
  - **Power (W)** – current output  
  - **Installed Capacity (kWp)** – PV system size  
  - **Uptime Days** – days since station was added  
  - **Normal / Offline / Warning / Fault devices** – counts of device status  
- Token auto-refresh when expired  
- Updates every 60 seconds  

---

## 📦 Installation

### Manual

1. Copy the folder `custom_components/dahsolar` into your Home Assistant `config` directory:

```

/config/custom_components/dahsolar

````

2. Restart Home Assistant (or run `ha core restart` inside your HA container).  

3. Add configuration to your `configuration.yaml`:

```yaml
sensor:
  - platform: dahsolar
    username: "your@email.com"
    password: "yourpassword"
````

4. Restart Home Assistant again.

---

## 🖥️ Entities

After restart, the following sensors will be created:

* `sensor.dah_cumulative_energy` (kWh, **usable in Energy Dashboard**)
* `sensor.dah_today_yield` (kWh, resets daily)
* `sensor.dah_power` (W)
* `sensor.dah_installed_capacity` (kWp)
* `sensor.dah_state`
* `sensor.dah_latitude` / `sensor.dah_longitude`
* `sensor.dah_uptime_days`
* `sensor.dah_normal_devices`
* `sensor.dah_offline_devices`
* `sensor.dah_warnings`
* `sensor.dah_faults`

---

## ⚡ Energy Dashboard

* Use **`sensor.dah_cumulative_energy`** as your *solar production source*.
* Do not use `today_yield` for the Energy Dashboard (it resets daily and HA rejects it).

---

## 📸 Example Screenshot

Here’s how the DAH Solar sensors look inside Home Assistant:

![DAH Solar Sensors](https://raw.githubusercontent.com/<yourusername>/dahsolar-homeassistant/main/docs/screenshot.png)

---

## 🔧 Debugging

* Enable debug logging in `configuration.yaml`:

  ```yaml
  logger:
    default: warning
    logs:
      custom_components.dahsolar: debug
  ```

* Then view logs under **Settings → System → Logs** or in your container logs.

---

## 🧩 Development Notes

* The integration uses `DataUpdateCoordinator` with a 60s refresh.
* On `401/403` responses the login is retried and a new token is fetched.
* The RSA public key is dynamically scraped from `/static/js/*.js` bundles on the DAH Solar frontend.

---

## 🙏 Credits

This integration was built **together with ChatGPT (GPT-5 by OpenAI)** through an iterative development process.
All code, fixes, and documentation were generated, tested, and refined in collaboration with the model.

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.
See the [LICENSE](LICENSE) file for details.
