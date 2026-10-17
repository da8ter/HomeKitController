# Testen gegen HAP-python

Stand: 17.10.2026

HAP-python (https://github.com/ikalchev/HAP-python) ist eine unabhängige, verbreitete Implementierung der Geräteseite. Gegen sie wird alles geprüft, bevor ein echtes Gerät gekoppelt wird.

## Test-Gerät starten

```bash
python3.12 -m venv /pfad/hapvenv && /pfad/hapvenv/bin/pip install HAP-python
/pfad/hapvenv/bin/python fake_fp2.py 51826 /pfad/fake_fp2.state
```

`fake_fp2.py` (liegt bewusst nicht im Repo, Vorlage unten) bildet einen FP2 nach:
- drei Präsenzdienste (Name „Anwesenheit“, „Zone Sofa“, „Zone Tisch“) und einen Lichtsensor,
- alle 5 s schaltet eine Zone um und die Helligkeit steigt (Ereignisse),
- Code `031-45-154`.

HAP-python bindet nur an die LAN-Adresse des Rechners, nicht an `127.0.0.1`. Es kündigt sich per Bonjour an; Apple-Geräte im Haus können es als „nicht gekoppeltes Gerät“ anzeigen, deshalb nach dem Test beenden.

## Mit dem Werkzeug prüfen

```bash
php tools/hap_cli.php pair   <lan-ip> 51826 031-45-154 /tmp/pairing.json
php tools/hap_cli.php listen <lan-ip> 51826 /tmp/pairing.json 15
php tools/hap_cli.php unpair <lan-ip> 51826 /tmp/pairing.json
```

Gemessen am 17.10.2026: Kopplung, Sitzung, `/accessories` (Dienst 0x86 mit Merkmal 0x71 und Namen 0x23, Dienst 0x84 mit 0x6B) und Ereignisse laufen gegen HAP-python 5.0.0. Ein Ereignis kann mehrere Merkmale bündeln.

## Vorlage fake_fp2.py

```python
from pyhap.accessory import Accessory
from pyhap.accessory_driver import AccessoryDriver
from pyhap.const import CATEGORY_SENSOR
import signal, sys

class FakeFP2(Accessory):
    category = CATEGORY_SENSOR
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.occ = []
        for name in ("Anwesenheit", "Zone Sofa", "Zone Tisch"):
            s = self.add_preload_service("OccupancySensor", chars=["Name"])
            s.configure_char("Name", value=name)
            self.occ.append(s.configure_char("OccupancyDetected", value=0))
        self.lux = self.add_preload_service("LightSensor").configure_char("CurrentAmbientLightLevel", value=123.0)
        self.tick = 0

    @Accessory.run_at_interval(5)
    async def run(self):
        self.tick += 1
        self.occ[self.tick % 3].set_value(1 - self.occ[self.tick % 3].get_value())
        self.lux.set_value(100.0 + self.tick)

driver = AccessoryDriver(port=int(sys.argv[1]), persist_file=sys.argv[2], pincode=b"031-45-154")
driver.add_accessory(accessory=FakeFP2(driver, "Symcon Testsensor"))
signal.signal(signal.SIGTERM, driver.signal_handler)
driver.start()
```
