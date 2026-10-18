# HomeKit Gerät

Ein HomeKit-Gerät (HomeKit über IP) an einem eigenen Client Socket. Symcon ist die Steuerzentrale: Kopplung mit dem HomeKit-Code, verschlüsselte Dauerverbindung, Ereignisse in Echtzeit.

### Inhaltsverzeichnis

1. [Funktionsumfang](#1-funktionsumfang)
2. [Voraussetzungen](#2-voraussetzungen)
3. [Software-Installation](#3-software-installation)
4. [Einrichten der Instanzen in Symcon](#4-einrichten-der-instanzen-in-symcon)
5. [Statusvariablen und Darstellungen](#5-statusvariablen-und-darstellungen)
6. [Visualisierung](#6-visualisierung)
7. [PHP-Befehlsreferenz](#7-php-befehlsreferenz)

### 1. Funktionsumfang

* Koppelt mit dem 8-stelligen HomeKit-Code und hält danach eine verschlüsselte Verbindung zum Gerät.
* Legt je bekanntem Merkmal eine Variable an, benannt nach dem Dienst des Geräts (beim Aqara FP2: eine je Zone plus Helligkeit). Namen lassen sich in Symcon ändern.
* Ereignisse des Geräts aktualisieren die Variablen sofort; schaltbare Merkmale lassen sich setzen.
* Findet das Gerät per Bonjour über seine HomeKit-ID wieder, wenn sich Adresse oder Port ändern.
* Verbindet nach Abbruch oder Neustart des Geräts selbst neu; liest nach 5 Minuten ohne Meldung die Werte nach.

### 2. Voraussetzungen

- Symcon 8.1 oder neuer; für die Bonjour-Suche die DNS-SD-Steuerung.
- Das Gerät ist mit der Hersteller-App eingerichtet und in keiner anderen HomeKit-Zentrale (Apple Home) gekoppelt.

### 3. Software-Installation

* Über das Module Control folgende URL hinzufügen:
  `https://github.com/da8ter/HomeKitController`

### 4. Einrichten der Instanzen in Symcon

Am einfachsten über den **HomeKit Konfigurator**, der die Instanz samt Client Socket anlegt. Von Hand: Instanz „HomeKit Gerät“ anlegen, als übergeordnete Instanz einen Client Socket wählen, HomeKit-ID eintragen (Bonjour füllt Adresse und Port) oder unter „Feste Adresse“ Adresse und Port setzen.

__Konfigurationsseite__:

| Name | Beschreibung |
|---|---|
| HomeKit-ID | ID des Geräts aus Bonjour (`id=` im TXT-Eintrag, z. B. `A4:FA:0D:12:34:56`). Darüber wird das Gerät wiedergefunden. |
| Feste Adresse | Adresse und Port, nur ohne Bonjour nötig. |
| HomeKit-Code + Koppeln | 8 Ziffern vom Aufkleber oder aus der Hersteller-App. Die Kopplung läuft im Hintergrund; der Status zeigt das Ergebnis. |
| Neu verbinden | Adresse nachführen und Verbindung neu aufbauen. |
| Entkoppeln | Kopplung beim Gerät aufheben und hier löschen. |
| Kopplung lokal löschen | Nur hier löschen, wenn das Gerät zurückgesetzt wurde. |

Die Zeile über den Knöpfen zeigt Adresse, Gerätekennung der Kopplung, Sitzungszustand und den letzten Fehler.

__Status__:

| Code | Bedeutung |
|---|---|
| 102 | Verbunden |
| 200 | Keine Verbindung zum Gerät |
| 201 | Nicht gekoppelt: HomeKit-Code eingeben und Koppeln drücken |
| 202 | Kopplung ungültig: das Gerät kennt Symcon nicht mehr (zurückgesetzt?). Kopplung lokal löschen und neu koppeln. |
| 203 | Gerät per Bonjour nicht gefunden |

### 5. Statusvariablen und Darstellungen

| Name | Typ | Beschreibung |
|---|---|---|
| Verbunden | Boolean | Sitzung mit dem Gerät steht (Darstellung Verbunden/Getrennt). |
| je Merkmal (Ident `A<aid>_I<iid>`) | je nach Merkmal | Anwesenheit, Bewegung, Kontakt (Boolean mit Beschriftung), Helligkeit in lx, Temperatur in °C, Luftfeuchte und Batterie in %, Schalter, Helligkeit dimmbar (Schieberegler). |

Merkmale, die das Modul nicht kennt (Herstellerdienste, Geräteinformation), bekommen keine Variable und erscheinen nur im Debug.

### 6. Visualisierung

Die Instanz als Kachel verlinken: Sie zeigt den Verbindungsstatus und alle Variablen. Für einzelne Zonen die Variablen direkt verlinken.

### 7. PHP-Befehlsreferenz

```php
HKC_Pair(int $InstanzID, string $Code): string
HKC_Unpair(int $InstanzID): string
HKC_ForgetPairing(int $InstanzID): string
HKC_Reconnect(int $InstanzID): void
HKC_Resolve(int $InstanzID): bool
```

Schaltbare Merkmale: `RequestAction($VariablenID, $Wert)`.
