# HomeKit Konfigurator

Listet die HomeKit-Geräte im Netz (Bonjour) und legt je Gerät eine Instanz „HomeKit Gerät“ samt Client Socket an.

### Inhaltsverzeichnis

1. [Funktionsumfang](#1-funktionsumfang)
2. [Voraussetzungen](#2-voraussetzungen)
3. [Software-Installation](#3-software-installation)
4. [Einrichten der Instanzen in Symcon](#4-einrichten-der-instanzen-in-symcon)

### 1. Funktionsumfang

* Zeigt je HomeKit-Gerät Name, Modell, Kategorie, HomeKit-ID, Adresse und ob es koppelbar ist („ja“, „anderswo gekoppelt“ oder „mit Symcon gekoppelt“).
* Ordnet vorhandene Instanzen über die HomeKit-ID zu; Instanzen, deren Gerät gerade nicht im Netz ist, bleiben als „nicht gefunden“ sichtbar.
* „Erstellen“ legt das Gerät und seinen Client Socket mit der gefundenen Adresse an.

### 2. Voraussetzungen

- Symcon 8.1 oder neuer mit der DNS-SD-Steuerung (Bonjour). Im Docker ohne Bonjour bleibt die Liste leer; dort das Gerät von Hand mit fester Adresse anlegen.

### 3. Software-Installation

* Über das Module Control folgende URL hinzufügen:
  `https://github.com/da8ter/HomeKitController`

### 4. Einrichten der Instanzen in Symcon

Instanz „HomeKit Konfigurator“ anlegen und öffnen. Steht bei einem Gerät „nein (anderswo gekoppelt)“, muss es zuerst in Apple Home entfernt werden; danach das Formular neu öffnen. Bonjour-Ergebnisse schwanken gelegentlich: Fehlt ein Gerät, das Formular erneut öffnen.

Nach dem Erstellen in der Geräteinstanz den HomeKit-Code eingeben und koppeln (siehe [HomeKit Gerät](../HomeKitDevice/README.md)).
