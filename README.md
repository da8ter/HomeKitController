# HomeKit Controller (Symcon)

Symcon als HomeKit-Steuerzentrale: Geräte, die HomeKit über IP sprechen, werden direkt gekoppelt und über eine verschlüsselte Dauerverbindung ausgelesen. Ohne Apple Home, ohne Home Assistant, ohne Cloud. Erster Anwendungsfall ist der Präsenzmelder **Aqara FP2** (Anwesenheit je Zone, Helligkeit), der sonst nur über HomeKit erreichbar ist.

## Inhaltsverzeichnis

1. [Funktionsumfang](#1-funktionsumfang)
2. [Voraussetzungen](#2-voraussetzungen)
3. [Enthaltene Module](#3-enthaltene-module)
4. [Einrichten](#4-einrichten)
5. [PHP-Befehle](#5-php-befehle)
6. [Versionshistorie](#6-versionshistorie)

## 1. Funktionsumfang

- **Kopplung** mit dem 8-stelligen HomeKit-Code des Geräts (Aufkleber am Gerät oder in der Hersteller-App), wie es eine HomeKit-Zentrale tut. Symcon wird die Steuerzentrale des Geräts; eine zweite Zentrale (Apple Home) lässt ein HomeKit-Gerät nicht zu.
- **Verschlüsselte Dauerverbindung** nach HomeKit-Standard; Ereignisse des Geräts kommen sofort an, ohne Abfragen.
- **Variablen aus den Diensten des Geräts:** Anwesenheit, Bewegung, Helligkeit, Temperatur, Luftfeuchte, Kontakt, Schalter, Helligkeit (dimmbar), Batterie. Jede Variable trägt den Namen ihres Dienstes; beim FP2 entstehen so eine Variable je Zone. Umbenennen in Symcon bleibt erhalten. Schaltbare Merkmale lassen sich aus Symcon heraus setzen.
- **Geräte finden** per Bonjour: Der Konfigurator listet alle HomeKit-Geräte im Netz mit Modell, Kategorie und ob sie koppelbar sind; ein Klick legt das Gerät samt Verbindung an. Das Gerät wird über seine HomeKit-ID wiedergefunden, auch wenn sich Adresse oder Port nach einem Neustart ändern.
- **Selbstheilung:** Wiederverbinden nach Verbindungsabbruch oder Neustart des Geräts, Kontroll-Lesen bei längerer Stille, Statusvariable „Verbunden“.
- **Sicherheit:** Die Kopplung (Langzeitschlüssel) liegt verschlüsselt in der Instanz; der Schlüssel dazu steht in einer Datei im Symcon-Verzeichnis, die nur der Symcon-Dienst lesen darf.

## 2. Voraussetzungen

- Symcon 8.1 oder neuer mit der DNS-SD-Steuerung (Bonjour; für die Gerätesuche)
- Das Gerät im selben Netz, mit der Hersteller-App eingerichtet (beim FP2: Aqara-App für WLAN, Zonen und Empfindlichkeit)
- Das Gerät darf nicht mehr in Apple Home gekoppelt sein

## 3. Enthaltene Module

- **HomeKit Gerät** (Gerät, Präfix `HKC`): ein HomeKit-Gerät an einem eigenen Client Socket. Kopplung, Verbindung, Variablen, Ereignisse.
- **HomeKit Konfigurator** (Konfigurator, Präfix `HKCC`): Liste der HomeKit-Geräte im Netz, legt Geräte an.

## 4. Einrichten

1. Das Gerät in **Apple Home entfernen**, falls es dort gekoppelt war (Kachel gedrückt halten → Einstellungen → „Gerät entfernen“). In der Hersteller-App bleibt es erhalten.
2. **HomeKit Konfigurator** anlegen. Die Liste zeigt die Geräte im Netz; in der Spalte „Koppelbar“ muss „ja“ stehen. Das Gerät auswählen und **Erstellen**: Es entstehen die Instanz „HomeKit Gerät“ und ihr Client Socket.
3. In der Geräteinstanz den **HomeKit-Code** eingeben und **Koppeln** drücken. Nach wenigen Sekunden steht die Instanz auf „Verbunden“, die Variablen sind angelegt.
4. Die Variablen nach Bedarf umbenennen (z. B. Zonen „Sofa“, „Esstisch“) und in die Visualisierung verlinken.

Ohne Bonjour (z. B. Symcon im Docker) lässt sich die Instanz von Hand anlegen: HomeKit-ID, feste Adresse und Port eintragen.

**Mehrere Fehlversuche sperren die Kopplung am Gerät** vorübergehend. Bei „Falscher HomeKit-Code“ den Code prüfen, bevor es weitergeht.

**Gerät zurückgesetzt?** Dann kennt es Symcon nicht mehr; die Instanz zeigt „Kopplung ungültig“. In der Instanz „Kopplung lokal löschen“ und neu koppeln.

## 5. PHP-Befehle

```php
HKC_Pair(int $InstanzID, string $Code): string           // koppeln, Rückgabe ist die Meldung für den Nutzer
HKC_Unpair(int $InstanzID): string                       // Kopplung beim Gerät aufheben und hier löschen
HKC_ForgetPairing(int $InstanzID): string                // Kopplung nur hier löschen (Gerät zurückgesetzt)
HKC_Reconnect(int $InstanzID): void                      // Verbindung neu aufbauen
HKC_Resolve(int $InstanzID): bool                        // Adresse per Bonjour nachführen, true bei Änderung
```

Schaltbare Merkmale werden wie jede Symcon-Variable gesetzt: `RequestAction($VariablenID, $Wert)`.

Zum Prüfen ohne Symcon liegt [tools/hap_cli.php](tools/hap_cli.php) bei: `pair`, `listen` (zeigt Dienste und Ereignisse) und `unpair` gegen ein HomeKit-Gerät. Die Kopplungsdatei enthält den privaten Schlüssel; außerhalb des Repos ablegen.

## 6. Versionshistorie

- **0.1, Build 1**: Erste Version: Kopplung und verschlüsselte Sitzung nach HomeKit (SRP-6a, Ed25519, X25519, ChaCha20-Poly1305), Variablen je Dienst mit Darstellungen, Ereignisse, Wiederverbinden, Bonjour-Suche, Konfigurator. Geprüft gegen HAP-python und zwei Aqara FP2.
