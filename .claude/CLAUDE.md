# HomeKit Controller (Bibliothek für Symcon)

Symcon als HomeKit-Steuerzentrale (HAP over IP): koppelt HomeKit-Geräte mit ihrem 8-stelligen Code, hält eine verschlüsselte Dauerverbindung und spiegelt Dienste und Merkmale als Variablen. Erster Anwendungsfall: Aqara FP2 (Präsenz je Zone, Helligkeit). Kein Apple Home, keine Cloud. Öffentliches Repo `da8ter/HomeKitController`, Zweig `main`.

Plan: `~/.claude/plans/schau-dir-mal-die-modular-sunrise.md` (freigegeben 17.10.2026). Betriebsdaten dieses Rechners: `CLAUDE.local.md` (nicht eingecheckt).

## Aufbau

- **`libs/`** – reine Bausteine ohne Symcon:
  - `HapTlv8` (TLV8 mit Fragmenten, Fehlercodes im Klartext)
  - `HapSrp` (SRP-6a, 3072 Bit, SHA-512; Gruppe und Hash einstellbar für die RFC-5054-Vektoren)
  - `HapCrypto` (HKDF-SHA512, ChaCha20-Poly1305, Ed25519, X25519 über sodium)
  - `HapSession` (verschlüsselte Rahmen; zustandslos, Zähler und Rest gehen hinein und heraus)
  - `HapHttp` (HTTP/1.1 und `EVENT/1.0`, Content-Length und chunked)
  - `HapPairing` (`/pair-setup` M1–M6, `/pair-verify` M1–M4, `/pairings`)
- **`tools/hap_cli.php`** – Diagnose ohne Symcon: `pair`, `listen`, `unpair`. Die Kopplungsdatei enthält den privaten Schlüssel, deshalb immer außerhalb des Repos ablegen.
- **`HomeKitDevice/`** (`HKC`, Typ 3, Kind eines eigenen Client Socket): Kopplung (`HKC_Pair`, `HKC_Unpair`, `HKC_ForgetPairing`), Sitzung, Variablen je bekanntem Merkmal (Ident `A<aid>_I<iid>`, Name aus dem Dienstnamen, z. B. FP2-Zonen), Ereignisse, `RequestAction` für schreibbare Merkmale. Traits `libs/HkcConnection.php` (Sitzungszustand im Puffer `S` unter Semaphor, Antwort-Warteschlange `q`) und `libs/HkcVariables.php`; Bausteine `HapModel` (Merkmal → Art/Typ) und `HkcSecretStore` (Kopplung verschlüsselt, Schlüsseldatei `HomeKitController.key`, 0600).
  - Adresse: per Bonjour über die HomeKit-ID (`Resolve`, TXT `id=`), Ports ändern sich nach Neustarts; feste Adresse nur als Ausweichweg.
  - Timer `Watch` (60 s): nach Fehler neu verbinden, nach 5 min Stille Werte nachlesen, nach 10 min Stille neu verbinden.
  - Timer `Reconnect`: **nie** aus `ReceiveData` heraus `IPS_ApplyChanges` am eigenen Client Socket aufrufen – der Socket blockiert sich dann selbst („Instanz ist belegt“, danach Zustand 104 trotz Open=true, nur ein Kernel-Neustart löst ihn; Docker 17.10.2026).
  - Geht der Sitzungszustand verloren (Reload, Kernelstart) bei offener Verbindung, wird neu verbunden: Das Gerät erwartet auf der alten Verbindung verschlüsselte Rahmen. Ebenso bei neuer Adresse (Bonjour) oder wenn der Socket trotz Open=true nicht aktiv ist.
  - **Semaphor-Regeln** (Review 18.10.2026): `lock()` liefert `false` nach 5 s, dann wird der Aufruf übersprungen, nie ohne Sperre weitergearbeitet. `sessionClosed()` sperrt ebenfalls. Jede Sitzung trägt eine Generation `gen`; `resetSession()` erhöht sie. `receive()` ignoriert Bytes, wenn die Sitzung `closed`/`error` ist.
  - **Fehler in /pair-verify** = Kopplung ungültig (zurückgesetztes oder getauschtes Gerät): genau ein Log-Eintrag, Status 202, kein Dauerversuch. Weg zurück: „Kopplung lokal löschen“, dann neu koppeln (im Docker geprüft).
  - `GET /accessories` wird nur bei Status < 300 und gültigem JSON übernommen; sonst Fehler, damit nie ein leeres Modell alle Variablen löscht.
  - Werte aus der Geräteliste kommen nur in **neu angelegte** Variablen; bestehende behalten die Ereigniswerte (ApplyChanges überschreibt nichts).
  - Fehlertexte der Bausteine sind englische Schlüssel (`Schritt: Text`), das Modul übersetzt beide Teile (`translateError`).
- **`HomeKitConfigurator/`** (`HKCC`, Typ 4): listet `_hap._tcp` über die DNS-SD-Steuerung (TXT `id`, `md`, `ci`, `sf`; `sf=1` = koppelbar), legt Gerät + eigenen Client Socket als Kette an, ordnet Instanzen über die HomeKit-ID zu, ein Gerät je ID (Bonjour meldet es sonst je Schnittstelle). Bonjour-Ergebnisse der DNS-SD-Steuerung schwanken (auf der SymBox fehlten am 17.10.2026 bei einer Abfrage beide FP2, die Minuten vorher gelistet waren): Formular neu öffnen; das Gerät behält die zuletzt gefundene Adresse. Im Docker gibt es kein Bonjour (Bridge-Netz).
- Alle Module `IPSModuleStrict`, Darstellungen statt Profilen.

## Prüfen

```bash
php tests/hap_lib_test.php   # TLV8, SRP gegen RFC 5054, Kopplung/Sitzung gegen ein simuliertes Gerät, Rahmen, HTTP, Modell
php -l <Datei>
```

Gegenprobe mit einer unabhängigen Implementierung: HAP-python als Test-Gerät (Python ≤ 3.12; 3.14 bricht an `asyncio.SafeChildWatcher`). Rezept in `.claude/docs/testen.md`.

## Regeln

- **Commits:** ein Thema je Commit, deutsche Botschaft, **ohne** Co-Authored-By-Zeile. Prüfungen vorher.
- **Nie** `git checkout`/`git restore` auf Dateien.
- **Push und Release nur auf Zuruf.** Release: `build` und `date` in `library.json`.
- **Öffentliches Repo:** keine IP-Adressen, HomeKit-Codes, Geräte-IDs echter Geräte, Kopplungsdateien, Instanz-IDs, Pfade unter `/Users/`.
- **Echte Geräte:** Kopplungsversuche an einem echten Gerät (FP2) nur auf Zusage und erst, wenn alles gegen HAP-python grün ist. Mehrere Fehlversuche sperren das Gerät (`kTLVError_MaxTries`).
- **Geheimnisse:** Langzeitschlüssel nie im Klartext in Eigenschaften oder Attributen (`settings.json` ist weltlesbar). Sitzungsschlüssel nur im Puffer.
- **Symcon-Plattformwissen** (HEX-Datenfluss bei Module Strict, Objektgrenzen, Puffergrenzen, Geheimnisse): `../List/.claude/docs/plattform/`.
