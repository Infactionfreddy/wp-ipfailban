# WP IP Fail Ban

WordPress-Plugin, das IPv4-Subnetze nach wiederholten fehlgeschlagenen Login-Versuchen vorübergehend sperrt (ähnlich wie ipfailban). Gesperrte Subnetze lassen sich im WordPress-Adminbereich einsehen und entbannen.

![PHP](https://img.shields.io/badge/PHP-777BB4?logo=php&logoColor=white)
![WordPress](https://img.shields.io/badge/WordPress-Plugin-21759B?logo=wordpress&logoColor=white)
![Lizenz: MIT](https://img.shields.io/badge/Lizenz-MIT-green)

## Features

- Überwacht fehlgeschlagene WordPress-Logins (Hook `wp_login_failed`)
- Sperrt das gesamte IPv4-Subnetz (Standard: /24) nach einem konfigurierbaren Schwellenwert (Standard: 5 Versuche)
- Automatische Entsperrung nach Ablauf der Bannzeit (Standard: 3600 Sekunden)
- Admin-Menü „IP Fail Ban“ mit Übersicht der gebannten Subnetze und Entbannen-Funktion
- Keine eigenen Datenbanktabellen: Speicherung über die WordPress Options-API

## Tech-Stack

- PHP (Einzeldatei-Plugin)
- WordPress Plugin-API (Actions, Filter, Options-API, Admin-Menü)

## Schnellstart

### Voraussetzungen

- WordPress-Installation mit Dateizugriff auf `wp-content/plugins/`
- PHP mit aktivierter Standard-Funktionalität (`filter_var`, `ip2long`); die genaue Mindestversion ist nicht angegeben (Annahme: PHP 7.0+ wegen Short-Array-Syntax und Closures)

### Installation

1. `ip-failban.php` in das Verzeichnis `wp-content/plugins/` kopieren (optional in einen eigenen Ordner, z. B. `wp-content/plugins/ip-failban/`).
2. Im WordPress-Dashboard unter **Plugins** das Plugin **IP Fail Ban** aktivieren.

### Start

Nach der Aktivierung arbeitet das Plugin automatisch. Gebannte Subnetze sind im Admin-Menü unter **IP Fail Ban** sichtbar.

## Konfiguration

Es gibt keine Umgebungsvariablen. Die Einstellungen sind Klasseneigenschaften in `ip-failban.php`:

| Eigenschaft | Standard | Bedeutung |
|---|---|---|
| `$failThreshold` | `5` | Anzahl fehlgeschlagener Logins bis zum Bann |
| `$banTime` | `3600` | Bann- und Zählfenster in Sekunden |
| `$subnetMask` | `24` | Präfixlänge des IPv4-Subnetzes |

Details: [docs/KONFIGURATION.md](docs/KONFIGURATION.md)

## Projektstruktur

```
.
├── README.md
└── ip-failban.php   # Plugin-Code (Klasse IPFailBan + Hooks + Admin-Seite)
```

## Dokumentation

- [Architektur](docs/ARCHITEKTUR.md)
- [Installation](docs/INSTALLATION.md)
- [Konfiguration](docs/KONFIGURATION.md)
- [Entwicklung](docs/ENTWICKLUNG.md)
- [API](docs/API.md)

## Lizenz

MIT License, Copyright (c) 2025 Infactionfreddy. Der vollständige Lizenztext stand bisher in dieser README; eine separate `LICENSE`-Datei existiert nicht im Repository (Empfehlung: anlegen).

```
MIT License

Copyright (c) 2025 Infactionfreddy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
