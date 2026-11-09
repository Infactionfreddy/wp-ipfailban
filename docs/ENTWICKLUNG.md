# Entwicklung

[← Zurück zur README](../README.md)

## Lokale Entwicklungsumgebung

1. Eine lokale WordPress-Instanz bereitstellen (z. B. mit Docker, LocalWP oder `wp-env`).
2. Repository in `wp-content/plugins/` klonen oder die Datei verlinken:
   ```bash
   ln -s /pfad/zu/wp-ipfailban /pfad/zu/wordpress/wp-content/plugins/wp-ipfailban
   ```
3. Plugin aktivieren und `WP_DEBUG` in `wp-config.php` einschalten.

## Code-Struktur

| Bereich in `ip-failban.php` | Inhalt |
|---|---|
| Plugin-Header | Name, Beschreibung, Version 1.1, Autor |
| Klasse `IPFailBan` | `get_subnet()` (privat), `register_failed_login()`, `is_blocked()`, `get_blocked_subnets()`, `unban_subnet()` |
| Globale Instanz | `$ipFailBan` |
| Hooks | `wp_login_failed`, `authenticate`, `admin_menu` (als Closures) |

## Tests

Im Repository sind keine automatisierten Tests vorhanden. Manuell prüfen:

1. Mit falschem Passwort fünfmal einloggen; danach muss der Login mit der Meldung zum gesperrten Subnetz abgelehnt werden.
2. Im Admin-Menü (von einem anderen Subnetz oder per WP-CLI) prüfen, dass das Subnetz mit Ban-Ende erscheint.
3. „Entbannen“ klicken und Login erneut testen.
4. Nach Ablauf von `$banTime` muss der Login wieder möglich sein.

Empfehlung: PHPUnit mit WP-Test-Suite oder Brain Monkey ergänzen, insbesondere für `get_subnet()` und die Schwellenwertlogik.

## Coding-Standards

Es ist kein Standard konfiguriert. Empfohlen (Annahme): WordPress Coding Standards via PHP_CodeSniffer:

```bash
phpcs --standard=WordPress ip-failban.php
```

Verbesserungsvorschläge: Nonce und Capability-Prüfung beim Entbannen, POST statt GET für Zustandsänderungen, Text-Domain für Übersetzungen, Unterstützung von IPv6, konfigurierbare Einstellungen.

## Release-Ablauf

Ein automatisierter Release-Prozess ist nicht vorhanden. Vorschlag:

1. `Version` im Plugin-Header erhöhen.
2. Änderungen in der README dokumentieren.
3. Git-Tag setzen (z. B. `v1.2`) und auf GitHub ein Release mit der `ip-failban.php` bzw. einem ZIP erstellen.