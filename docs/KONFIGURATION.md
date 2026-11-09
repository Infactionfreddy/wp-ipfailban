# Konfiguration

[← Zurück zur README](../README.md)

Das Plugin liest keine Umgebungsvariablen und bietet keine Einstellungsseite. Konfiguriert wird durch direktes Ändern der privaten Eigenschaften der Klasse `IPFailBan` in `ip-failban.php`.

## Einstellungen

| Eigenschaft | Standard | Beschreibung |
|---|---|---|
| `$failThreshold` | `5` | Fehlversuche innerhalb des Zeitfensters, ab denen gebannt wird |
| `$banTime` | `3600` | Sekunden; gilt sowohl als Dauer des Banns als auch als Zeitfenster für das Zählen der Fehlversuche |
| `$subnetMask` | `24` | Präfixlänge (CIDR) zur Gruppierung der IPv4-Adressen; sinnvoll 1–32 (Annahme: 0 wird nicht geprüft und führt zu unerwartetem Verhalten) |
| `$optionAttempts` | `ipfailban_failed_attempts` | Name der WordPress-Option für Fehlversuche |
| `$optionBlocked` | `ipfailban_blocked_subnets` | Name der WordPress-Option für gebannte Subnetze |

## Umgebungsvariablen

Keine.

## Gespeicherte Optionen

| Option | Struktur |
|---|---|
| `ipfailban_failed_attempts` | `['192.0.2.0/24' => [Zeitstempel, ...]]` |
| `ipfailban_blocked_subnets` | `['192.0.2.0/24' => Ban-Ende als Unix-Zeitstempel]` |

## Hooks und Filter

Das Plugin registriert folgende WordPress-Hooks (es stellt selbst keine eigenen Hooks bereit):

| Hook | Typ | Priorität | Zweck |
|---|---|---|---|
| `wp_login_failed` | Action | Standard (10) | Fehlversuch registrieren |
| `authenticate` | Filter | 1 (3 Argumente) | Login bei Bann verweigern |
| `admin_menu` | Action | Standard (10) | Admin-Seite `ip-failban-admin` registrieren |

## Berechtigungen

| Element | Anforderung |
|---|---|
| Menüseite „IP Fail Ban“ | Capability `manage_options` |

## Hinweise

- Hinter Reverse-Proxys oder CDNs enthält `REMOTE_ADDR` evtl. die Proxy-IP; dann würden alle Besucher als ein Subnetz gelten.
- Änderungen an `$subnetMask` wirken sich nicht auf bereits gespeicherte Einträge aus, da diese unter dem alten Subnetz-Schlüssel liegen.