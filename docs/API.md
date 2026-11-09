# API

[← Zurück zur README](../README.md)

Das Plugin stellt keine HTTP-Endpunkte (REST/AJAX) und keine eigenen Hooks bereit. Die öffentlichen Methoden der Klasse `IPFailBan` bilden die interne Schnittstelle; die Instanz liegt in der globalen Variablen `$ipFailBan`.

## Öffentliche Methoden

| Methode | Parameter | Rückgabe | Beschreibung |
|---|---|---|---|
| `register_failed_login($ip)` | `string $ip` IPv4-Adresse | `void` | Zählt einen Fehlversuch für das Subnetz; bannt bei Erreichen von `$failThreshold` |
| `is_blocked($ip)` | `string $ip` | `bool` | `true`, wenn das Subnetz der IP aktuell gebannt ist; entfernt abgelaufene Banns |
| `get_blocked_subnets()` | – | `array` | Aktive Banns als `Subnetz => Ban-Ende (Unix-Zeitstempel)` |
| `unban_subnet($subnet)` | `string $subnet` z. B. `192.0.2.0/24` | `void` | Hebt den Bann des Subnetzes auf |

Die Methode `get_subnet($ip)` ist privat und liefert für gültige IPv4-Adressen eine Zeichenkette wie `192.0.2.0/24`, sonst `false`.

## Admin-Oberfläche

| Pfad | Parameter | Beschreibung |
|---|---|---|
| `wp-admin/admin.php?page=ip-failban-admin` | – | Übersicht der gebannten Subnetze (Capability `manage_options`) |
| `wp-admin/admin.php?page=ip-failban-admin&unban=<subnet>` | `unban` (GET) | Entbannt das angegebene Subnetz; ohne Nonce-Prüfung |

## Fehlercodes

| Code | Quelle | Meldung |
|---|---|---|
| `ip_banned` | `WP_Error` im Filter `authenticate` | „Your subnet is temporarily blocked due to repeated failed logins.“ |

## Beispiel

```php
global $ipFailBan;
if ($ipFailBan->is_blocked('192.0.2.15')) {
    // Subnetz 192.0.2.0/24 ist gesperrt
}
```