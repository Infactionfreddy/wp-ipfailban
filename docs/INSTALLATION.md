# Installation

[← Zurück zur README](../README.md)

## Voraussetzungen

- Laufende WordPress-Installation (Mindestversion nicht angegeben)
- Schreibzugriff auf `wp-content/plugins/` (FTP, SSH o. Ä.)
- PHP-Version: nicht festgelegt (Annahme: PHP 7.0 oder neuer)
- Administratorrechte im WordPress-Dashboard (Capability `manage_options`)

## Schritt-für-Schritt

1. Repository herunterladen oder klonen:
   ```bash
   git clone https://github.com/Infactionfreddy/wp-ipfailban.git
   ```
2. Optional einen Plugin-Ordner anlegen und die Datei kopieren:
   ```bash
   mkdir -p /pfad/zu/wordpress/wp-content/plugins/ip-failban
   cp wp-ipfailban/ip-failban.php /pfad/zu/wordpress/wp-content/plugins/ip-failban/
   ```
   Alternativ genügt die Datei direkt in `wp-content/plugins/`.
3. Im Dashboard unter **Plugins** **IP Fail Ban** aktivieren.
4. Prüfen, ob links im Menü der Eintrag **IP Fail Ban** erscheint.

## Update

1. Neue Version von `ip-failban.php` über die bestehende Datei kopieren.
2. Eigene Anpassungen (`$failThreshold`, `$banTime`, `$subnetMask`) erneut eintragen, da sie im Code stehen und überschrieben werden.

## Deinstallation

1. Plugin im Dashboard deaktivieren und löschen (bzw. Datei entfernen).
2. Das Plugin enthält keinen Uninstall-Hook. Die Optionen `ipfailban_failed_attempts` und `ipfailban_blocked_subnets` bleiben in `wp_options` bestehen. Manuell entfernen, z. B. mit WP-CLI:
   ```bash
   wp option delete ipfailban_failed_attempts
   wp option delete ipfailban_blocked_subnets
   ```

## Hinweis bei Selbstaussperrung

Bei einer Sperre des eigenen Subnetzes die Option `ipfailban_blocked_subnets` per WP-CLI oder Datenbank löschen oder die Plugin-Datei temporär umbenennen.