# Architektur

[← Zurück zur README](../README.md)

## Überblick

Das Plugin besteht aus einer einzigen Datei, `ip-failban.php`. Sie enthält die Klasse `IPFailBan` (Logik und Speicherung) sowie die WordPress-Hooks, die diese Klasse an Login-Vorgang und Admin-Menü anbinden. Eine Instanz wird global als `$ipFailBan` erzeugt.

## Komponenten

| Komponente | Typ | Aufgabe |
|---|---|---|
| `IPFailBan` | Klasse | Subnetzberechnung, Zählen der Fehlversuche, Bann-Prüfung, Entbannen |
| `wp_login_failed` | Action | Registriert jeden fehlgeschlagenen Login für die Client-IP |
| `authenticate` (Priorität 1) | Filter | Bricht die Authentifizierung mit `WP_Error` ab, wenn das Subnetz gebannt ist |
| `admin_menu` | Action | Fügt die Seite „IP Fail Ban“ (`ip-failban-admin`) hinzu |
| Option `ipfailban_failed_attempts` | Datenspeicher | Zeitstempel der Fehlversuche je Subnetz |
| Option `ipfailban_blocked_subnets` | Datenspeicher | Subnetz => Unix-Zeitstempel des Bann-Endes |

## Datenfluss

```mermaid
sequenceDiagram
    participant B as Browser
    participant WP as WordPress
    participant P as IPFailBan
    participant DB as wp_options
    B->>WP: Login-Versuch
    WP->>P: Filter authenticate (Prio 1)
    P->>DB: ipfailban_blocked_subnets lesen
    alt Subnetz gebannt
        P-->>WP: WP_Error ip_banned
        WP-->>B: Login abgelehnt
    else nicht gebannt
        WP->>WP: Zugangsdaten prüfen
        opt Login fehlgeschlagen
            WP->>P: Action wp_login_failed
            P->>DB: Fehlversuch speichern
            P->>DB: ggf. Subnetz bannen
        end
    end
```

## Bann-Logik

```mermaid
flowchart TD
    A[Fehlversuch von IP] --> B{IPv4 gültig?}
    B -- nein --> Z[Ignorieren]
    B -- ja --> C[Subnetz berechnen, z. B. 192.0.2.0/24]
    C --> D[Zeitstempel hinzufügen, ältere als banTime entfernen]
    D --> E{Anzahl >= failThreshold?}
    E -- ja --> F[Bann bis jetzt + banTime]
    E -- nein --> G[Nur speichern]
```

## Hinweise

- Nur IPv4 wird unterstützt; andere Adressen ergeben kein Subnetz und werden weder gezählt noch gesperrt.
- Abgelaufene Banns werden beim nächsten `is_blocked()`-Aufruf für das Subnetz entfernt; die Übersicht blendet abgelaufene Einträge aus.
- Die Client-IP stammt aus `$_SERVER['REMOTE_ADDR']`.