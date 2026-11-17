# ShodanCheck
Multi-threaded Windows desktop GUI (Python &amp; CustomTkinter) for querying Shodan, validating open ports and HTTP/HTTPS endpoints at scale, grabbing banners, and managing custom URL suffixes with CSV/JSON export.
# 🛡️ ShodanCheck — Multi-Threaded IP, Port & Endpoint Validator

**ShodanCheck** ist eine moderne, performante Windows-Desktop-Anwendung (entwickelt mit Python und CustomTkinter) zum schnellen Suchen, Validieren und Analysieren von Netzwerk-Endpunkten über die Shodan-API oder eigene IP-Listen.

---

## ✨ Features

* **Shodan-API-Integration & Pagination:** Direkte Suche nach Shodan-Queries inkl. seitenweisem Nachladen (`➕ Nächste 100 laden`), ohne bestehende Ergebnisse oder Markierungen zu überschreiben.
* **Integrierter Demo-Modus:** Mit dem Suchbegriff `demo` lässt sich die Anwendung auch ohne hinterlegten Shodan-API-Key sofort testen.
* **Multi-Threaded Port- & HTTP-Scanner:** Konfigurierbare Thread-Anzahl (`10` bis `100` gleichzeitige Threads) mit sofortiger Abbruchmöglichkeit (`⏹ Scan abbrechen`) unter Beibehaltung der bis dahin geprüften Ergebnisse.
* **Live Server-Antwort & Banner-Grabbing:** Prüft offene Ports automatisch auf HTTP/HTTPS-Statuscodes (`200 OK`, `401`, `403`, `404`), extrahiert HTML-Seitentitel (`<title>`) oder liest rohe TCP-Banner aus.
* **Flexibler Link-Builder & Rescan:** Dynamisches Anhängen von URL-Suffixen (nach Port, ohne Port, nach letztem `/` oder ab frei wählbarem Zeichen-Index) sowie optionaler HTTPS-Zwang (`🔒 HTTPS erzwingen`) und erneute Prüfung (`Rescan`).
* **Optimiert für große Listen (8.000+ IPs):** Asynchroner Datei-Import (`.txt` / `.csv`), verzögerungsfreie In-Place-Zeilenaktualisierung beim Öffnen von Links und seitenweise Tabellenansicht (100 Einträge pro Seite) für flüssiges Arbeiten ohne UI-Freezes.
* **Persistenz & Verlauf:** Automatisches Speichern der letzten Sitzung (`session_state.json`), dauerhafte Markierung bereits besuchter Endpunkte (`visited_history.json`) sowie eine Suchhistorie.
* **Export:** Speichern der Prüfergebnisse inklusive Status, besuchtem Zustand und Server-Antwort als **CSV** oder **JSON**.

---

## 🖥️ Benutzeroberfläche (Menüband-Aufbau)

Die Oberfläche ist in ein übersichtliches 4-Tab-Menüband unterteilt, um maximale Breite für die Ergebnistabelle zu schaffen:

1. **🔍 Suche & Scan:** Suchanfrage, Ziel-Port, Scan-Start und seitenweises Nachladen (`Nächste 100`).
2. **🔗 Links & Rescan:** URL-Suffix, Einfügeposition, HTTPS-Schalter und erneutes Prüfen angepasster URLs.
3. **📂 Import, Export & Historie:** Import eigener IP-Listen (`.txt`/`.csv`), CSV/JSON-Export, Suchhistorie-Auswahl und Zurücksetzen von Besuchsmarkierungen.
4. **⚙️ Einstellungen:** Lokale Speicherung des Shodan-API-Keys und Auswahl der gleichzeitigen Scan-Threads (`10`–`100`).

---

## 🚀 Installation & Start (aus dem Quellcode)

### Voraussetzungen
* Python **3.10** oder neuer
* Windows 10 / 11 (empfohlen)

### 1. Repository klonen & Abhängigkeiten installieren
```bash
git clone [https://github.com/](https://github.com/)<DEIN-USERNAME>/ShodanCheck.git
cd ShodanCheck
pip install customtkinter shodan
