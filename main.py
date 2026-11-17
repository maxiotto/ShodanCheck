import customtkinter as ctk
from tkinter import filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import urllib.error
import ssl
import threading
import socket
import webbrowser
import json
import csv
import os
import re

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

CONFIG_FILE = "config.json"
SESSION_FILE = "session_state.json"
HISTORY_FILE = "visited_history.json"
SEARCH_HISTORY_FILE = "search_history.json"
TABLE_PAGE_SIZE = 100


class ShodanCheckApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ShodanCheck — IP, Port & Endpoint Validator")
        self.geometry("1360x820")
        self.minsize(1100, 660)

        self.results = []
        self.filtered_indices = []
        self.table_page = 0
        self.filter_after_id = None
        self.row_widgets = {}
        self.is_scanning = False
        self.stop_event = threading.Event()
        self.current_page = 1
        self.active_query = ""
        self.active_port = 80
        self.total_shodan_matches = 0
        self.history_map = {}

        self.api_key = self.load_api_key()
        self.visited_history = self.load_visited_history()
        self.search_history = self.load_search_history()

        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE

        self._build_ui()
        self._refresh_history_dropdown()
        self.load_session()

    def load_api_key(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f).get("shodan_api_key", "")
            except Exception:
                return ""
        return ""

    def save_api_key(self, key):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump({"shodan_api_key": key}, f, indent=2)
        self.api_key = key

    def load_visited_history(self):
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return set(data) if isinstance(data, list) else set()
            except Exception:
                return set()
        return set()

    def save_visited_history_async(self):
        snapshot = sorted(list(self.visited_history))
        def _write():
            try:
                with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                    json.dump(snapshot, f, indent=2)
            except Exception:
                pass
        threading.Thread(target=_write, daemon=True).start()

    def load_search_history(self):
        if os.path.exists(SEARCH_HISTORY_FILE):
            try:
                with open(SEARCH_HISTORY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
            except Exception:
                return []
        return []

    def save_search_history(self):
        try:
            with open(SEARCH_HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self.search_history[:25], f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def add_to_search_history(self, query, port):
        self.search_history = [
            entry for entry in self.search_history
            if not (entry.get("query") == query and entry.get("port") == port)
        ]
        self.search_history.insert(0, {"query": query, "port": port})
        self.search_history = self.search_history[:25]
        self.save_search_history()
        self.after(0, self._refresh_history_dropdown)

    def clear_search_history(self):
        self.search_history = []
        self.save_search_history()
        self._refresh_history_dropdown()
        self._set_status("Suchhistorie gelöscht.", "#60a5fa")

    def save_session(self):
        state = {
            "query": self.query_entry.get(),
            "port": self.port_entry.get(),
            "active_query": self.active_query,
            "active_port": self.active_port,
            "current_page": self.current_page,
            "total_shodan_matches": self.total_shodan_matches,
            "threads": self.threads_menu.get(),
            "suffix": self.suffix_entry.get(),
            "suffix_mode": self.suffix_mode.get(),
            "suffix_index": self.index_entry.get(),
            "force_https": self.force_https_var.get(),
            "only_ok": self.only_ok_var.get(),
            "only_unvisited": self.only_unvisited_var.get(),
            "results": [dict(r) for r in self.results],
        }
        def _write():
            try:
                with open(SESSION_FILE, "w", encoding="utf-8") as f:
                    json.dump(state, f, indent=2, ensure_ascii=False)
            except Exception:
                pass
        threading.Thread(target=_write, daemon=True).start()

    def load_session(self):
        if not os.path.exists(SESSION_FILE):
            return
        try:
            with open(SESSION_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)

            self.query_entry.delete(0, "end")
            self.query_entry.insert(0, state.get("query", ""))

            self.port_entry.delete(0, "end")
            self.port_entry.insert(0, state.get("port", "80"))

            self.active_query = state.get("active_query", state.get("query", ""))
            self.active_port = int(state.get("active_port", state.get("port", 80)))
            self.current_page = int(state.get("current_page", 1))
            self.total_shodan_matches = int(state.get("total_shodan_matches", 0))

            saved_threads = str(state.get("threads", "40"))
            if saved_threads in ("10", "20", "40", "60", "100"):
                self.threads_menu.set(saved_threads)

            self.suffix_entry.delete(0, "end")
            self.suffix_entry.insert(0, state.get("suffix", ""))

            mode = state.get("suffix_mode", "Nach Port (http://IP:Port + Suffix)")
            self.suffix_mode.set(mode)
            if mode == "Ab Zeichen-Position (Index)":
                self.index_entry.pack(side="left", padx=(0, 8))

            self.index_entry.delete(0, "end")
            self.index_entry.insert(0, state.get("suffix_index", "15"))

            self.force_https_var.set(state.get("force_https", False))
            self.only_ok_var.set(state.get("only_ok", False))
            self.only_unvisited_var.set(state.get("only_unvisited", False))

            self.results = state.get("results", [])
            for item in self.results:
                key = f"{item['ip']}:{item['port']}"
                if key in self.visited_history:
                    item["visited"] = True
                if "response_info" not in item:
                    item["response_info"] = ""

            self._update_next_page_btn()

            if self.results:
                self._apply_suffix_to_all(save=False)
                self._update_dashboard_and_table(save=False, reset_page=True)
                self._set_status(
                    f"Sitzung geladen ({len(self.results)} Einträge).", "#60a5fa"
                )
        except Exception:
            pass

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # =====================================================================
        # 1. TOP-BAR & MENÜBAND (RIBBON-TABS)
        # =====================================================================
        ribbon_wrapper = ctk.CTkFrame(self, corner_radius=0, fg_color="#18181b")
        ribbon_wrapper.grid(row=0, column=0, sticky="ew")
        ribbon_wrapper.grid_columnconfigure(0, weight=1)

        # Obere Tab-Leiste mit App-Logo links & Menüband-Reitern
        tab_header = ctk.CTkFrame(ribbon_wrapper, fg_color="transparent")
        tab_header.grid(row=0, column=0, padx=18, pady=(10, 6), sticky="ew")

        ctk.CTkLabel(
            tab_header,
            text="🛡️ ShodanCheck",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left", padx=(0, 20))

        self.ribbon_tabs = ctk.CTkSegmentedButton(
            tab_header,
            values=[
                "🔍 Suche & Scan",
                "🔗 Links & Rescan",
                "📂 Import, Export & Historie",
                "⚙️ Einstellungen"
            ],
            font=ctk.CTkFont(size=13, weight="bold"),
            height=30,
            command=self._switch_ribbon_tab
        )
        self.ribbon_tabs.set("🔍 Suche & Scan")
        self.ribbon_tabs.pack(side="left")

        # Container für die aktive Menüband-Leiste
        self.ribbon_body = ctk.CTkFrame(ribbon_wrapper, fg_color="#222226", corner_radius=8)
        self.ribbon_body.grid(row=1, column=0, padx=18, pady=(0, 12), sticky="ew")
        self.ribbon_body.grid_columnconfigure(0, weight=1)

        self.ribbon_panels = {}
        self._build_ribbon_search_panel()
        self._build_ribbon_links_panel()
        self._build_ribbon_data_panel()
        self._build_ribbon_settings_panel()
        self._switch_ribbon_tab("🔍 Suche & Scan")

        # =====================================================================
        # 2. KOMPAKTE KPI-ÜBERSICHT
        # =====================================================================
        kpi_frame = ctk.CTkFrame(self, fg_color="transparent")
        kpi_frame.grid(row=1, column=0, padx=18, pady=(10, 8), sticky="ew")
        kpi_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.kpi_total = self._create_kpi_card(kpi_frame, 0, "Gefundene IPs", "0")
        self.kpi_ok = self._create_kpi_card(kpi_frame, 1, "Port Aktiv (OK)", "0", "#4ade80")
        self.kpi_visited = self._create_kpi_card(kpi_frame, 2, "Bereits angeschaut", "0 / 0", "#60a5fa")
        self.kpi_closed = self._create_kpi_card(kpi_frame, 3, "Nicht erreichbar", "0", "#f87171")

        # =====================================================================
        # 3. FILTER & SEITEN-NAVIGATION
        # =====================================================================
        filter_bar = ctk.CTkFrame(self, fg_color="transparent")
        filter_bar.grid(row=2, column=0, padx=18, pady=(2, 6), sticky="ew")

        self.only_ok_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            filter_bar, text="Nur aktive Dienste (OK)", variable=self.only_ok_var,
            command=lambda: self._refresh_table(save=True, reset_page=True)
        ).pack(side="left", padx=(0, 16))

        self.only_unvisited_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            filter_bar, text="Nur noch nicht angeschaute", variable=self.only_unvisited_var,
            command=lambda: self._refresh_table(save=True, reset_page=True)
        ).pack(side="left", padx=(0, 16))

        pager_frame = ctk.CTkFrame(filter_bar, fg_color="transparent")
        pager_frame.pack(side="left", padx=(10, 0))

        self.prev_tbl_btn = ctk.CTkButton(
            pager_frame, text="◀", width=28, height=26, fg_color="#2b2b2b", hover_color="#3a3a3a",
            command=self._prev_table_page
        )
        self.prev_tbl_btn.pack(side="left", padx=(0, 6))

        self.page_info_label = ctk.CTkLabel(
            pager_frame, text="Seite 1 / 1 (0 Einträge)", font=ctk.CTkFont(size=12, weight="bold")
        )
        self.page_info_label.pack(side="left", padx=4)

        self.next_tbl_btn = ctk.CTkButton(
            pager_frame, text="▶", width=28, height=26, fg_color="#2b2b2b", hover_color="#3a3a3a",
            command=self._next_table_page
        )
        self.next_tbl_btn.pack(side="left", padx=(6, 0))

        self.filter_entry = ctk.CTkEntry(
            filter_bar, placeholder_text="🔎 Schnellfilter (IP, Info, Link, Server-Antwort...)", width=290
        )
        self.filter_entry.pack(side="right")
        self.filter_entry.bind("<KeyRelease>", self._on_filter_key)

        # =====================================================================
        # 4. ERGEBNIS-TABELLE (VOLLE FENSTERBREITE)
        # =====================================================================
        self.table_frame = ctk.CTkScrollableFrame(self, label_text="Prüfergebnisse, Links & Server-Antwort")
        self.table_frame.grid(row=3, column=0, padx=18, pady=(0, 8), sticky="nsew")
        self.table_frame.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        self._render_table_headers()

        # =====================================================================
        # 5. SCHLANKE STATUSLEISTE UNTEN
        # =====================================================================
        footer = ctk.CTkFrame(self, height=34, corner_radius=0, fg_color="#18181b")
        footer.grid(row=4, column=0, sticky="ew")
        footer.grid_columnconfigure(1, weight=1)

        self.progress_bar = ctk.CTkProgressBar(footer, width=200, height=8)
        self.progress_bar.grid(row=0, column=0, padx=(18, 12), pady=10)
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(
            footer, text="Bereit.", text_color="#4ade80", font=ctk.CTkFont(size=12)
        )
        self.status_label.grid(row=0, column=1, sticky="w", pady=8)

        self.stop_btn = ctk.CTkButton(
            footer,
            text="⏹ Scan abbrechen",
            width=125,
            height=24,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#dc2626",
            hover_color="#991b1b",
            state="disabled",
            command=self._request_stop_scan
        )
        self.stop_btn.grid(row=0, column=2, padx=(10, 18), pady=6)

    # --- RIBBON PANELS ---
    def _build_ribbon_search_panel(self):
        panel = ctk.CTkFrame(self.ribbon_body, fg_color="transparent")
        panel.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(panel, text="Suchanfrage:", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, padx=(14, 8), pady=10
        )
        self.query_entry = ctk.CTkEntry(
            panel, placeholder_text='z.B. synology country:"DE" oder "demo" für Testdaten'
        )
        self.query_entry.grid(row=0, column=1, padx=(0, 12), pady=10, sticky="ew")
        self.query_entry.bind("<Return>", lambda e: self._start_shodan_search(load_next_page=False))

        ctk.CTkLabel(panel, text="Port:", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=2, padx=(0, 6), pady=10
        )
        self.port_entry = ctk.CTkEntry(panel, placeholder_text="8080", width=85)
        self.port_entry.grid(row=0, column=3, padx=(0, 12), pady=10)
        self.port_entry.insert(0, "80")
        self.port_entry.bind("<Return>", lambda e: self._start_shodan_search(load_next_page=False))

        self.search_btn = ctk.CTkButton(
            panel,
            text="🔍 Suchen & Prüfen",
            font=ctk.CTkFont(weight="bold"),
            command=lambda: self._start_shodan_search(load_next_page=False)
        )
        self.search_btn.grid(row=0, column=4, padx=(0, 8), pady=10)

        self.next_page_btn = ctk.CTkButton(
            panel,
            text="➕ Nächste 100 laden",
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            font=ctk.CTkFont(weight="bold"),
            state="disabled",
            command=lambda: self._start_shodan_search(load_next_page=True)
        )
        self.next_page_btn.grid(row=0, column=5, padx=(0, 14), pady=10)

        self.ribbon_panels["🔍 Suche & Scan"] = panel

    def _build_ribbon_links_panel(self):
        panel = ctk.CTkFrame(self.ribbon_body, fg_color="transparent")

        ctk.CTkLabel(panel, text="Link-Suffix:", font=ctk.CTkFont(weight="bold")).pack(
            side="left", padx=(14, 8), pady=10
        )
        self.suffix_entry = ctk.CTkEntry(
            panel, placeholder_text="z.B. /photo, /admin oder ?status=1", width=260
        )
        self.suffix_entry.pack(side="left", padx=(0, 12), pady=10)
        self.suffix_entry.bind("<KeyRelease>", lambda e: self._apply_suffix_to_all())

        ctk.CTkLabel(panel, text="Einfügen ab:").pack(side="left", padx=(0, 6), pady=10)

        self.suffix_mode = ctk.CTkOptionMenu(
            panel,
            values=[
                "Nach Port (http://IP:Port + Suffix)",
                "Ohne Port (http://IP + Suffix)",
                "Ab Zeichen-Position (Index)",
                "Nach letztem '/'"
            ],
            command=self._on_suffix_mode_change,
            width=225
        )
        self.suffix_mode.pack(side="left", padx=(0, 8), pady=10)

        self.index_entry = ctk.CTkEntry(panel, placeholder_text="Pos.", width=55)
        self.index_entry.insert(0, "15")
        self.index_entry.bind("<KeyRelease>", lambda e: self._apply_suffix_to_all())

        self.force_https_var = ctk.BooleanVar(value=False)
        self.https_switch = ctk.CTkSwitch(
            panel,
            text="🔒 HTTPS erzwingen",
            variable=self.force_https_var,
            font=ctk.CTkFont(weight="bold"),
            command=self._apply_suffix_to_all
        )
        self.https_switch.pack(side="left", padx=(10, 14), pady=10)

        self.rescan_btn = ctk.CTkButton(
            panel,
            text="🔄 Alle Links neu prüfen (Rescan)",
            fg_color="#d97706",
            hover_color="#b45309",
            font=ctk.CTkFont(weight="bold"),
            command=self._start_rescan
        )
        self.rescan_btn.pack(side="right", padx=(0, 14), pady=10)

        self.ribbon_panels["🔗 Links & Rescan"] = panel

    def _build_ribbon_data_panel(self):
        panel = ctk.CTkFrame(self.ribbon_body, fg_color="transparent")

        self.import_btn = ctk.CTkButton(
            panel, text="📂 IP-Liste importieren (.txt/.csv)", command=self._import_ip_list
        )
        self.import_btn.pack(side="left", padx=(14, 10), pady=10)

        ctk.CTkButton(
            panel, text="💾 CSV Export", width=110, fg_color="#1f6aa5",
            command=lambda: self._export_results("csv")
        ).pack(side="left", padx=(0, 6), pady=10)

        ctk.CTkButton(
            panel, text="💾 JSON Export", width=115, fg_color="#1f6aa5",
            command=lambda: self._export_results("json")
        ).pack(side="left", padx=(0, 14), pady=10)

        ctk.CTkLabel(panel, text="🕒 Suchhistorie:", font=ctk.CTkFont(weight="bold")).pack(
            side="left", padx=(6, 6), pady=10
        )

        self.history_menu = ctk.CTkOptionMenu(
            panel,
            values=["Keine Suchen gespeichert"],
            width=230,
            command=self._on_history_selected
        )
        self.history_menu.pack(side="left", padx=(0, 6), pady=10)

        ctk.CTkButton(
            panel, text="🗑️", width=32, fg_color="#2b2b2b", hover_color="#3a3a3a",
            command=self.clear_search_history
        ).pack(side="left", padx=(0, 14), pady=10)

        ctk.CTkButton(
            panel, text="↺ Markierungen zurücksetzen", fg_color="#2b2b2b", hover_color="#3a3a3a",
            command=self._reset_current_visited
        ).pack(side="right", padx=(0, 14), pady=10)

        self.ribbon_panels["📂 Import, Export & Historie"] = panel

    def _build_ribbon_settings_panel(self):
        panel = ctk.CTkFrame(self.ribbon_body, fg_color="transparent")

        ctk.CTkLabel(panel, text="Shodan API-Key:", font=ctk.CTkFont(weight="bold")).pack(
            side="left", padx=(14, 8), pady=10
        )
        self.api_entry = ctk.CTkEntry(panel, placeholder_text="API Key eingeben...", show="*", width=290)
        self.api_entry.pack(side="left", padx=(0, 8), pady=10)
        if self.api_key:
            self.api_entry.insert(0, self.api_key)

        ctk.CTkButton(
            panel, text="💾 Speichern", width=105, fg_color="#15803d", hover_color="#166534",
            command=self._on_save_key
        ).pack(side="left", padx=(0, 24), pady=10)

        ctk.CTkLabel(panel, text="⚡ Gleichzeitige Scan-Threads:", font=ctk.CTkFont(weight="bold")).pack(
            side="left", padx=(0, 8), pady=10
        )
        self.threads_menu = ctk.CTkOptionMenu(
            panel,
            values=["10", "20", "40", "60", "100"],
            width=85,
            command=lambda _: self.save_session()
        )
        self.threads_menu.set("40")
        self.threads_menu.pack(side="left", padx=(0, 10), pady=10)

        ctk.CTkLabel(
            panel, text="(40 = Standard • 100 = Max. Speed für große Listen)",
            text_color="gray", font=ctk.CTkFont(size=12)
        ).pack(side="left", pady=10)

        self.ribbon_panels["⚙️ Einstellungen"] = panel

    def _switch_ribbon_tab(self, tab_name):
        for name, panel in self.ribbon_panels.items():
            if name == tab_name:
                panel.grid(row=0, column=0, sticky="ew")
            else:
                panel.grid_forget()

    def _refresh_history_dropdown(self):
        self.history_map.clear()
        if not self.search_history:
            self.history_menu.configure(values=["Keine Suchen gespeichert"])
            self.history_menu.set("Keine Suchen gespeichert")
            return

        labels = []
        for entry in self.search_history:
            q = entry.get("query", "")
            p = entry.get("port", 80)
            label = f"{q}  [Port {p}]"
            labels.append(label)
            self.history_map[label] = (q, p)

        self.history_menu.configure(values=labels)
        self.history_menu.set(labels[0])

    def _on_history_selected(self, choice):
        if choice not in self.history_map:
            return
        query, port = self.history_map[choice]
        self.query_entry.delete(0, "end")
        self.query_entry.insert(0, query)
        self.port_entry.delete(0, "end")
        self.port_entry.insert(0, str(port))
        self.ribbon_tabs.set("🔍 Suche & Scan")
        self._switch_ribbon_tab("🔍 Suche & Scan")
        self._set_status(f"Suche aus Historie geladen: '{query}' (Port {port})", "#60a5fa")

    def _request_stop_scan(self):
        if self.is_scanning and not self.stop_event.is_set():
            self.stop_event.set()
            self.stop_btn.configure(state="disabled", text="Stoppt…")
            self._set_status("Breche laufenden Scan ab (übernehme bisherige Ergebnisse)...", "#f87171")

    def _on_filter_key(self, event=None):
        if self.filter_after_id is not None:
            self.after_cancel(self.filter_after_id)
        self.filter_after_id = self.after(250, lambda: self._refresh_table(save=False, reset_page=True))

    def _prev_table_page(self):
        if self.table_page > 0:
            self.table_page -= 1
            self._render_current_table_page()

    def _next_table_page(self):
        total_pages = max(1, (len(self.filtered_indices) + TABLE_PAGE_SIZE - 1) // TABLE_PAGE_SIZE)
        if self.table_page + 1 < total_pages:
            self.table_page += 1
            self._render_current_table_page()

    def _update_next_page_btn(self):
        can_load_more = bool(self.active_query and self.active_query.lower() != "demo" and len(self.results) > 0)
        if can_load_more:
            next_p = self.current_page + 1
            self.next_page_btn.configure(text=f"➕ Nächste 100 (S.{next_p})", state="normal")
        else:
            self.next_page_btn.configure(text="➕ Nächste 100 laden", state="disabled")

    def _on_suffix_mode_change(self, choice):
        if choice == "Ab Zeichen-Position (Index)":
            self.index_entry.pack(side="left", padx=(0, 8), after=self.suffix_mode)
        else:
            self.index_entry.pack_forget()
        self._apply_suffix_to_all()

    def _get_effective_protocol(self, default_protocol):
        return "https" if self.force_https_var.get() else default_protocol

    def _build_custom_url(self, ip, port, default_protocol):
        protocol = self._get_effective_protocol(default_protocol)
        base_url = f"{protocol}://{ip}:{port}"
        suffix = self.suffix_entry.get().strip()
        mode = self.suffix_mode.get()

        if mode == "Nach Port (http://IP:Port + Suffix)":
            target = f"{protocol}://{ip}:{port}"
        elif mode == "Ohne Port (http://IP + Suffix)":
            target = f"{protocol}://{ip}"
        elif mode == "Nach letztem '/'":
            last_slash = base_url.rfind("/")
            target = base_url[:last_slash + 1] if last_slash > 7 else base_url + "/"
            suffix = suffix.lstrip("/")
        elif mode == "Ab Zeichen-Position (Index)":
            try:
                pos = max(0, int(self.index_entry.get().strip()))
            except ValueError:
                pos = len(base_url)
            target = base_url[:pos]
        else:
            target = base_url

        if not suffix:
            return target

        if mode != "Ab Zeichen-Position (Index)" and not suffix.startswith(("/", "?", "#", ":")) and not target.endswith("/"):
            return f"{target}/{suffix}"
        return f"{target}{suffix}"

    def _apply_suffix_to_all(self, save=True):
        if not self.results:
            if save:
                self.save_session()
            return
        for idx, item in enumerate(self.results):
            if item["status"] == "OK":
                item["url"] = self._build_custom_url(
                    item["ip"], item["port"], item["protocol"]
                )
                if idx in self.row_widgets and "link_btn" in self.row_widgets[idx]:
                    prefix = "✓" if item["visited"] else "🌐"
                    self.row_widgets[idx]["link_btn"].configure(text=f"{prefix} {item['url']}")
        if save:
            self.save_session()

    def _create_kpi_card(self, parent, col, title, value, color="white"):
        card = ctk.CTkFrame(parent)
        card.grid(row=0, column=col, padx=5, sticky="ew")
        ctk.CTkLabel(card, text=title, text_color="gray", font=ctk.CTkFont(size=12)).pack(pady=(6, 0))
        val_label = ctk.CTkLabel(card, text=value, text_color=color, font=ctk.CTkFont(size=20, weight="bold"))
        val_label.pack(pady=(1, 6))
        return val_label

    def _render_table_headers(self):
        headers = ["IP-Adresse", "Port", "Status", "Shodan Info / Quelle", "Aktion (Browser-Link)", "Server-Antwort"]
        for idx, text in enumerate(headers):
            lbl = ctk.CTkLabel(self.table_frame, text=text, font=ctk.CTkFont(weight="bold"))
            lbl.grid(row=0, column=idx, padx=8, pady=8, sticky="w")

    def _on_save_key(self):
        key = self.api_entry.get().strip()
        self.save_api_key(key)
        self._set_status("API-Key lokal gespeichert.", "#4ade80")

    def _set_status(self, msg, color="white"):
        self.status_label.configure(text=msg, text_color=color)

    def _set_controls_state(self, state):
        self.search_btn.configure(state=state)
        self.rescan_btn.configure(state=state)
        self.import_btn.configure(state=state)
        self.threads_menu.configure(state=state)
        if state == "disabled":
            self.next_page_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal", text="⏹ Scan abbrechen")
        else:
            self.stop_btn.configure(state="disabled", text="⏹ Scan abbrechen")
            self._update_next_page_btn()

    def _get_target_port(self):
        try:
            port = int(self.port_entry.get().strip())
            if 1 <= port <= 65535:
                return port
        except ValueError:
            pass
        messagebox.showerror("Ungültiger Port", "Bitte gib eine gültige Portnummer zwischen 1 und 65535 ein.")
        return None

    def _get_thread_count(self):
        try:
            return int(self.threads_menu.get())
        except ValueError:
            return 40

    def _update_kpis_only(self):
        total = len(self.results)
        ok_count = sum(1 for r in self.results if r["status"] == "OK")
        visited_count = sum(1 for r in self.results if r["status"] == "OK" and r["visited"])
        closed_count = total - ok_count

        self.kpi_total.configure(text=str(total))
        self.kpi_ok.configure(text=str(ok_count))
        self.kpi_visited.configure(text=f"{visited_count} / {ok_count}")
        self.kpi_closed.configure(text=str(closed_count))

    def _update_single_row_visuals(self, idx):
        if idx not in self.row_widgets:
            return
        item = self.results[idx]
        w = self.row_widgets[idx]
        is_ok = item["status"] == "OK"
        is_visited = item["visited"]

        row_text_color = "#888888" if is_visited else "white"
        status_color = "#60a5fa" if is_visited else ("#4ade80" if is_ok else "#f87171")
        status_text = "✓ ANGESCHAUT" if is_visited else f"● {item['status']}"

        w["ip"].configure(text_color=row_text_color)
        w["port"].configure(text_color=row_text_color)
        w["status"].configure(text=status_text, text_color=status_color)
        w["info"].configure(text_color=row_text_color)

        if "link_btn" in w:
            btn_color = "#334155" if is_visited else "#15803d"
            btn_hover = "#475569" if is_visited else "#166534"
            btn_prefix = "✓" if is_visited else "🌐"
            w["link_btn"].configure(
                text=f"{btn_prefix} {item['url']}",
                fg_color=btn_color,
                hover_color=btn_hover
            )
        if "toggle_btn" in w:
            w["toggle_btn"].configure(text="↺" if is_visited else "✓")

        resp_text = item.get("response_info", "")
        resp_color = "#666666" if is_visited else self._get_response_color(resp_text, is_ok)
        w["resp"].configure(text_color=resp_color)

    def _open_and_mark_visited(self, idx):
        item = self.results[idx]
        url = item["url"]
        threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()

        if not item["visited"]:
            item["visited"] = True
            self.visited_history.add(f"{item['ip']}:{item['port']}")
            self.save_visited_history_async()
            self._update_kpis_only()

            if self.only_unvisited_var.get():
                self._refresh_table(save=True, reset_page=False)
            else:
                self._update_single_row_visuals(idx)
                self.save_session()

    def _toggle_visited(self, idx):
        item = self.results[idx]
        item["visited"] = not item["visited"]
        key = f"{item['ip']}:{item['port']}"
        if item["visited"]:
            self.visited_history.add(key)
        else:
            self.visited_history.discard(key)
        self.save_visited_history_async()
        self._update_kpis_only()

        if self.only_unvisited_var.get():
            self._refresh_table(save=True, reset_page=False)
        else:
            self._update_single_row_visuals(idx)
            self.save_session()

    def _reset_current_visited(self):
        if not self.results:
            return
        for item in self.results:
            item["visited"] = False
            self.visited_history.discard(f"{item['ip']}:{item['port']}")
        self.save_visited_history_async()
        self._update_dashboard_and_table(save=True, reset_page=False)
        self._set_status("Markierungen der aktuellen Liste zurückgesetzt.", "#60a5fa")

    def _start_shodan_search(self, load_next_page=False):
        if self.is_scanning:
            return

        if load_next_page:
            if not self.active_query:
                return
            query = self.active_query
            port = self.active_port
            target_page = self.current_page + 1
            self.query_entry.delete(0, "end")
            self.query_entry.insert(0, query)
            self.port_entry.delete(0, "end")
            self.port_entry.insert(0, str(port))
        else:
            query = self.query_entry.get().strip()
            port = self._get_target_port()
            if not port:
                return
            if not query:
                messagebox.showwarning("Eingabe fehlt", "Bitte gib einen Suchbegriff ein (oder 'demo' zum Testen).")
                return
            target_page = 1

        thread_limit = self._get_thread_count()
        self.stop_event.clear()
        self.is_scanning = True
        self._set_controls_state("disabled")
        self.progress_bar.set(0)
        self._set_status(f"Suche auf Shodan (Seite {target_page}) nach '{query}'...", "#60a5fa")

        threading.Thread(
            target=self._worker_shodan_and_scan,
            args=(query, port, thread_limit, target_page, load_next_page),
            daemon=True
        ).start()

    def _worker_shodan_and_scan(self, query, port, thread_limit, page, append_mode):
        targets = []
        total_available = 0
        try:
            if query.lower() == "demo":
                targets = [
                    {"ip": "1.1.1.1", "info": "Cloudflare DNS (Demo)"},
                    {"ip": "8.8.8.8", "info": "Google DNS (Demo)"},
                    {"ip": "93.184.216.34", "info": "Example.com (Demo)"},
                    {"ip": "192.0.2.1", "info": "Test-Net Offline (Demo)"},
                    {"ip": "208.67.222.222", "info": "OpenDNS (Demo)"},
                    {"ip": "9.9.9.9", "info": "Quad9 (Demo)"},
                ]
                total_available = len(targets)
            else:
                if not SHODAN_AVAILABLE:
                    raise RuntimeError("Das Paket 'shodan' ist nicht installiert (pip install shodan).")
                if not self.api_key:
                    raise RuntimeError("Kein Shodan API-Key hinterlegt! (Unter Tab '⚙️ Einstellungen' eintragen)")

                api = shodan.Shodan(self.api_key)
                full_query = query if "port:" in query else f"{query} port:{port}"
                res = api.search(full_query, page=page, limit=100)
                total_available = res.get("total", 0)
                for match in res.get("matches", []):
                    ip = match.get("ip_str")
                    org = match.get("org", "Unbekannt")
                    product = match.get("product", "")
                    targets.append({"ip": ip, "info": f"{org} {product}".strip()})

            if self.stop_event.is_set():
                self.after(0, lambda: self._set_status("Suche abgebrochen.", "#f87171"))
                return

            self.active_query = query
            self.active_port = port
            self.current_page = page
            self.total_shodan_matches = total_available

            if not append_mode:
                self.add_to_search_history(query, port)

            if append_mode:
                existing_keys = {f"{r['ip']}:{r['port']}" for r in self.results}
                targets = [t for t in targets if f"{t['ip']}:{port}" not in existing_keys]

            if not targets and append_mode:
                self.after(0, lambda: self._set_status(
                    f"Seite {page}: Keine weiteren neuen IPs gefunden (Gesamt auf Shodan: {total_available}).",
                    "#60a5fa"
                ))
                self.after(0, self.save_session)
                return

            self.after(0, lambda: self._set_status(
                f"Seite {page}: {len(targets)} Ziele gefunden. Starte Scan ({thread_limit} Threads)...", "#facc15"
            ))
            self._run_port_checks_parallel(targets, port, thread_limit, append=append_mode)

        except Exception as e:
            self.after(0, lambda err=str(e): messagebox.showerror("Fehler", err))
            self.after(0, lambda: self._set_status("Fehler bei der Abfrage.", "#f87171"))
        finally:
            self.is_scanning = False
            self.after(0, lambda: self._set_controls_state("normal"))

    def _start_rescan(self):
        if self.is_scanning:
            return
        if not self.results:
            messagebox.showinfo("Keine Einträge", "Es sind noch keine Ergebnisse zum erneuten Prüfen vorhanden.")
            return

        self._apply_suffix_to_all(save=False)
        thread_limit = self._get_thread_count()

        self.stop_event.clear()
        self.is_scanning = True
        self._set_controls_state("disabled")
        self.progress_bar.set(0)
        self._set_status(f"Rescan von {len(self.results)} Links ({thread_limit} Threads)...", "#facc15")

        threading.Thread(target=self._worker_rescan, args=(thread_limit,), daemon=True).start()

    def _worker_rescan(self, thread_limit):
        try:
            targets = [{"ip": r["ip"], "info": r["info"], "port": r["port"]} for r in self.results]
            self._run_port_checks_parallel(targets, default_port=None, thread_limit=thread_limit, append=False)
        finally:
            self.is_scanning = False
            self.after(0, lambda: self._set_controls_state("normal"))

    def _import_ip_list(self):
        if self.is_scanning:
            return
        port = self._get_target_port()
        if not port:
            return

        file_path = filedialog.askopenfilename(
            title="IP-Liste auswählen",
            filetypes=[("Text & CSV Dateien", "*.txt *.csv"), ("Alle Dateien", "*.*")]
        )
        if not file_path:
            return

        thread_limit = self._get_thread_count()
        self.stop_event.clear()
        self.is_scanning = True
        self._set_controls_state("disabled")
        self.progress_bar.set(0)
        self._set_status(f"Lese '{os.path.basename(file_path)}' im Hintergrund ein...", "#60a5fa")

        threading.Thread(
            target=self._worker_parse_and_import_scan, args=(file_path, port, thread_limit), daemon=True
        ).start()

    def _worker_parse_and_import_scan(self, file_path, port, thread_limit):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if self.stop_event.is_set():
                self.after(0, lambda: self._set_status("Import abgebrochen.", "#f87171"))
                return

            raw_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
            ips = list(dict.fromkeys(raw_ips))
            if not ips:
                self.after(0, lambda: messagebox.showinfo(
                    "Keine IPs", "In der ausgewählten Datei wurden keine IPv4-Adressen gefunden."
                ))
                self.after(0, lambda: self._set_status("Keine gültigen IPs in Datei.", "#f87171"))
                return

            if self.stop_event.is_set():
                self.after(0, lambda: self._set_status("Import abgebrochen.", "#f87171"))
                return

            self.active_query = ""
            self.current_page = 1
            self.total_shodan_matches = 0

            source_name = f"Import ({os.path.basename(file_path)})"
            targets = [{"ip": ip, "info": source_name} for ip in ips]

            self.after(0, lambda: self._set_status(
                f"{len(targets)} eindeutige IPs geladen. Starte Scan ({thread_limit} Threads)...", "#facc15"
            ))
            self._run_port_checks_parallel(targets, port, thread_limit, append=False)
        except Exception as e:
            self.after(0, lambda err=str(e): messagebox.showerror("Import-Fehler", err))
            self.after(0, lambda: self._set_status("Import fehlgeschlagen.", "#f87171"))
        finally:
            self.is_scanning = False
            self.after(0, lambda: self._set_controls_state("normal"))

    def _probe_endpoint_response(self, url, ip, port, timeout=2.5):
        if url.startswith(("http://", "https://")):
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShodanCheck/1.0"}
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=self.ssl_ctx) as resp:
                    code = resp.getcode()
                    raw = resp.read(2048).decode("utf-8", errors="ignore")
                    snippet = self._extract_response_summary(raw, resp.headers)
                    return f"{code} OK — {snippet}" if snippet else f"{code} OK"
            except urllib.error.HTTPError as e:
                raw = ""
                try:
                    raw = e.read(1024).decode("utf-8", errors="ignore")
                except Exception:
                    pass
                snippet = self._extract_response_summary(raw, e.headers)
                reason = e.reason or "HTTP Error"
                return f"{e.code} {reason} — {snippet}" if snippet else f"{e.code} {reason}"
            except Exception as e:
                banner = self._grab_tcp_banner(ip, port, timeout=1.2)
                if banner:
                    return f"Banner: {banner}"
                err_msg = str(e.reason) if hasattr(e, "reason") else str(e)
                return f"Keine HTTP-Antwort ({err_msg[:28]})"

        banner = self._grab_tcp_banner(ip, port, timeout=1.5)
        return f"Banner: {banner}" if banner else "Port offen (kein Banner)"

    def _extract_response_summary(self, html_text, headers):
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
        if title_match:
            clean_title = re.sub(r"\s+", " ", title_match.group(1)).strip()
            if clean_title:
                return clean_title[:42]

        server_hdr = headers.get("Server", "") if headers else ""
        cleaned_body = re.sub(r"<[^>]+>", " ", html_text)
        cleaned_body = re.sub(r"\s+", " ", cleaned_body).strip()
        if cleaned_body:
            return cleaned_body[:42]
        if server_hdr:
            return f"Server: {server_hdr[:32]}"
        return ""

    def _grab_tcp_banner(self, ip, port, timeout=1.2):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                data = s.recv(256)
                text = data.decode("utf-8", errors="ignore").strip()
                text = re.sub(r"[\r\n\t]+", " ", text)
                return text[:42] if text else ""
        except Exception:
            return ""

    def _check_single_target(self, item, default_port, timeout=1.5):
        if self.stop_event.is_set():
            return None

        ip = item["ip"]
        port = item.get("port", default_port)
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                is_open = True
        except Exception:
            is_open = False

        if self.stop_event.is_set() and not is_open:
            return None

        default_protocol = "https" if port in (443, 8443, 9443) else "http"
        final_url = self._build_custom_url(ip, port, default_protocol) if is_open else ""
        already_visited = f"{ip}:{port}" in self.visited_history

        if is_open and not self.stop_event.is_set():
            response_info = self._probe_endpoint_response(final_url, ip, port)
        elif is_open:
            response_info = "Port offen (Scan gestoppt)"
        else:
            response_info = "Keine Verbindung (Timeout/Closed)"

        return {
            "ip": ip,
            "port": port,
            "protocol": default_protocol,
            "status": "OK" if is_open else "CLOSED",
            "info": item["info"],
            "url": final_url,
            "response_info": response_info,
            "visited": already_visited
        }

    def _run_port_checks_parallel(self, targets, default_port, thread_limit=40, append=False):
        total = len(targets)
        if total == 0:
            if not append:
                self.results = []
            self.after(0, lambda: self._update_dashboard_and_table(save=True, reset_page=True))
            self.after(0, lambda: self._set_status("Keine Ziele gefunden.", "#f87171"))
            return

        ordered_results = [None] * total
        completed = 0
        max_workers = max(1, min(thread_limit, total))
        update_step = max(3, total // 120)

        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            future_to_idx = {
                executor.submit(self._check_single_target, item, default_port): idx
                for idx, item in enumerate(targets)
            }

            for future in as_completed(future_to_idx):
                if self.stop_event.is_set():
                    for f in future_to_idx:
                        f.cancel()
                    break

                idx = future_to_idx[future]
                try:
                    res = future.result()
                except Exception:
                    res = None

                if res is not None:
                    ordered_results[idx] = res
                    completed += 1

                    if completed % update_step == 0 or completed == total:
                        prog = completed / total
                        self.after(0, lambda p=prog, c=completed, t=total, w=max_workers: (
                            self.progress_bar.set(p),
                            self._set_status(f"Prüfe Endpoints ({w} Threads): {c} / {t}...", "#facc15")
                        ))
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        valid_results = [r for r in ordered_results if r is not None]
        was_stopped = self.stop_event.is_set()

        if append:
            self.results.extend(valid_results)
        else:
            self.results = valid_results

        previously_seen = sum(1 for r in valid_results if r["visited"])

        self.after(0, lambda: self._update_dashboard_and_table(save=True, reset_page=(not append)))

        if was_stopped:
            status_msg = f"⏹ Abgebrochen! {len(valid_results)} / {total} Ziele geprüft (übernommen)."
            self.after(0, lambda: self._set_status(status_msg, "#facc15"))
        else:
            status_msg = f"Fertig! +{len(valid_results)} Ziele geprüft" if append else f"Fertig! {len(valid_results)} Ziele geprüft"
            if self.total_shodan_matches > 0:
                status_msg += f" (Shodan Gesamt: {self.total_shodan_matches:,})".replace(",", ".")
            if previously_seen > 0:
                status_msg += f" • {previously_seen} bereits angeschaut"
            self.after(0, lambda: self._set_status(status_msg, "#4ade80"))

    def _update_dashboard_and_table(self, save=True, reset_page=False):
        self._update_kpis_only()
        self._refresh_table(save=save, reset_page=reset_page)

    def _get_response_color(self, resp_text, is_ok):
        if not is_ok:
            return "gray"
        if resp_text.startswith(("200", "201", "204", "301", "302")):
            return "#4ade80"
        if resp_text.startswith(("401", "403")):
            return "#facc15"
        if resp_text.startswith(("404", "500", "502", "503", "Keine HTTP")):
            return "#f87171"
        return "#93c5fd"

    def _refresh_table(self, save=True, reset_page=False):
        if save:
            self.save_session()

        only_ok = self.only_ok_var.get()
        only_unvisited = self.only_unvisited_var.get()
        text_filter = self.filter_entry.get().strip().lower()

        new_filtered = []
        for idx, item in enumerate(self.results):
            if only_ok and item["status"] != "OK":
                continue
            if only_unvisited and item["visited"]:
                continue

            resp_text = item.get("response_info", "")
            if text_filter and (
                text_filter not in item["ip"].lower()
                and text_filter not in item["info"].lower()
                and text_filter not in item["url"].lower()
                and text_filter not in resp_text.lower()
            ):
                continue
            new_filtered.append(idx)

        self.filtered_indices = new_filtered
        if reset_page:
            self.table_page = 0
        else:
            total_pages = max(1, (len(self.filtered_indices) + TABLE_PAGE_SIZE - 1) // TABLE_PAGE_SIZE)
            if self.table_page >= total_pages:
                self.table_page = max(0, total_pages - 1)

        self._render_current_table_page()

    def _render_current_table_page(self):
        for widget in self.table_frame.winfo_children():
            widget.destroy()
        self.row_widgets.clear()
        self._render_table_headers()

        total_filtered = len(self.filtered_indices)
        total_pages = max(1, (total_filtered + TABLE_PAGE_SIZE - 1) // TABLE_PAGE_SIZE)
        current_p = min(self.table_page, total_pages - 1)

        self.page_info_label.configure(
            text=f"Seite {current_p + 1} / {total_pages} ({total_filtered} Treffer)"
        )
        self.prev_tbl_btn.configure(state="normal" if current_p > 0 else "disabled")
        self.next_tbl_btn.configure(state="normal" if current_p + 1 < total_pages else "disabled")

        start = current_p * TABLE_PAGE_SIZE
        end = min(start + TABLE_PAGE_SIZE, total_filtered)
        page_slice = self.filtered_indices[start:end]

        row_idx = 1
        for idx in page_slice:
            item = self.results[idx]
            resp_text = item.get("response_info", "")
            is_ok = item["status"] == "OK"
            is_visited = item["visited"]
            status_color = "#4ade80" if is_ok else "#f87171"
            row_text_color = "#888888" if is_visited else "white"

            w_dict = {}

            w_dict["ip"] = ctk.CTkLabel(self.table_frame, text=item["ip"], text_color=row_text_color)
            w_dict["ip"].grid(row=row_idx, column=0, padx=8, pady=4, sticky="w")

            w_dict["port"] = ctk.CTkLabel(self.table_frame, text=str(item["port"]), text_color=row_text_color)
            w_dict["port"].grid(row=row_idx, column=1, padx=8, pady=4, sticky="w")

            status_text = "✓ ANGESCHAUT" if is_visited else f"● {item['status']}"
            w_dict["status"] = ctk.CTkLabel(
                self.table_frame,
                text=status_text,
                text_color="#60a5fa" if is_visited else status_color,
                font=ctk.CTkFont(weight="bold")
            )
            w_dict["status"].grid(row=row_idx, column=2, padx=8, pady=4, sticky="w")

            w_dict["info"] = ctk.CTkLabel(self.table_frame, text=item["info"][:34], text_color=row_text_color)
            w_dict["info"].grid(row=row_idx, column=3, padx=8, pady=4, sticky="w")

            if is_ok:
                action_cell = ctk.CTkFrame(self.table_frame, fg_color="transparent")
                action_cell.grid(row=row_idx, column=4, padx=8, pady=3, sticky="w")

                btn_color = "#334155" if is_visited else "#15803d"
                btn_hover = "#475569" if is_visited else "#166534"
                btn_prefix = "✓" if is_visited else "🌐"

                w_dict["link_btn"] = ctk.CTkButton(
                    action_cell,
                    text=f"{btn_prefix} {item['url']}",
                    height=26,
                    fg_color=btn_color,
                    hover_color=btn_hover,
                    command=lambda i=idx: self._open_and_mark_visited(i)
                )
                w_dict["link_btn"].pack(side="left", padx=(0, 5))

                w_dict["toggle_btn"] = ctk.CTkButton(
                    action_cell,
                    text="↺" if is_visited else "✓",
                    width=28,
                    height=26,
                    fg_color="#2b2b2b",
                    hover_color="#3a3a3a",
                    command=lambda i=idx: self._toggle_visited(i)
                )
                w_dict["toggle_btn"].pack(side="left")
            else:
                ctk.CTkLabel(self.table_frame, text="—", text_color="gray").grid(
                    row=row_idx, column=4, padx=8, pady=4, sticky="w"
                )

            short_resp = resp_text if len(resp_text) <= 52 else resp_text[:50] + "…"
            resp_color = "#666666" if is_visited else self._get_response_color(resp_text, is_ok)
            w_dict["resp"] = ctk.CTkLabel(
                self.table_frame,
                text=short_resp or "—",
                text_color=resp_color,
                font=ctk.CTkFont(size=12)
            )
            w_dict["resp"].grid(row=row_idx, column=5, padx=8, pady=4, sticky="w")

            self.row_widgets[idx] = w_dict
            row_idx += 1

    def _export_results(self, fmt):
        if not self.results:
            messagebox.showinfo("Keine Daten", "Es gibt noch keine Ergebnisse zum Exportieren.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[(f"{fmt.upper()} Datei", f"*.{fmt}")]
        )
        if not file_path:
            return

        export_data = [
            {k: r.get(k, "") for k in ("ip", "port", "status", "visited", "info", "url", "response_info")}
            for r in self.results
        ]

        try:
            if fmt == "json":
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
            elif fmt == "csv":
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(
                        f, fieldnames=["ip", "port", "status", "visited", "info", "url", "response_info"]
                    )
                    writer.writeheader()
                    writer.writerows(export_data)
            self._set_status("Export erfolgreich gespeichert!", "#4ade80")
        except Exception as e:
            messagebox.showerror("Export-Fehler", str(e))


if __name__ == "__main__":
    app = ShodanCheckApp()
    app.mainloop()