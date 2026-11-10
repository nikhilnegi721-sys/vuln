
import tkinter as tk
from tkinter import ttk, messagebox
import socket
import requests
import threading
import json
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse


# ============== CONFIGURATION ==============

BG = "#0B1120"
SIDEBAR = "#101A2D"
CARD = "#162238"
CARD2 = "#1C2B43"
BLUE = "#3984FF"
CYAN = "#22D3EE"
GREEN = "#20D6A0"
RED = "#FF647C"
YELLOW = "#FFBE55"
WHITE = "#F1F5F9"
MUTED = "#91A3BC"

PORTS = [21, 22, 80, 443, 3306, 8080]

HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

REPORT_DIR = Path("reports")


# ============== MAIN APP ==============

class SecurityDashboard:

    def __init__(self, root):

        self.root = root
        self.root.title("NEXUS | Security Intelligence")
        self.root.geometry("1150x780")
        self.root.minsize(900, 650)
        self.root.configure(bg=BG)

        self.results = None
        self.history = []

        self.create_styles()
        self.create_layout()
        self.show_dashboard()

    # ============== STYLES ==============

    def create_styles(self):

        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background=CARD,
            foreground=WHITE,
            fieldbackground=CARD,
            rowheight=32,
            borderwidth=0,
            font=("Segoe UI", 10)
        )

        style.configure(
            "Treeview.Heading",
            background=CARD2,
            foreground=CYAN,
            font=("Segoe UI", 10, "bold"),
            relief="flat"
        )

        style.map(
            "Treeview",
            background=[("selected", BLUE)]
        )

        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=CARD2,
            background=BLUE,
            thickness=7
        )

    # ============== LAYOUT ==============

    def create_layout(self):

        self.sidebar = tk.Frame(
            self.root,
            bg=SIDEBAR,
            width=225
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        self.content = tk.Frame(
            self.root,
            bg=BG
        )
        self.content.pack(
            side="right",
            fill="both",
            expand=True
        )

        # Brand

        tk.Label(
            self.sidebar,
            text="✦ NEXUS",
            bg=SIDEBAR,
            fg=CYAN,
            font=("Segoe UI", 23, "bold")
        ).pack(anchor="w", padx=23, pady=(30, 4))

        tk.Label(
            self.sidebar,
            text="SECURITY INTELLIGENCE",
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(anchor="w", padx=25, pady=(0, 35))

        self.nav_button("▦   Dashboard", self.show_dashboard)
        self.nav_button("⌕   Vulnerability Scanner", self.show_dashboard)
        self.nav_button("◷   Scan History", self.show_history)
        self.nav_button("▤   Reports", self.show_reports)

        # Sidebar bottom

        tk.Frame(
            self.sidebar,
            bg="#29374D",
            height=1
        ).pack(fill="x", padx=18, pady=25)

        tk.Label(
            self.sidebar,
            text="● SYSTEM ONLINE",
            bg=SIDEBAR,
            fg=GREEN,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", padx=23)

        tk.Label(
            self.sidebar,
            text="NEXUS Scanner v2.0",
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 9)
        ).pack(anchor="w", padx=23, pady=5)

        # Top bar

        top = tk.Frame(
            self.content,
            bg=BG,
            height=65
        )
        top.pack(fill="x", padx=28, pady=(15, 5))

        tk.Label(
            top,
            text="SECURITY CENTER",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10, "bold")
        ).pack(side="left")

        tk.Label(
            top,
            text="●  READY",
            bg=BG,
            fg=GREEN,
            font=("Segoe UI", 10, "bold")
        ).pack(side="right")

        self.page = tk.Frame(
            self.content,
            bg=BG
        )
        self.page.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=10
        )

    def nav_button(self, text, command):

        btn = tk.Button(
            self.sidebar,
            text=text,
            command=command,
            bg=SIDEBAR,
            fg="#B7C5DA",
            activebackground=CARD2,
            activeforeground=CYAN,
            relief="flat",
            anchor="w",
            padx=22,
            pady=14,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2"
        )

        btn.pack(fill="x", padx=10, pady=3)

    # ============== PAGE MANAGEMENT ==============

    def clear_page(self):

        for widget in self.page.winfo_children():
            widget.destroy()

    def show_dashboard(self):

        self.clear_page()

        tk.Label(
            self.page,
            text="Security Overview",
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 25, "bold")
        ).pack(anchor="w")

        tk.Label(
            self.page,
            text="Monitor and analyze your website security posture.",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10)
        ).pack(anchor="w", pady=(3, 20))

        # Target card

        target = self.make_card(self.page)
        target.pack(fill="x", pady=(0, 18))

        tk.Label(
            target,
            text="TARGET WEBSITE",
            bg=CARD,
            fg=CYAN,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        input_row = tk.Frame(target, bg=CARD)
        input_row.pack(fill="x", pady=12)

        self.url_entry = tk.Entry(
            input_row,
            bg=CARD2,
            fg=WHITE,
            insertbackground=WHITE,
            relief="flat",
            font=("Segoe UI", 12)
        )
        self.url_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=12,
            padx=(0, 12)
        )

        self.url_entry.insert(0, "https://example.com")

        self.scan_btn = tk.Button(
            input_row,
            text="  ⚡ START SCAN  ",
            command=self.start_scan,
            bg=BLUE,
            fg=WHITE,
            activebackground="#2368D8",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
            pady=12
        )
        self.scan_btn.pack(side="right")

        self.authorization = tk.BooleanVar(value=False)

        tk.Checkbutton(
            target,
            text="I have permission to scan this website.",
            variable=self.authorization,
            bg=CARD,
            fg=MUTED,
            selectcolor=CARD2,
            activebackground=CARD,
            activeforeground=WHITE,
            font=("Segoe UI", 9)
        ).pack(anchor="w")

        self.progress = ttk.Progressbar(
            target,
            mode="indeterminate",
            style="Horizontal.TProgressbar"
        )
        self.progress.pack(fill="x", pady=(14, 0))

        # Statistic cards

        stats = tk.Frame(self.page, bg=BG)
        stats.pack(fill="x", pady=5)

        self.stat_values = {}

        self.stat_card(
            stats, "OPEN PORTS", "0", "NETWORK",
            BLUE, "ports"
        )

        self.stat_card(
            stats, "MISSING HEADERS", "0", "SECURITY",
            YELLOW, "headers"
        )

        self.stat_card(
            stats, "HTTP STATUS", "--", "WEBSITE",
            CYAN, "http"
        )

        self.stat_card(
            stats, "SCAN HISTORY", "0", "ACTIVITY",
            GREEN, "history"
        )

        # Results panels

        results = tk.Frame(self.page, bg=BG)
        results.pack(fill="both", expand=True, pady=15)

        left = self.make_card(results)
        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 8)
        )

        right = self.make_card(results)
        right.pack(
            side="right",
            fill="both",
            expand=True,
            padx=(8, 0)
        )

        tk.Label(
            left,
            text="PORT ANALYSIS",
            bg=CARD,
            fg=CYAN,
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w", pady=(0, 12))

        self.port_output = tk.Text(
            left,
            bg=CARD2,
            fg=WHITE,
            font=("Consolas", 10),
            relief="flat",
            height=9,
            padx=10,
            pady=10
        )
        self.port_output.pack(fill="both", expand=True)

        self.port_output.insert(
            "end",
            "Waiting for scan...\n"
        )
        self.port_output.config(state="disabled")

        tk.Label(
            right,
            text="SECURITY HEADERS",
            bg=CARD,
            fg=CYAN,
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w", pady=(0, 12))

        self.header_output = tk.Text(
            right,
            bg=CARD2,
            fg=WHITE,
            font=("Consolas", 9),
            relief="flat",
            height=9,
            padx=10,
            pady=10
        )
        self.header_output.pack(fill="both", expand=True)

        self.header_output.insert(
            "end",
            "Waiting for scan...\n"
        )
        self.header_output.config(state="disabled")

        self.report_btn = tk.Button(
            self.page,
            text="↓  EXPORT SECURITY REPORT",
            command=self.save_report,
            bg="#087F65",
            fg=WHITE,
            activebackground="#066B55",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2",
            pady=11,
            state="disabled"
        )
        self.report_btn.pack(fill="x", pady=(0, 10))

    # ============== COMPONENTS ==============

    def make_card(self, parent):

        return tk.Frame(
            parent,
            bg=CARD,
            padx=17,
            pady=15,
            highlightthickness=1,
            highlightbackground="#263A56"
        )

    def stat_card(
        self, parent, title, value, subtitle, color, key
    ):

        card = self.make_card(parent)

        card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=5
        )

        tk.Label(
            card,
            text=title,
            bg=CARD,
            fg=MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(anchor="w")

        label = tk.Label(
            card,
            text=value,
            bg=CARD,
            fg=color,
            font=("Segoe UI", 24, "bold")
        )
        label.pack(anchor="w", pady=5)

        self.stat_values[key] = label

        tk.Label(
            card,
            text=subtitle,
            bg=CARD,
            fg=MUTED,
            font=("Segoe UI", 8)
        ).pack(anchor="w")

    # ============== SCANNING ==============

    def start_scan(self):

        if not self.authorization.get():

            messagebox.showwarning(
                "Permission Required",
                "Please confirm that you have permission."
            )
            return

        raw = self.url_entry.get().strip()

        if not raw:
            messagebox.showwarning(
                "Missing URL",
                "Enter a website URL."
            )
            return

        if "://" not in raw:
            raw = "https://" + raw

        parsed = urlparse(raw)

        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):

            messagebox.showerror(
                "Invalid URL",
                "Enter a valid HTTP or HTTPS URL."
            )
            return

        self.target_url = raw
        self.target_host = parsed.hostname

        self.scan_btn.config(state="disabled")
        self.report_btn.config(state="disabled")
        self.progress.start(12)

        self.stat_values["ports"].config(text="...")
        self.stat_values["headers"].config(text="...")
        self.stat_values["http"].config(text="...")
        
        threading.Thread(
            target=self.run_scan,
            daemon=True
        ).start()

    def run_scan(self):

        data = {
            "target": self.target_host,
            "url": self.target_url,
            "date": datetime.now().isoformat(),
            "ports": {},
            "headers": {},
            "server": None,
            "powered_by": None,
            "http_status": None,
            "error": None
        }

        # Port scanning

        for port in PORTS:

            try:
                conn = socket.create_connection(
                    (self.target_host, port),
                    timeout=0.7
                )

                conn.close()
                data["ports"][str(port)] = "OPEN"

            except OSError:
                data["ports"][str(port)] = "CLOSED"

        # Header and software detection

        try:

            response = requests.get(
                self.target_url,
                timeout=10,
                allow_redirects=True
            )

            data["http_status"] = response.status_code

            for header in HEADERS:

                data["headers"][header] = (
                    "PRESENT"
                    if header in response.headers
                    else "MISSING"
                )

            data["server"] = response.headers.get("Server")
            data["powered_by"] = response.headers.get(
                "X-Powered-By"
            )

        except requests.exceptions.RequestException as error:

            data["error"] = str(error)

            for header in HEADERS:
                data["headers"][header] = "NOT CHECKED"

        self.results = data

        self.root.after(
            0,
            self.display_results,
            data
        )

    # ============== DISPLAY ==============

    def update_text(self, widget, text):

        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.config(state="disabled")

    def display_results(self, data):

        self.progress.stop()

        open_ports = sum(
            1 for value in data["ports"].values()
            if value == "OPEN"
        )

        missing = sum(
            1 for value in data["headers"].values()
            if value == "MISSING"
        )

        self.stat_values["ports"].config(text=str(open_ports))
        self.stat_values["headers"].config(text=str(missing))

        self.stat_values["http"].config(
            text=str(data["http_status"] or "--")
        )

        self.history.append(data)

        self.stat_values["history"].config(
            text=str(len(self.history))
        )

        port_text = "PORT       STATUS\n"
        port_text += "-" * 25 + "\n"

        for port, status in data["ports"].items():
            port_text += f"{port:<10} {status}\n"

        header_text = ""

        for name, status in data["headers"].items():
            header_text += f"{name}\n  {status}\n\n"

        self.update_text(
            self.port_output,
            port_text
        )

        self.update_text(
            self.header_output,
            header_text
        )

        self.scan_btn.config(state="normal")
        self.report_btn.config(state="normal")

        if data["error"]:
            messagebox.showwarning(
                "HTTP Scan Issue",
                "Port scan completed, but HTTP check failed:\n"
                + data["error"]
            )

    # ============== HISTORY ==============

    def show_history(self):

        self.clear_page()

        tk.Label(
            self.page,
            text="Scan History",
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 25, "bold")
        ).pack(anchor="w", pady=(10, 20))

        table = ttk.Treeview(
            self.page,
            columns=("target", "date", "status"),
            show="headings"
        )

        table.heading("target", text="TARGET")
        table.heading("date", text="SCAN DATE")
        table.heading("status", text="HTTP STATUS")

        table.column("target", width=250)
        table.column("date", width=250)
        table.column("status", width=120)

        table.pack(fill="both", expand=True)

        for item in self.history:

            table.insert(
                "",
                "end",
                values=(
                    item["target"],
                    item["date"],
                    item["http_status"] or "Unavailable"
                )
            )

        if not self.history:
            tk.Label(
                self.page,
                text="No scans performed yet.",
                bg=BG,
                fg=MUTED,
                font=("Segoe UI", 12)
            ).pack(pady=20)

    # ============== REPORTS ==============

    def show_reports(self):

        self.clear_page()

        tk.Label(
            self.page,
            text="Security Reports",
            bg=BG,
            fg=WHITE,
            font=("Segoe UI", 25, "bold")
        ).pack(anchor="w", pady=(10, 15))

        tk.Label(
            self.page,
            text="Generate TXT and JSON reports from your latest scan.",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10)
        ).pack(anchor="w", pady=10)

        tk.Button(
            self.page,
            text="↓  SAVE LATEST SCAN REPORT",
            command=self.save_report,
            bg=BLUE,
            fg=WHITE,
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            pady=14,
            state="normal" if self.results else "disabled"
        ).pack(fill="x", pady=15)

    def save_report(self):

        if not self.results:
            messagebox.showwarning(
                "No Data",
                "Perform a scan first."
            )
            return

        REPORT_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        txt_path = REPORT_DIR / f"report_{timestamp}.txt"
        json_path = REPORT_DIR / f"report_{timestamp}.json"

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("NEXUS SECURITY SCAN REPORT\n")
            f.write("=" * 40 + "\n\n")
            f.write(json.dumps(self.results, indent=4))

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=4)

        messagebox.showinfo(
            "Reports Saved",
            f"Reports saved successfully!\n\n"
            f"{txt_path}\n\n{json_path}"
        )


# ============== APPLICATION ==============

if __name__ == "__main__":

    root = tk.Tk()
    app = SecurityDashboard(root)
    root.mainloop()
