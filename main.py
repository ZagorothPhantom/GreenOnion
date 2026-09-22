from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import messagebox, ttk
import checks

'''Green onion by Zagoroth Phantom'''

class NetworkCheckerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        self.title("Tor / VPN Connection Checker")
        self.geometry("850x650")
        self.minsize(720, 500)

        self.colors = {
            "background": "#101418",
            "panel": "#192127",
            "panel_light": "#222d35",
            "text": "#e8eef2",
            "muted": "#9aaab5",
            "accent": "#65c466",
            "warning": "#e4b85c",
            "error": "#e56b6f",
            "border": "#34434d",
        }

        self.configure(bg=self.colors["background"])
        self._configure_style()
        self._build_ui()

    def _configure_style(self) -> None:
        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Main.TFrame",
            background=self.colors["background"],
        )

        style.configure(
            "Panel.TFrame",
            background=self.colors["panel"],
        )

        style.configure(
            "Title.TLabel",
            background=self.colors["background"],
            foreground=self.colors["text"],
            font=("Segoe UI", 20, "bold"),
        )

        style.configure(
            "Subtitle.TLabel",
            background=self.colors["background"],
            foreground=self.colors["muted"],
            font=("Segoe UI", 10),
        )

        style.configure(
            "PanelTitle.TLabel",
            background=self.colors["panel"],
            foreground=self.colors["text"],
            font=("Segoe UI", 11, "bold"),
        )

        style.configure(
            "Status.TLabel",
            background=self.colors["panel"],
            foreground=self.colors["muted"],
            font=("Segoe UI", 10),
        )

        style.configure(
            "Accent.TButton",
            background=self.colors["accent"],
            foreground="#071008",
            font=("Segoe UI", 10, "bold"),
            padding=(16, 8),
        )

        style.map(
            "Accent.TButton",
            background=[
                ("active", "#83d684"),
                ("disabled", "#526754"),
            ],
        )

        style.configure(
            "TNotebook",
            background=self.colors["background"],
            borderwidth=0,
        )

        style.configure(
            "TNotebook.Tab",
            background=self.colors["panel"],
            foreground=self.colors["muted"],
            padding=(14, 8),
        )

        style.map(
            "TNotebook.Tab",
            background=[("selected", self.colors["panel_light"])],
            foreground=[("selected", self.colors["text"])],
        )

    def _build_ui(self) -> None:
        root = ttk.Frame(self, style="Main.TFrame", padding=20)
        root.pack(fill="both", expand=True)

        header = ttk.Frame(root, style="Main.TFrame")
        header.pack(fill="x", pady=(0, 16))

        ttk.Label(
            header,
            text="Tor / VPN Connection Checker",
            style="Title.TLabel",
        ).pack(anchor="w")

        ttk.Label(
            header,
            text=(
                "Check public IP, Tor routing, VPN-over-Tor heuristics, "
                "and local DNS configuration."
            ),
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(5, 0))

        controls = ttk.Frame(root, style="Main.TFrame")
        controls.pack(fill="x", pady=(0, 14))

        self.run_button = ttk.Button(
            controls,
            text="Run checks",
            style="Accent.TButton",
            command=self.start_checks,
        )
        self.run_button.pack(side="left")

        self.progress = ttk.Progressbar(
            controls,
            mode="indeterminate",
            length=180,
        )
        self.progress.pack(side="left", padx=15)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(
            controls,
            textvariable=self.status_var,
            style="Subtitle.TLabel",
        ).pack(side="left")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        self.results_frame = ttk.Frame(
            self.notebook,
            style="Panel.TFrame",
            padding=16,
        )
        self.details_frame = ttk.Frame(
            self.notebook,
            style="Panel.TFrame",
            padding=16,
        )

        self.notebook.add(self.results_frame, text="Results")
        self.notebook.add(self.details_frame, text="Raw details")

        self.results_canvas = tk.Canvas(
            self.results_frame,
            background=self.colors["panel"],
            highlightthickness=0,
        )
        self.results_scrollbar = ttk.Scrollbar(
            self.results_frame,
            orient="vertical",
            command=self.results_canvas.yview,
        )

        self.results_inner = ttk.Frame(
            self.results_canvas,
            style="Panel.TFrame",
        )

        self.results_inner.bind(
            "<Configure>",
            lambda event: self.results_canvas.configure(
                scrollregion=self.results_canvas.bbox("all")
            ),
        )

        self.results_canvas.create_window(
            (0, 0),
            window=self.results_inner,
            anchor="nw",
        )

        self.results_canvas.configure(
            yscrollcommand=self.results_scrollbar.set
        )

        self.results_canvas.pack(side="left", fill="both", expand=True)
        self.results_scrollbar.pack(side="right", fill="y")

        self.details_text = tk.Text(
            self.details_frame,
            background="#0b0f12",
            foreground=self.colors["text"],
            insertbackground=self.colors["text"],
            selectbackground="#31566c",
            relief="flat",
            wrap="word",
            font=("Consolas", 10),
            padx=12,
            pady=12,
        )
        self.details_text.pack(fill="both", expand=True)
        self.details_text.configure(state="disabled")

        self._show_empty_state()

    def _show_empty_state(self) -> None:
        for widget in self.results_inner.winfo_children():
            widget.destroy()

        ttk.Label(
            self.results_inner,
            text="No checks have been run yet.",
            style="PanelTitle.TLabel",
        ).pack(anchor="w", pady=(10, 5))

        ttk.Label(
            self.results_inner,
            text="Click “Run checks” to begin.",
            style="Status.TLabel",
        ).pack(anchor="w")

    def start_checks(self) -> None:
        self.run_button.configure(state="disabled")
        self.progress.start(10)
        self.status_var.set("Running checks…")
        self._show_empty_state()

        worker = threading.Thread(
            target=self._run_checks_worker,
            daemon=True,
        )
        worker.start()

    def _run_checks_worker(self) -> None:
        try:
            data = checks.run_all_checks()
            self.after(0, lambda: self._display_results(data))
        except Exception as exc:
            self.after(0, lambda: self._show_error(str(exc)))

    def _show_error(self, error: str) -> None:
        self.progress.stop()
        self.run_button.configure(state="normal")
        self.status_var.set("Error")

        messagebox.showerror(
            "Check failed",
            error,
        )

    def _display_results(self, data: dict) -> None:
        self.progress.stop()
        self.run_button.configure(state="normal")
        self.status_var.set(
            f"Completed at {data.get('timestamp', 'unknown time')}"
        )

        for widget in self.results_inner.winfo_children():
            widget.destroy()

        results = data.get("results", [])

        for result in results:
            self._add_result_card(result)

        raw_json = json.dumps(data, indent=2)

        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", raw_json)
        self.details_text.configure(state="disabled")

    def _add_result_card(self, result: dict) -> None:
        status = result.get("status", "UNKNOWN")
        name = result.get("name", "Unknown check")
        summary = result.get("summary", "")
        details = result.get("details", "")
        latency = result.get("latency_ms")

        if status == "PASS":
            color = self.colors["accent"]
        elif status == "WARN":
            color = self.colors["warning"]
        else:
            color = self.colors["error"]

        card = tk.Frame(
            self.results_inner,
            background=self.colors["panel_light"],
            highlightbackground=self.colors["border"],
            highlightthickness=1,
        )
        card.pack(fill="x", pady=(0, 10))

        top = tk.Frame(
            card,
            background=self.colors["panel_light"],
        )
        top.pack(fill="x", padx=14, pady=(12, 4))

        tk.Label(
            top,
            text=status,
            background=color,
            foreground="#0b0f12",
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=3,
        ).pack(side="left")

        tk.Label(
            top,
            text=name,
            background=self.colors["panel_light"],
            foreground=self.colors["text"],
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left", padx=10)

        if latency is not None:
            tk.Label(
                top,
                text=f"{latency} ms",
                background=self.colors["panel_light"],
                foreground=self.colors["muted"],
                font=("Segoe UI", 9),
            ).pack(side="right")

        tk.Label(
            card,
            text=summary,
            background=self.colors["panel_light"],
            foreground=self.colors["text"],
            font=("Segoe UI", 10),
            anchor="w",
            justify="left",
        ).pack(fill="x", padx=14, pady=(0, 5))

        tk.Label(
            card,
            text=details,
            background=self.colors["panel_light"],
            foreground=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=700,
        ).pack(fill="x", padx=14, pady=(0, 12))


if __name__ == "__main__":
    app = NetworkCheckerApp()
    app.mainloop()
