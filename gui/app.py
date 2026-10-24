import json
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from scanner.scanner import scan_directory_with_metadata
from hashing.hasher import hash_file
from ai.anomaly import score_artifacts
from reports.reports import generate_human_readable_report


class ForensicApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Forensic Artifact Extraction System")
        self.geometry("900x520")

        self.selected_path = tk.StringVar()
        self.status_text = tk.StringVar(value="Ready.")
        self.sensitivity = tk.StringVar(value="0.05")
        self._build_ui()

    def _build_ui(self):
        top_frame = tk.Frame(self, padx=10, pady=10)
        top_frame.pack(fill="x")

        tk.Label(top_frame, text="Target folder / drive:").pack(side="left")
        tk.Entry(top_frame, textvariable=self.selected_path, width=55).pack(
            side="left", padx=5
        )
        tk.Button(top_frame, text="Browse...", command=self._browse).pack(
            side="left", padx=5
        )
        tk.Button(
            top_frame, text="Scan", command=self._start_scan, bg="#2c7a4b", fg="white"
        ).pack(side="left", padx=5)

        tk.Label(top_frame, text="Sensitivity:").pack(side="left", padx=(15, 0))
        tk.Entry(top_frame, textvariable=self.sensitivity, width=6).pack(side="left", padx=5)

        columns = ("path", "size", "hash", "score", "anomaly")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        headers = [
    ("path", "File Path", 380),
    ("size", "Size (bytes)", 90),
    ("hash", "SHA-256", 200),
    ("score", "Anomaly Score", 100),
    ("anomaly", "Anomaly", 80),
]
        for col, label, width in headers:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("anomaly", background="#ffdede")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        tk.Label(
            self, textvariable=self.status_text, bd=1, relief="sunken", anchor="w"
        ).pack(fill="x", side="bottom")

    def _browse(self):
        folder = filedialog.askdirectory(title="Select folder or drive to scan")
        if folder:
            self.selected_path.set(folder)

    def _start_scan(self):
        path = self.selected_path.get().strip()
        if not path or not os.path.isdir(path):
            messagebox.showerror("Invalid path", "Please choose a valid folder or drive.")
            return
        try:
            contamination = float(self.sensitivity.get())
            if not 0.0 < contamination < 0.5:
                raise ValueError
        except ValueError:
          messagebox.showerror("Invalid sensitivity", "Sensitivity must be a number between 0 and 0.5, e.g. 0.05")
          return
        self.tree.delete(*self.tree.get_children())
        self.status_text.set("Scanning... this may take a moment.")
        threading.Thread(target=self._run_pipeline, args=(path, contamination), daemon=True).start()
    def _run_pipeline(self, path, contamination):
        try:
            artifacts = scan_directory_with_metadata(path, exclude_extensions=[".pyc"])

            for artifact in artifacts:
                artifact["hash"] = hash_file(artifact["path"])

            artifacts = score_artifacts(artifacts, contamination=contamination)

            output_dir = os.path.join(os.getcwd(), "output")
            os.makedirs(output_dir, exist_ok=True)
            generate_human_readable_report(
                artifacts, output_path=os.path.join(output_dir, "report.txt")
            )
            with open(os.path.join(output_dir, "report.json"), "w") as f:
                json.dump(artifacts, f, default=str, indent=4)

            self.after(0, self._display_results, artifacts, output_dir)
        except Exception as e:
            print("SCAN ERROR:", e)
            self.after(0, self._show_error, str(e))
            
    def _display_results(self, artifacts, output_dir):
        for a in artifacts:
            tag = "anomaly" if a.get("is_anomaly") else ""
            self.tree.insert(
                "",
                "end",
                values=(
                    a["path"],
                    a.get("size", ""),
                    a.get("hash", "N/A"),
                    a.get("anomaly_score", ""),
                    "YES" if a.get("is_anomaly") else "",
                ),
                tags=(tag,),
            )
        self.status_text.set(
            f"Scan complete: {len(artifacts)} files scanned. Reports saved to {output_dir}"
        )

    def _show_error(self, message):
        self.status_text.set("Error during scan.")
        messagebox.showerror("Scan failed", message)


if __name__ == "__main__":
    ForensicApp().mainloop()