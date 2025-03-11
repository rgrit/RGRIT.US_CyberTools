#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
from tkinter import ttk
import hashlib
import os
import json
import datetime
import glob

HISTORY_FILE = "history.json"

def compute_hash(file_path):
    """Compute SHA-256 hash for a file."""
    hash_obj = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hash_obj.update(chunk)
    except Exception as e:
        return None, f"Error reading {file_path}: {e}"
    return hash_obj.hexdigest(), None

def scan_directory(directory):
    """
    Recursively scan the directory and return a dictionary mapping file paths to their SHA-256 hashes.
    """
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash, error = compute_hash(file_path)
            if file_hash:
                file_hashes[file_path] = file_hash
    return file_hashes

def create_baseline_gui(directory, baseline_file, logger=None):
    """Create a baseline file that includes both the scanned directory and its file hashes."""
    if logger:
        logger("Starting baseline creation for directory: " + directory)
        logger("Scanning directory for files...")
    file_hashes = scan_directory(directory)
    if logger:
        logger(f"Scanning complete. Total files scanned: {len(file_hashes)}")
        logger(f"Saving baseline file to {baseline_file}...")
    data = {
        "directory": directory,
        "hashes": file_hashes
    }
    try:
        with open(baseline_file, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        return f"Error writing baseline file: {e}"
    if logger:
        logger("Baseline file saved successfully.")
    return f"Baseline saved to {baseline_file} with {len(file_hashes)} files processed."

def check_integrity_gui(directory, baseline_file, logger=None):
    """
    Check integrity by comparing the current directory (or the one stored in the baseline file if no
    directory is selected) with the hashes in the baseline.
    Returns a tuple: (result_text, changes_dict)
    where changes_dict is a dictionary with keys: "modified", "new", "deleted".
    """
    if logger:
        logger("Loading baseline file: " + baseline_file)
    try:
        with open(baseline_file, 'r') as f:
            data = json.load(f)
        baseline_hashes = data.get("hashes", {})
        baseline_directory = data.get("directory", "")
        if logger:
            logger(f"Baseline loaded successfully. Total baseline entries: {len(baseline_hashes)}")
    except Exception as e:
        return f"Error loading baseline file: {e}", {}

    # If no directory is selected, default to the directory stored in the baseline.
    if not directory:
        directory = baseline_directory
        if logger:
            logger(f"No directory selected, using baseline's directory: {directory}")
    else:
        if directory != baseline_directory:
            if logger:
                logger(f"Warning: Selected directory ({directory}) differs from baseline directory ({baseline_directory}).")

    if logger:
        logger("Scanning current directory for files...")
    current_hashes = scan_directory(directory)
    if logger:
        logger(f"Scanning complete. Total files scanned: {len(current_hashes)}")
        logger("Comparing baseline with current file state...")

    modified_files = []
    new_files = []
    deleted_files = []
    for file_path, current_hash in current_hashes.items():
        if file_path in baseline_hashes:
            if current_hash != baseline_hashes[file_path]:
                modified_files.append(file_path)
        else:
            new_files.append(file_path)
    for file_path in baseline_hashes:
        if file_path not in current_hashes:
            deleted_files.append(file_path)
    if logger:
        logger("Comparison complete.")

    changes = {"modified": modified_files, "new": new_files, "deleted": deleted_files}
    result = ""
    if modified_files or new_files or deleted_files:
        result += "File Integrity Issues Detected:\n"
        if modified_files:
            result += "\nModified files:\n"
            for file in modified_files:
                result += f" - {file}\n"
        if new_files:
            result += "\nNew files:\n"
            for file in new_files:
                result += f" - {file}\n"
        if deleted_files:
            result += "\nDeleted files:\n"
            for file in deleted_files:
                result += f" - {file}\n"
    else:
        result = "No integrity issues detected."
    if logger:
        logger("Integrity check process complete.")
    return result, changes

def load_history():
    """Load history records from the persistent history file."""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_history(history):
    """Save the history records to the persistent history file."""
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)

class FileIntegrityGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Integrity Monitoring")
        self.geometry("800x700")
        self.selected_directory = ""
        self.baseline_files = []  # List to store baseline file paths
        self.selected_baseline_var = tk.StringVar(value="")  # Holds the currently selected baseline file
        self.create_widgets()
        self.load_existing_baselines()  # Load any existing baseline files on startup
        self.update_history_table()     # Load persistent history into the table

    def create_widgets(self):
        # Directory selection frame
        dir_frame = tk.Frame(self)
        dir_frame.pack(pady=10, fill=tk.X, padx=10)
        self.dir_label = tk.Label(dir_frame, text="Selected Directory: None", font=("Arial", 12), anchor="w")
        self.dir_label.pack(side=tk.TOP, fill=tk.X, pady=5)
        select_dir_button = tk.Button(dir_frame, text="Select Directory", command=self.select_directory,
                                      font=("Arial", 12), width=20)
        select_dir_button.pack(side=tk.TOP, pady=5)

        # Baseline Files frame with radio buttons
        baseline_list_frame = tk.Frame(self, relief=tk.GROOVE, bd=2)
        baseline_list_frame.pack(pady=10, fill=tk.X, padx=10)
        baseline_title = tk.Label(baseline_list_frame, text="Baseline Files", font=("Arial", 12, "bold"), anchor="w")
        baseline_title.pack(side=tk.TOP, fill=tk.X, pady=5, padx=5)
        self.baseline_radio_frame = tk.Frame(baseline_list_frame)
        self.baseline_radio_frame.pack(side=tk.TOP, fill=tk.X, padx=5)

        # Buttons for creating baseline and checking integrity
        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)
        baseline_button = tk.Button(button_frame, text="Create Baseline", command=self.handle_baseline,
                                    font=("Arial", 12), width=20)
        baseline_button.pack(side=tk.LEFT, padx=10)
        check_button = tk.Button(button_frame, text="Check Integrity", command=self.handle_check,
                                 font=("Arial", 12), width=20)
        check_button.pack(side=tk.LEFT, padx=10)

        # Scrolled text area for verbose output
        self.output_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=80, height=10, font=("Arial", 12))
        self.output_text.pack(pady=10)

        # History table for changes using Treeview
        history_frame = tk.Frame(self)
        history_frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=10)
        history_label = tk.Label(history_frame, text="History of Changes", font=("Arial", 12, "bold"))
        history_label.pack(side=tk.TOP, anchor="w")
        self.history_tree = ttk.Treeview(history_frame, columns=("Timestamp", "Type", "File Path"), show="headings")
        self.history_tree.heading("Timestamp", text="Timestamp")
        self.history_tree.heading("Type", text="Change Type")
        self.history_tree.heading("File Path", text="File Path")
        self.history_tree.column("Timestamp", width=150)
        self.history_tree.column("Type", width=100)
        self.history_tree.column("File Path", width=500)
        self.history_tree.pack(fill=tk.BOTH, expand=True)

    def log(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)

    def select_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.selected_directory = directory
            self.dir_label.config(text=f"Selected Directory: {directory}")

    def add_baseline_radio(self, baseline_file):
        """Add a radio button for the newly created baseline file."""
        if baseline_file not in self.baseline_files:
            self.baseline_files.append(baseline_file)
            rb = tk.Radiobutton(
                self.baseline_radio_frame,
                text=baseline_file,
                variable=self.selected_baseline_var,
                value=baseline_file,
                font=("Arial", 12)
            )
            rb.pack(anchor="w")
        self.selected_baseline_var.set(baseline_file)

    def load_existing_baselines(self):
        """Scan the current directory for existing baseline files and add them to the radio button list."""
        for file_path in glob.glob("baseline_*.json"):
            self.add_baseline_radio(file_path)
        if self.baseline_files and not self.selected_baseline_var.get():
            self.selected_baseline_var.set(self.baseline_files[0])

    def handle_baseline(self):
        if not self.selected_directory:
            messagebox.showerror("Error", "Please select a directory first.")
            return
        baseline_name = simpledialog.askstring("Baseline Name", "Enter a name for the baseline:")
        if not baseline_name:
            messagebox.showerror("Error", "Baseline name cannot be empty.")
            return
        self.output_text.delete(1.0, tk.END)
        self.log("Starting baseline creation process...")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        baseline_file = f"baseline_{baseline_name}_{timestamp}.json"
        result = create_baseline_gui(self.selected_directory, baseline_file, logger=self.log)
        self.log(result)
        self.log("Baseline creation process complete.")
        self.add_baseline_radio(baseline_file)

    def update_history_table(self):
        """Reload the persistent history from file and update the table."""
        # Clear existing rows
        for row in self.history_tree.get_children():
            self.history_tree.delete(row)
        history = load_history()
        # For each record, add rows for each change.
        for record in history:
            timestamp = record.get("timestamp", "")
            changes = record.get("changes", {})
            for change_type, files in changes.items():
                for file in files:
                    self.history_tree.insert("", "end", values=(timestamp, change_type.capitalize(), file))

    def handle_check(self):
        baseline_file = self.selected_baseline_var.get()
        if not baseline_file and self.baseline_files:
            baseline_file = self.baseline_files[0]
            self.selected_baseline_var.set(baseline_file)
        if not baseline_file:
            messagebox.showerror("Error", "Please select a baseline file from the list.")
            return
        self.output_text.delete(1.0, tk.END)
        self.log("Starting integrity check process...")
        result, changes = check_integrity_gui(self.selected_directory, baseline_file, logger=self.log)
        self.log(result)
        self.log("Integrity check process complete.")

        # Record this check into persistent history
        record = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "baseline_file": baseline_file,
            "directory": self.selected_directory if self.selected_directory else "N/A",
            "changes": changes
        }
        history = load_history()
        history.append(record)
        save_history(history)
        self.update_history_table()

if __name__ == '__main__':
    app = FileIntegrityGUI()
    app.mainloop()
