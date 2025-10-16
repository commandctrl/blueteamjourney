import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import tarfile
import gzip
import os
import threading
import queue
import re
import logging
from datetime import datetime
import hashlib
import subprocess
import tempfile
import shutil
import platform
import zipfile

try:
    import py7zr
    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('archive_searcher.log'),
        logging.StreamHandler()
    ]
)


class SecurityException(Exception):
    """Custom exception for security-related issues"""
    pass


class ValidationException(Exception):
    """Custom exception for validation errors"""
    pass


class PasswordDialog(tk.Toplevel):
    """Custom dialog for password input"""

    def __init__(self, parent, archive_name):
        super().__init__(parent)
        self.password = None
        self.remember = False

        self.title("Password Required")
        self.geometry("400x180")
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()

        ttk.Label(self, text=f"Password required for:",
                  wraplength=380).pack(pady=(10, 0))
        ttk.Label(self, text=os.path.basename(archive_name),
                  font=('TkDefaultFont', 9, 'bold'), wraplength=380).pack(pady=(0, 10))

        password_frame = ttk.Frame(self)
        password_frame.pack(pady=10, padx=20, fill=tk.X)

        ttk.Label(password_frame, text="Password:").pack(
            side=tk.LEFT, padx=(0, 10))
        self.password_entry = ttk.Entry(password_frame, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.password_entry.focus()

        self.show_password_var = tk.BooleanVar()
        show_check = ttk.Checkbutton(self, text="Show password",
                                     variable=self.show_password_var,
                                     command=self.toggle_password_visibility)
        show_check.pack(pady=5)

        self.remember_var = tk.BooleanVar()
        remember_check = ttk.Checkbutton(self, text="Remember password for this session",
                                         variable=self.remember_var)
        remember_check.pack(pady=5)

        button_frame = ttk.Frame(self)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="OK", command=self.ok_clicked,
                   width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Skip", command=self.skip_clicked,
                   width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel All",
                   command=self.cancel_clicked, width=10).pack(side=tk.LEFT, padx=5)

        self.password_entry.bind('<Return>', lambda e: self.ok_clicked())

        self.wait_window()

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def ok_clicked(self):
        self.password = self.password_entry.get()
        self.remember = self.remember_var.get()
        self.destroy()

    def skip_clicked(self):
        self.password = None
        self.remember = False
        self.destroy()

    def cancel_clicked(self):
        self.password = "CANCEL_ALL"
        self.remember = False
        self.destroy()


class MultiFolderDialog(tk.Toplevel):
    """Dialog for selecting multiple folders"""

    def __init__(self, parent):
        super().__init__(parent)
        self.selected_folders = []

        self.title("Select Multiple Folders")
        self.geometry("600x400")

        self.transient(parent)
        self.grab_set()

        ttk.Label(self, text="Selected Folders:", font=(
            'TkDefaultFont', 10, 'bold')).pack(pady=(10, 5))

        list_frame = ttk.Frame(self)
        list_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

        self.folders_listbox = tk.Listbox(list_frame, selectmode=tk.MULTIPLE)
        self.folders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(
            list_frame, orient=tk.VERTICAL, command=self.folders_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.folders_listbox.configure(yscrollcommand=scrollbar.set)

        button_frame = ttk.Frame(self)
        button_frame.pack(pady=10, padx=10, fill=tk.X)

        ttk.Button(button_frame, text="Add Folder",
                   command=self.add_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Remove Selected",
                   command=self.remove_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear All",
                   command=self.clear_all).pack(side=tk.LEFT, padx=5)

        done_frame = ttk.Frame(self)
        done_frame.pack(pady=10)

        ttk.Button(done_frame, text="Done", command=self.done_clicked,
                   width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(done_frame, text="Cancel", command=self.cancel_clicked,
                   width=12).pack(side=tk.LEFT, padx=5)

        self.wait_window()

    def add_folder(self):
        folder = filedialog.askdirectory(title="Select Folder")
        if folder and folder not in self.folders_listbox.get(0, tk.END):
            self.folders_listbox.insert(tk.END, folder)

    def remove_selected(self):
        selected = self.folders_listbox.curselection()
        for index in reversed(selected):
            self.folders_listbox.delete(index)

    def clear_all(self):
        self.folders_listbox.delete(0, tk.END)

    def done_clicked(self):
        self.selected_folders = list(self.folders_listbox.get(0, tk.END))
        self.destroy()

    def cancel_clicked(self):
        self.selected_folders = []
        self.destroy()


class ArchiveSearcherGUI:
    MAX_FILE_SIZE = None  # No limit
    MAX_TOTAL_SIZE = None
    MAX_KEYWORD_LENGTH = 1000
    MAX_DEPTH_LIMIT = 10000
    MAX_EXTRACTION_SIZE = 10 * 1024 * 1024 * 1024
    TIMEOUT_SECONDS = 300
    MAX_PASSWORD_ATTEMPTS = 3

    # Archive formats that need extraction
    ARCHIVE_EXTENSIONS = {'.tar.gz', '.gz', '.7z',
                          '.zip', '.tar', '.bz2', '.xz', '.tgz'}

    def __init__(self, root):
        self.root = root
        self.root.title("Universal File Searcher - GREP/FINDSTR Powered")
        self.root.geometry("1050x850")

        self.search_thread = None
        self.stop_search = False
        self.result_queue = queue.Queue()
        self.password_queue = queue.Queue()
        self.total_processed_size = 0
        self.search_start_time = None

        self.temp_base_dir = None

        self.suspicious_files = []
        self.error_count = 0
        self.max_errors = 1000

        self.password_cache = {}
        self.default_passwords = []
        self.global_password = None
        self.password_attempts = {}

        # Detect OS and search tool
        self.os_type = platform.system()
        self.search_tool, self.search_version = self.detect_search_tool()

        self.setup_ui()
        logging.info(
            f"Application initialized - OS: {self.os_type}, Search tool: {self.search_tool}")

    def detect_search_tool(self):
        """Detect which search tool is available"""
        # Try grep first (Linux/Mac/Windows with Git Bash)
        try:
            result = subprocess.run(['grep', '--version'],
                                    capture_output=True,
                                    text=True,
                                    timeout=5)
            if result.returncode == 0:
                version = result.stdout.split('\n')[0]
                logging.info(f"GREP found: {version}")
                return 'grep', version
        except Exception as e:
            logging.debug(f"GREP not found: {str(e)}")

        # Try findstr (Windows)
        if self.os_type == 'Windows':
            try:
                result = subprocess.run(['findstr', '/?'],
                                        capture_output=True,
                                        text=True,
                                        timeout=5,
                                        shell=True)
                if result.returncode == 0:
                    logging.info("FINDSTR found (Windows)")
                    return 'findstr', 'Windows findstr'
            except Exception as e:
                logging.debug(f"FINDSTR not found: {str(e)}")

        logging.warning("No search tool found - using Python fallback")
        return None, None

    def is_archive(self, file_path):
        """Check if file is an archive that needs extraction"""
        return any(file_path.lower().endswith(ext) for ext in self.ARCHIVE_EXTENSIONS)

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(9, weight=1)

        # Search tool status
        tool_status_frame = ttk.Frame(main_frame)
        tool_status_frame.grid(
            row=0, column=0, columnspan=3, sticky=tk.W, pady=5)

        if self.search_tool == 'grep':
            ttk.Label(tool_status_frame, text="✓ GREP Available",
                      foreground="green", font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT, padx=5)
            ttk.Label(tool_status_frame, text=f"Searching ALL file types | {self.search_version}",
                      foreground="gray").pack(side=tk.LEFT)
        elif self.search_tool == 'findstr':
            ttk.Label(tool_status_frame, text="✓ FINDSTR Available",
                      foreground="green", font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT, padx=5)
            ttk.Label(tool_status_frame, text="Searching ALL file types | Windows findstr",
                      foreground="gray").pack(side=tk.LEFT)
        else:
            ttk.Label(tool_status_frame, text="⚠ No Search Tool",
                      foreground="orange", font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT, padx=5)
            ttk.Label(tool_status_frame, text="Searching ALL file types | Python fallback",
                      foreground="gray").pack(side=tk.LEFT)

        # Files/Folders selection
        files_label_frame = ttk.Frame(main_frame)
        files_label_frame.grid(row=1, column=0, sticky=tk.W, pady=5)

        ttk.Label(files_label_frame, text="Files/Folders:").pack(side=tk.LEFT)
        self.file_count_display = ttk.Label(
            files_label_frame, text="(0 items)", foreground="blue")
        self.file_count_display.pack(side=tk.LEFT, padx=5)

        self.files_listbox = tk.Listbox(
            main_frame, height=5, selectmode=tk.EXTENDED)
        self.files_listbox.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)

        files_scrollbar = ttk.Scrollbar(
            main_frame, orient=tk.VERTICAL, command=self.files_listbox.yview)
        files_scrollbar.grid(row=1, column=2, sticky=(tk.N, tk.S), pady=5)
        self.files_listbox.configure(yscrollcommand=files_scrollbar.set)

        self.listbox_menu = tk.Menu(self.files_listbox, tearoff=0)
        self.listbox_menu.add_command(
            label="Remove Selected", command=self.remove_selected_files)
        self.listbox_menu.add_command(
            label="Remove All", command=self.clear_files)
        self.files_listbox.bind("<Button-3>", self.show_listbox_menu)

        # File/Folder buttons
        file_buttons_frame = ttk.Frame(main_frame)
        file_buttons_frame.grid(row=2, column=1, sticky=tk.W, pady=5)

        ttk.Button(file_buttons_frame, text="Add Files (Any Type)",
                   command=self.add_files).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_buttons_frame, text="Add Folder",
                   command=self.add_folder).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_buttons_frame, text="Add Multiple Folders",
                   command=self.add_multiple_folders).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_buttons_frame, text="Remove Selected",
                   command=self.remove_selected_files).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_buttons_frame, text="Clear All",
                   command=self.clear_files).pack(side=tk.LEFT, padx=2)

        # Keyword input
        ttk.Label(main_frame, text="Search Keyword:").grid(
            row=3, column=0, sticky=tk.W, pady=5)

        keyword_frame = ttk.Frame(main_frame)
        keyword_frame.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)

        self.keyword_entry = ttk.Entry(keyword_frame, width=50)
        self.keyword_entry.grid(row=0, column=0, sticky=(tk.W, tk.E))
        self.keyword_entry.bind('<KeyRelease>', self.validate_keyword_input)

        self.keyword_length_label = ttk.Label(
            keyword_frame, text="0/1000", foreground="gray")
        self.keyword_length_label.grid(row=0, column=1, padx=5)

        keyword_frame.columnconfigure(0, weight=1)

        # Password options frame (for protected archives)
        password_frame = ttk.LabelFrame(
            main_frame, text="Password Options (for protected archives)", padding="5")
        password_frame.grid(row=4, column=0, columnspan=3,
                            sticky=(tk.W, tk.E), pady=5)

        global_pass_frame = ttk.Frame(password_frame)
        global_pass_frame.pack(fill=tk.X, pady=2)

        ttk.Label(global_pass_frame, text="Global Password:").pack(
            side=tk.LEFT, padx=5)
        self.global_password_entry = ttk.Entry(
            global_pass_frame, show="*", width=30)
        self.global_password_entry.pack(side=tk.LEFT, padx=5)

        self.show_global_pass = tk.BooleanVar()
        ttk.Checkbutton(global_pass_frame, text="Show", variable=self.show_global_pass,
                        command=self.toggle_global_password).pack(side=tk.LEFT, padx=5)

        ttk.Button(global_pass_frame, text="Clear",
                   command=lambda: self.global_password_entry.delete(0, tk.END)).pack(side=tk.LEFT, padx=5)

        default_pass_frame = ttk.Frame(password_frame)
        default_pass_frame.pack(fill=tk.X, pady=2)

        ttk.Label(default_pass_frame,
                  text="Default Passwords (comma-separated):").pack(side=tk.LEFT, padx=5)
        self.default_passwords_entry = ttk.Entry(default_pass_frame, width=40)
        self.default_passwords_entry.pack(
            side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        ttk.Button(default_pass_frame, text="Load from File",
                   command=self.load_password_file).pack(side=tk.LEFT, padx=5)

        self.prompt_for_password = tk.BooleanVar(value=True)
        ttk.Checkbutton(password_frame, text="Prompt for password if file is protected",
                        variable=self.prompt_for_password).pack(anchor=tk.W, padx=5, pady=2)

        # Search Options frame
        options_frame = ttk.LabelFrame(
            main_frame, text=f"Search Options ({self.search_tool or 'Python'})", padding="5")
        options_frame.grid(row=5, column=0, columnspan=3,
                           sticky=(tk.W, tk.E), pady=5)

        # First row
        opt_row1 = ttk.Frame(options_frame)
        opt_row1.pack(fill=tk.X, pady=2)

        self.case_sensitive = tk.BooleanVar()
        case_text = "Case Sensitive" if not self.search_tool else "Case Sensitive (-i inverted)"
        ttk.Checkbutton(opt_row1, text=case_text,
                        variable=self.case_sensitive).pack(side=tk.LEFT, padx=10)

        self.whole_word = tk.BooleanVar()
        word_text = "Whole Word Match" if not self.search_tool else "Whole Word (-w)"
        ttk.Checkbutton(opt_row1, text=word_text,
                        variable=self.whole_word).pack(side=tk.LEFT, padx=10)

        if self.search_tool == 'grep':
            self.search_binary = tk.BooleanVar(value=True)
            ttk.Checkbutton(opt_row1, text="Binary Files (-a)",
                            variable=self.search_binary).pack(side=tk.LEFT, padx=10)

        # Second row
        opt_row2 = ttk.Frame(options_frame)
        opt_row2.pack(fill=tk.X, pady=2)

        self.line_numbers = tk.BooleanVar(value=True)
        line_text = "Show Line Numbers" if not self.search_tool else "Line Numbers (-n)"
        ttk.Checkbutton(opt_row2, text=line_text,
                        variable=self.line_numbers).pack(side=tk.LEFT, padx=10)

        self.recursive_search = tk.BooleanVar(value=True)
        rec_text = "Recursive Search" if not self.search_tool else "Recursive (-r)"
        ttk.Checkbutton(opt_row2, text=rec_text,
                        variable=self.recursive_search).pack(side=tk.LEFT, padx=10)

        if self.search_tool == 'grep':
            self.extended_regex = tk.BooleanVar()
            ttk.Checkbutton(opt_row2, text="Extended Regex (-E)",
                            variable=self.extended_regex).pack(side=tk.LEFT, padx=10)

        # Third row
        opt_row3 = ttk.Frame(options_frame)
        opt_row3.pack(fill=tk.X, pady=2)

        if self.search_tool == 'grep':
            ttk.Label(opt_row3, text="Context Lines:").pack(
                side=tk.LEFT, padx=5)
            self.context_lines = tk.IntVar(value=0)
            ttk.Spinbox(opt_row3, from_=0, to=10, textvariable=self.context_lines, width=5).pack(
                side=tk.LEFT, padx=5)

        ttk.Label(opt_row3, text="Max Folder Depth:").pack(
            side=tk.LEFT, padx=5)
        self.max_depth = tk.IntVar(value=1000)
        depth_spinbox = ttk.Spinbox(
            opt_row3,
            from_=1,
            to=self.MAX_DEPTH_LIMIT,
            textvariable=self.max_depth,
            width=10,
            command=self.validate_depth
        )
        depth_spinbox.pack(side=tk.LEFT)

        # File type filter
        opt_row4 = ttk.Frame(options_frame)
        opt_row4.pack(fill=tk.X, pady=2)

        ttk.Label(
            opt_row4, text="File Extensions (comma-separated, leave empty for all):").pack(side=tk.LEFT, padx=5)
        self.file_extensions_entry = ttk.Entry(opt_row4, width=40)
        self.file_extensions_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(opt_row4, text="e.g., .txt,.log,.py",
                  foreground="gray").pack(side=tk.LEFT)

        # Search button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=3, pady=10)

        search_btn_text = f"Search with {self.search_tool.upper()}" if self.search_tool else "Search (Python)"
        self.search_button = ttk.Button(
            button_frame, text=search_btn_text, command=self.start_search, width=20)
        self.search_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(
            button_frame, text="Stop", command=self.stop_search_func, width=15, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="Clear Results",
                   command=self.clear_results, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Results",
                   command=self.export_results, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Passwords",
                   command=self.clear_password_cache, width=15).pack(side=tk.LEFT, padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=7, column=0, columnspan=3,
                           sticky=(tk.W, tk.E), pady=5)

        # Status label
        tool_name = self.search_tool.upper() if self.search_tool else "Python"
        self.status_label = ttk.Label(
            main_frame, text=f"Ready - Searching ALL file types with {tool_name}", relief=tk.SUNKEN)
        self.status_label.grid(
            row=8, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        # Results area
        results_frame = ttk.LabelFrame(
            main_frame, text="Search Results", padding="5")
        results_frame.grid(row=9, column=0, columnspan=3,
                           sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        self.results_text = scrolledtext.ScrolledText(
            results_frame, height=20, wrap=tk.WORD, font=('Courier', 9))
        self.results_text.grid(
            row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.results_text.bind("<Key>", lambda e: "break")

    def build_grep_command(self, keyword, target_path):
        """Build grep command: grep -arnw [options] 'keyword' path"""
        cmd = ['grep']

        # Core flags for comprehensive search
        cmd.append('-a')  # Treat binary files as text
        cmd.append('-r')  # Recursive
        cmd.append('-n')  # Line numbers

        # Case sensitivity
        if not self.case_sensitive.get():
            cmd.append('-i')  # Case insensitive

        # Whole word
        if self.whole_word.get():
            cmd.append('-w')  # Whole word match

        # Extended regex
        if hasattr(self, 'extended_regex') and self.extended_regex.get():
            cmd.append('-E')  # Extended regex

        # Context lines
        if hasattr(self, 'context_lines'):
            context = self.context_lines.get()
            if context > 0:
                cmd.append(f'-C{context}')

        # Additional useful flags
        cmd.append('-H')  # Always print filename
        cmd.append('--color=never')  # No ANSI color codes
        cmd.append('--binary-files=text')  # Treat binary as text

        # File extension filter
        extensions = self.file_extensions_entry.get().strip()
        if extensions:
            ext_list = [e.strip() for e in extensions.split(',') if e.strip()]
            for ext in ext_list:
                if not ext.startswith('.'):
                    ext = '.' + ext
                cmd.append(f'--include=*{ext}')

        # Pattern and path
        cmd.append(keyword)
        cmd.append(target_path)

        return cmd

    def build_findstr_command(self, keyword, target_path):
        """Build findstr command: findstr /S /N /I /C:"keyword" files"""
        cmd = ['findstr']

        # Core flags
        cmd.append('/S')  # Search subdirectories
        cmd.append('/N')  # Line numbers

        # Case sensitivity
        if not self.case_sensitive.get():
            cmd.append('/I')  # Case insensitive

        # Literal string or regex
        if hasattr(self, 'extended_regex') and self.extended_regex.get():
            cmd.append('/R')  # Regular expression
        else:
            cmd.append('/C:' + keyword)  # Literal string with /C:

            # File pattern based on extensions
            extensions = self.file_extensions_entry.get().strip()
            if extensions:
                ext_list = [e.strip()
                            for e in extensions.split(',') if e.strip()]
                patterns = []
                for ext in ext_list:
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    patterns.append(f'*{ext}')
                cmd.append(' '.join(patterns))
            else:
                cmd.append('*')  # Search all files

            return cmd

        # If regex, add pattern separately
        cmd.append(keyword)

        extensions = self.file_extensions_entry.get().strip()
        if extensions:
            ext_list = [e.strip() for e in extensions.split(',') if e.strip()]
            patterns = []
            for ext in ext_list:
                if not ext.startswith('.'):
                    ext = '.' + ext
                patterns.append(f'*{ext}')
            cmd.append(' '.join(patterns))
        else:
            cmd.append('*')

        return cmd

    def run_search_command(self, keyword, search_path, display_name):
        """Run appropriate search command based on OS and available tools"""
        matches = []

        try:
            if self.search_tool == 'grep':
                cmd = self.build_grep_command(keyword, search_path)
            elif self.search_tool == 'findstr':
                cmd = self.build_findstr_command(keyword, search_path)
            else:
                # Fallback to Python search
                return self.python_search(keyword, search_path, display_name)

            logging.info(f"Running command: {' '.join(cmd)}")

            # Change to search directory for findstr
            cwd = search_path if self.search_tool == 'findstr' else None

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.TIMEOUT_SECONDS,
                cwd=cwd,
                errors='ignore'  # Ignore encoding errors
            )

            # Process output
            if result.returncode == 0 or (self.search_tool == 'findstr' and result.stdout):
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        # Clean up the path
                        if search_path in line:
                            relative_line = line.replace(
                                search_path + os.sep, '').replace(search_path + '/', '')
                        else:
                            relative_line = line

                        matches.append(f"✓ {display_name} >> {relative_line}")

            # Log stderr if present (warnings, not necessarily errors)
            if result.stderr and result.returncode not in [0, 1]:
                logging.warning(f"Search stderr: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            logging.error(f"Search timeout for {display_name}")
            matches.append(f"⚠ TIMEOUT: {display_name}")
        except Exception as e:
            logging.error(f"Search execution error: {str(e)}")
            matches.append(f"✗ ERROR: {display_name}: {str(e)}")

        return matches

    def python_search(self, keyword, search_path, display_name):
        """Fallback Python-based search"""
        matches = []

        try:
            search_keyword = keyword if self.case_sensitive.get() else keyword.lower()

            # Get file extension filter
            extensions = self.file_extensions_entry.get().strip()
            ext_filter = None
            if extensions:
                ext_filter = [e.strip() if e.strip().startswith('.') else '.' + e.strip()
                              for e in extensions.split(',') if e.strip()]

            for root, dirs, files in os.walk(search_path):
                # Limit depth
                depth = root[len(search_path):].count(os.sep)
                if depth > self.max_depth.get():
                    dirs.clear()
                    continue

                for file in files:
                    # Check extension filter
                    if ext_filter and not any(file.lower().endswith(ext.lower()) for ext in ext_filter):
                        continue

                    file_path = os.path.join(root, file)

                    try:
                        # Try to read as text
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line_num, line in enumerate(f, 1):
                                search_line = line if self.case_sensitive.get() else line.lower()

                                if self.whole_word.get():
                                    # Simple whole word check
                                    if re.search(r'\b' + re.escape(search_keyword) + r'\b', search_line):
                                        relative_path = os.path.relpath(
                                            file_path, search_path)
                                        if self.line_numbers.get():
                                            matches.append(
                                                f"✓ {display_name} >> {relative_path}:{line_num}: {line.strip()[:100]}")
                                        else:
                                            matches.append(
                                                f"✓ {display_name} >> {relative_path}")
                                        break
                                else:
                                    if search_keyword in search_line:
                                        relative_path = os.path.relpath(
                                            file_path, search_path)
                                        if self.line_numbers.get():
                                            matches.append(
                                                f"✓ {display_name} >> {relative_path}:{line_num}: {line.strip()[:100]}")
                                        else:
                                            matches.append(
                                                f"✓ {display_name} >> {relative_path}")
                                        break
                    except Exception:
                        # Skip files that can't be read
                        continue
        except Exception as e:
            logging.error(f"Python search error: {str(e)}")
            matches.append(f"✗ ERROR: {display_name}: {str(e)}")

        return matches

    def search_item(self, item_path, keyword):
        """Search a file or folder (with or without extraction)"""
        matches_count = 0
        temp_dir = None

        try:
            # Check if it's a directory
            if os.path.isdir(item_path):
                # Direct folder search - no extraction needed
                self.result_queue.put({
                    'type': 'status',
                    'text': f"Searching folder: {os.path.basename(item_path)}"
                })

                matches = self.run_search_command(
                    keyword, item_path, os.path.basename(item_path))
                matches_count = len(matches)

                for match in matches:
                    self.result_queue.put({'type': 'result', 'text': match})

            # Check if it's an archive that needs extraction
            elif self.is_archive(item_path):
                temp_dir = tempfile.mkdtemp(
                    prefix='archive_search_', dir=self.temp_base_dir)

                self.result_queue.put({
                    'type': 'status',
                    'text': f"Extracting: {os.path.basename(item_path)}"
                })

                # Extract the archive
                if item_path.endswith('.tar.gz') or item_path.endswith('.tgz'):
                    with tarfile.open(item_path, 'r:gz') as tar:
                        tar.extractall(temp_dir, filter='data')
                elif item_path.endswith('.tar'):
                    with tarfile.open(item_path, 'r') as tar:
                        tar.extractall(temp_dir, filter='data')
                elif item_path.endswith('.gz') and not item_path.endswith('.tar.gz'):
                    output_file = os.path.join(
                        temp_dir, os.path.basename(item_path)[:-3])
                    with gzip.open(item_path, 'rb') as gz_in:
                        with open(output_file, 'wb') as file_out:
                            shutil.copyfileobj(gz_in, file_out)
                elif item_path.endswith('.zip'):
                    password = self.get_archive_password(item_path, 'zip')
                    if password is False:
                        return 0
                    with zipfile.ZipFile(item_path, 'r') as zip_file:
                        if password:
                            zip_file.extractall(
                                temp_dir, pwd=password.encode('utf-8'))
                        else:
                            zip_file.extractall(temp_dir)
                elif item_path.endswith('.7z') and PY7ZR_AVAILABLE:
                    password = self.get_archive_password(item_path, '7z')
                    if password is False:
                        return 0
                    if password:
                        with py7zr.SevenZipFile(item_path, 'r', password=password) as archive:
                            archive.extractall(temp_dir)
                    else:
                        with py7zr.SevenZipFile(item_path, 'r') as archive:
                            archive.extractall(temp_dir)

                self.result_queue.put({
                    'type': 'status',
                    'text': f"Searching: {os.path.basename(item_path)}"
                })

                # Search extracted content
                matches = self.run_search_command(
                    keyword, temp_dir, os.path.basename(item_path))
                matches_count = len(matches)

                for match in matches:
                    self.result_queue.put({'type': 'result', 'text': match})

            # Regular file - search directly
            else:
                self.result_queue.put({
                    'type': 'status',
                    'text': f"Searching file: {os.path.basename(item_path)}"
                })

                # For single files, search in parent directory with filename filter
                parent_dir = os.path.dirname(item_path)
                filename = os.path.basename(item_path)

                # Temporarily save extension filter
                old_filter = self.file_extensions_entry.get()
                file_ext = os.path.splitext(filename)[1]
                if file_ext:
                    self.file_extensions_entry.delete(0, tk.END)
                    self.file_extensions_entry.insert(0, file_ext)

                matches = self.run_search_command(
                    keyword, parent_dir, filename)

                # Filter to only this file
                matches = [m for m in matches if filename in m]
                matches_count = len(matches)

                # Restore extension filter
                self.file_extensions_entry.delete(0, tk.END)
                self.file_extensions_entry.insert(0, old_filter)

                for match in matches:
                    self.result_queue.put({'type': 'result', 'text': match})

        except Exception as e:
            logging.error(f"Search error for {item_path}: {str(e)}")
            self.result_queue.put({
                'type': 'error',
                'text': f"{os.path.basename(item_path)}: {str(e)}"
            })
        finally:
            # Cleanup temp directory
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logging.warning(
                        f"Failed to cleanup temp dir {temp_dir}: {str(e)}")

        return matches_count

    def get_archive_password(self, archive_path, archive_type):
        """Get password for protected archive"""
        passwords = self.get_passwords_to_try(archive_path)

        for password in passwords:
            try:
                if archive_type == 'zip':
                    with zipfile.ZipFile(archive_path, 'r') as zf:
                        zf.testzip()
                        if password:
                            # Test with password
                            first_file = zf.namelist()[0]
                            zf.read(first_file, pwd=password.encode(
                                'utf-8') if password else None)
                        return password
                elif archive_type == '7z' and PY7ZR_AVAILABLE:
                    if password:
                        with py7zr.SevenZipFile(archive_path, 'r', password=password) as archive:
                            archive.getnames()
                    else:
                        with py7zr.SevenZipFile(archive_path, 'r') as archive:
                            archive.getnames()
                    return password
            except:
                continue

        # Request from user
        if self.prompt_for_password.get():
            password_response = self.request_password(archive_path)

            if password_response:
                password, remember = password_response

                if password == "CANCEL_ALL":
                    self.stop_search = True
                    return False

                if password is None:
                    return False

                # Test password
                try:
                    if archive_type == 'zip':
                        with zipfile.ZipFile(archive_path, 'r') as zf:
                            if password:
                                first_file = zf.namelist()[0]
                                zf.read(
                                    first_file, pwd=password.encode('utf-8'))
                            else:
                                zf.testzip()
                    elif archive_type == '7z' and PY7ZR_AVAILABLE:
                        if password:
                            with py7zr.SevenZipFile(archive_path, 'r', password=password) as archive:
                                archive.getnames()
                        else:
                            with py7zr.SevenZipFile(archive_path, 'r') as archive:
                                archive.getnames()

                    if remember:
                        file_hash = self.get_file_hash(archive_path)
                        self.password_cache[file_hash] = password

                    return password
                except:
                    return False

        return False

    # [Keep all the helper methods from previous version]
    def show_listbox_menu(self, event):
        try:
            self.listbox_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.listbox_menu.grab_release()

    def remove_selected_files(self):
        selected = self.files_listbox.curselection()
        if not selected:
            messagebox.showinfo(
                "No Selection", "Please select items to remove")
            return
        for index in reversed(selected):
            self.files_listbox.delete(index)
        self.update_file_count()

    def toggle_global_password(self):
        if self.show_global_pass.get():
            self.global_password_entry.config(show="")
        else:
            self.global_password_entry.config(show="*")

    def load_password_file(self):
        try:
            file_path = filedialog.askopenfilename(
                title="Select Password File",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                with open(file_path, 'r', encoding='utf-8') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                current = self.default_passwords_entry.get()
                if current:
                    all_passwords = current + "," + ",".join(passwords)
                else:
                    all_passwords = ",".join(passwords)
                self.default_passwords_entry.delete(0, tk.END)
                self.default_passwords_entry.insert(0, all_passwords)
                messagebox.showinfo(
                    "Success", f"Loaded {len(passwords)} password(s)")
        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to load password file: {str(e)}")

    def clear_password_cache(self):
        self.password_cache.clear()
        self.password_attempts.clear()
        messagebox.showinfo("Success", "Password cache cleared")

    def get_file_hash(self, file_path):
        try:
            return hashlib.md5(file_path.encode()).hexdigest()
        except:
            return file_path

    def get_passwords_to_try(self, archive_path):
        passwords = []
        file_hash = self.get_file_hash(archive_path)
        if file_hash in self.password_cache:
            passwords.append(self.password_cache[file_hash])
        global_pass = self.global_password_entry.get().strip()
        if global_pass and global_pass not in passwords:
            passwords.append(global_pass)
        default_pass = self.default_passwords_entry.get().strip()
        if default_pass:
            for pwd in default_pass.split(','):
                pwd = pwd.strip()
                if pwd and pwd not in passwords:
                    passwords.append(pwd)
        if "" not in passwords:
            passwords.append("")
        return passwords

    def request_password(self, archive_path):
        if not self.prompt_for_password.get():
            return None
        file_hash = self.get_file_hash(archive_path)
        if file_hash in self.password_attempts:
            if self.password_attempts[file_hash] >= self.MAX_PASSWORD_ATTEMPTS:
                return None
        else:
            self.password_attempts[file_hash] = 0
        self.password_queue.put({'archive': archive_path, 'request': True})
        while True:
            try:
                response = self.password_queue.get(timeout=0.1)
                if 'password' in response:
                    self.password_attempts[file_hash] = self.password_attempts.get(
                        file_hash, 0) + 1
                    return response['password'], response.get('remember', False)
            except queue.Empty:
                if self.stop_search:
                    return None
                continue

    def validate_keyword_input(self, event=None):
        keyword = self.keyword_entry.get()
        length = len(keyword)
        self.keyword_length_label.config(
            text=f"{length}/{self.MAX_KEYWORD_LENGTH}")
        if length > self.MAX_KEYWORD_LENGTH:
            self.keyword_length_label.config(foreground="red")
            self.keyword_entry.delete(self.MAX_KEYWORD_LENGTH, tk.END)
        elif length > self.MAX_KEYWORD_LENGTH * 0.9:
            self.keyword_length_label.config(foreground="orange")
        else:
            self.keyword_length_label.config(foreground="gray")

    def validate_depth(self):
        try:
            depth = self.max_depth.get()
            if depth < 1:
                self.max_depth.set(1)
            elif depth > self.MAX_DEPTH_LIMIT:
                self.max_depth.set(self.MAX_DEPTH_LIMIT)
        except tk.TclError:
            self.max_depth.set(1000)

    def validate_keyword(self, keyword):
        if not keyword or not keyword.strip():
            raise ValidationException("Keyword cannot be empty")
        if len(keyword) > self.MAX_KEYWORD_LENGTH:
            raise ValidationException(f"Keyword too long")
        return True

    def format_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    def update_file_count(self):
        count = self.files_listbox.size()
        self.file_count_display.config(text=f"({count} items)")

    def add_files(self):
        try:
            files = filedialog.askopenfilenames(
                title="Select Files (ANY TYPE)",
                filetypes=[("All files", "*.*")]
            )
            if not files:
                return
            added = 0
            existing_items = set(self.files_listbox.get(0, tk.END))
            for file in files:
                if os.path.exists(file) and file not in existing_items:
                    self.files_listbox.insert(tk.END, file)
                    existing_items.add(file)
                    added += 1
            self.update_file_count()
            if added > 0:
                messagebox.showinfo("Success", f"Added {added} file(s)")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add files: {str(e)}")

    def add_folder(self):
        try:
            folder = filedialog.askdirectory(title="Select Folder")
            if not folder:
                return
            existing_items = set(self.files_listbox.get(0, tk.END))
            if folder not in existing_items:
                self.files_listbox.insert(tk.END, folder)
                self.update_file_count()
                messagebox.showinfo("Success", "Folder added")
            else:
                messagebox.showinfo("Info", "Folder already in list")
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {str(e)}")

    def add_multiple_folders(self):
        try:
            dialog = MultiFolderDialog(self.root)
            folders = dialog.selected_folders
            if not folders:
                return
            added = 0
            existing_items = set(self.files_listbox.get(0, tk.END))
            for folder in folders:
                if folder not in existing_items:
                    self.files_listbox.insert(tk.END, folder)
                    existing_items.add(folder)
                    added += 1
            self.update_file_count()
            if added > 0:
                messagebox.showinfo("Success", f"Added {added} folder(s)")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def clear_files(self):
        count = self.files_listbox.size()
        if count > 0:
            if messagebox.askyesno("Confirm", f"Remove all {count} item(s)?"):
                self.files_listbox.delete(0, tk.END)
                self.update_file_count()

    def clear_results(self):
        self.results_text.delete(1.0, tk.END)

    def export_results(self):
        try:
            content = self.results_text.get(1.0, tk.END)
            if not content.strip():
                messagebox.showwarning("Warning", "No results to export")
                return
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"search_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")

    def stop_search_func(self):
        self.stop_search = True
        self.update_status("Stopping...")

    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()

    def start_search(self):
        try:
            keyword = self.keyword_entry.get().strip()
            self.validate_keyword(keyword)
            items = list(self.files_listbox.get(0, tk.END))
            if not items:
                raise ValidationException(
                    "Please add at least one file or folder")

            # Create temp base directory
            self.temp_base_dir = tempfile.mkdtemp(prefix='universal_searcher_')

            self.total_processed_size = 0
            self.error_count = 0
            self.search_start_time = datetime.now()
            self.stop_search = False

            self.search_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.progress.start()
            self.clear_results()

            logging.info(
                f"Starting search: '{keyword}' across {len(items)} items")

            self.search_thread = threading.Thread(
                target=self.perform_search,
                args=(items, keyword),
                daemon=True
            )
            self.search_thread.start()
            self.check_queue()

        except (ValidationException, SecurityException) as e:
            messagebox.showwarning("Validation Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start: {str(e)}")

    def check_queue(self):
        try:
            while True:
                msg = self.result_queue.get_nowait()
                if msg['type'] == 'result':
                    self.results_text.insert(tk.END, msg['text'] + "\n")
                    self.results_text.see(tk.END)
                elif msg['type'] == 'status':
                    self.update_status(msg['text'])
                elif msg['type'] == 'error':
                    self.results_text.insert(tk.END, f"ERROR: {msg['text']}\n")
                elif msg['type'] == 'warning':
                    self.results_text.insert(
                        tk.END, f"WARNING: {msg['text']}\n")
                elif msg['type'] == 'done':
                    self.search_complete()
                    return
        except queue.Empty:
            pass

        try:
            while True:
                msg = self.password_queue.get_nowait()
                if msg.get('request'):
                    dialog = PasswordDialog(self.root, msg['archive'])
                    self.password_queue.put({
                        'password': dialog.password,
                        'remember': dialog.remember
                    })
        except queue.Empty:
            pass

        if self.search_thread and self.search_thread.is_alive():
            self.root.after(100, self.check_queue)

    def search_complete(self):
        self.progress.stop()
        self.search_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        # Cleanup temp directory
        if self.temp_base_dir and os.path.exists(self.temp_base_dir):
            try:
                shutil.rmtree(self.temp_base_dir)
            except:
                pass

        if self.search_start_time:
            duration = (datetime.now() -
                        self.search_start_time).total_seconds()
            logging.info(f"Search completed in {duration:.2f} seconds")

        self.update_status(
            "Search completed" if not self.stop_search else "Search stopped")

    def perform_search(self, items, keyword):
        total_matches = 0
        total_items = len(items)
        processed_items = 0

        try:
            for idx, item_path in enumerate(items, 1):
                if self.stop_search:
                    break

                self.result_queue.put({
                    'type': 'status',
                    'text': f"Processing [{idx}/{total_items}]: {os.path.basename(item_path)}"
                })

                try:
                    if os.path.exists(item_path):
                        matches = self.search_item(item_path, keyword)
                        total_matches += matches
                        processed_items += 1
                    else:
                        self.result_queue.put({
                            'type': 'warning',
                            'text': f"Item not found: {item_path}"
                        })

                except Exception as e:
                    self.error_count += 1
                    self.result_queue.put({
                        'type': 'error',
                        'text': f"{os.path.basename(item_path)}: {str(e)}"
                    })

            # Summary
            summary = f"\n{'='*70}\n"
            summary += f"Search Summary:\n"
            summary += f"  Search tool: {self.search_tool or 'Python'}\n"
            summary += f"  Total matches: {total_matches}\n"
            summary += f"  Items processed: {processed_items}/{total_items}\n"
            summary += f"  Errors: {self.error_count}\n"

            if self.search_start_time:
                duration = (datetime.now() -
                            self.search_start_time).total_seconds()
                summary += f"  Duration: {duration:.2f} seconds\n"

            summary += f"{'='*70}"

            self.result_queue.put({'type': 'result', 'text': summary})

        except Exception as e:
            logging.critical(f"Critical error: {str(e)}")
            self.result_queue.put(
                {'type': 'error', 'text': f"Critical error: {str(e)}"})
        finally:
            self.result_queue.put({'type': 'done'})


def main():
    try:
        root = tk.Tk()
        app = ArchiveSearcherGUI(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Fatal error: {str(e)}")
        messagebox.showerror("Fatal Error", f"Application error:\n{str(e)}")


if __name__ == "__main__":
    main()
