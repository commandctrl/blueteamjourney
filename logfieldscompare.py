import pandas as pd
from difflib import SequenceMatcher
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import re
import html
from datetime import datetime
from pathlib import Path
import hashlib


class SecureFieldComparisonGUI:
    # Security constants - ADJUSTED FOR USABILITY
    MAX_FILE_SIZE = 500 * 1024 * 1024  # Increased to 500MB
    MAX_ROWS = 500000  # Increased to 500K rows
    MAX_STRING_LENGTH = 50000  # Increased string length
    ALLOWED_EXTENSIONS = {'.csv', '.xlsx', '.xls'}
    MAX_FIELD_NAME_LENGTH = 1000  # Increased field name length
    FORBIDDEN_PATTERNS = [
        r'\.\.[/\\]',  # Directory traversal
        r'^[/\\]{2}',  # UNC paths
    ]

    # Rename detection thresholds
    FIELD_NAME_SIMILARITY_THRESHOLD = 0.6  # 60% similar field names
    VALUE_SIMILARITY_THRESHOLD = 0.85  # 85% similar values to consider rename

    # Beautiful color scheme - SOFTER COLORS
    COLORS = {
        'primary_bg': '#F8F9FA',        # Soft light gray
        'secondary_bg': '#FFFFFF',       # Pure white
        'accent_blue': '#4A90E2',        # Soft blue
        'accent_green': '#52C41A',       # Fresh green
        'accent_orange': '#FA8C16',      # Warm orange
        'accent_red': '#F5222D',         # Soft red
        'accent_purple': '#9C27B0',      # Purple for renames
        'text_primary': '#2C3E50',       # Dark blue-gray
        'text_secondary': '#5A6C7D',     # Medium gray
        'border': '#E1E8ED',             # Light border
        'header_bg': '#667EEA',          # Purple-blue gradient start
        'header_text': '#FFFFFF',        # White text
        'success': '#52C41A',            # Green
        'warning': '#FAAD14',            # Yellow
        'error': '#FF4D4F',              # Red
        'info': '#1890FF',               # Blue
    }

    def __init__(self, root):
        self.root = root
        self.root.title(
            "Field & Value Comparison Tool - Secure Edition with Smart Analysis")
        self.root.geometry("1400x900")  # Wider for table view
        self.root.configure(bg=self.COLORS['primary_bg'])

        # Variables with validation
        self.prod_file = tk.StringVar(value="")
        self.dev_file = tk.StringVar(value="")
        self.results = None

        # Button colors - ALL BUTTONS NOW USE THESE
        self.BTN_DEFAULT_BG = '#5DADE2'  # Bright blue
        self.BTN_ACTIVE_BG = '#52C41A'   # Green when clicked
        self.BTN_HOVER_BG = '#3498DB'    # Darker blue on hover
        self.BTN_DISABLED_BG = '#BDC3C7'  # Light gray when disabled
        self.BTN_TEXT_COLOR = '#000000'  # BLACK TEXT for maximum visibility!

        # Create GUI
        self.create_widgets()

    def sanitize_string(self, value, max_length=None):
        """Sanitize string input to prevent injection attacks"""
        if value is None or pd.isna(value):
            return ""

        value = str(value)

        if max_length is None:
            max_length = self.MAX_STRING_LENGTH
        value = value[:max_length]

        value = value.replace('\x00', '')
        value = ''.join(char for char in value if ord(char)
                        >= 32 or char in '\n\t')

        return value

    def sanitize_html(self, text):
        """Escape HTML to prevent XSS attacks"""
        if text is None or pd.isna(text):
            return ""
        return html.escape(str(text), quote=True)

    def sanitize_csv_injection(self, value):
        """Prevent CSV formula injection attacks"""
        if value is None or pd.isna(value):
            return ""

        value = str(value)
        dangerous_prefixes = ['=', '+', '-', '@', '\t', '\r']

        if any(value.startswith(prefix) for prefix in dangerous_prefixes):
            value = "'" + value

        return value

    def validate_file_path(self, path_var):
        """Validate file path for security issues - RELAXED"""
        path = path_var.get()

        if not path:
            return True

        try:
            file_path = Path(path).resolve()

            if not file_path.exists():
                return False

            if not file_path.is_file():
                return False

            if file_path.suffix.lower() not in self.ALLOWED_EXTENSIONS:
                messagebox.showerror(
                    "Invalid File Type",
                    f"File must be CSV or Excel (.csv, .xlsx, .xls)\nSelected: {file_path.suffix}"
                )
                return False

            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.MAX_FILE_SIZE:
                messagebox.showerror(
                    "File Too Large",
                    f"File size: {file_size / (1024*1024):.1f}MB\n"
                    f"Maximum allowed: {self.MAX_FILE_SIZE / (1024*1024):.0f}MB"
                )
                return False

            # Relaxed path traversal check - only check for obvious attacks
            path_str = str(file_path)
            if '..' in path_str and ('/../' in path_str or '\\..\\' in path_str):
                messagebox.showerror("Error", "Suspicious file path detected!")
                return False

            return True

        except Exception as e:
            print(f"Path validation error: {e}")
            return False

    def validate_field_name(self, field_name):
        """Validate field names to prevent injection"""
        if not field_name or pd.isna(field_name):
            return False

        field_name = str(field_name)

        if len(field_name) > self.MAX_FIELD_NAME_LENGTH:
            return False

        if '\x00' in field_name:
            return False

        return True

    def calculate_similarity_safe(self, str1, str2):
        """Safely calculate similarity with bounds checking"""
        try:
            if not str1 or not str2:
                return 0.0

            str1 = str(str1)[:self.MAX_STRING_LENGTH]
            str2 = str(str2)[:self.MAX_STRING_LENGTH]

            return SequenceMatcher(None, str1, str2).ratio()
        except Exception:
            return 0.0

    def analyze_field_discrepancies(self, missing_in_dev, missing_in_prod, values_prod, values_dev):
        """
        COMBINED ANALYSIS: Detect missing fields AND potential renames with value comparison
        
        Returns: Dictionary with categorized field analysis
        """
        analysis = {
            'truly_missing_in_dev': [],      # Fields definitely missing
            'truly_missing_in_prod': [],     # Fields only in dev
            'potential_renames': [],         # Likely renamed fields
            'suspicious_fields': []          # Uncertain cases
        }

        self.update_status(
            "🔍 Analyzing field discrepancies and potential renames...")

        # Track which dev fields have been matched
        matched_dev_fields = set()

        # For each field missing in dev, analyze if it's truly missing or renamed
        for prod_field in missing_in_dev:
            prod_value = values_prod.get(prod_field, '')

            best_match = None
            best_score = 0

            # Compare with all fields only in dev (not yet matched)
            for dev_field in missing_in_prod:
                if dev_field in matched_dev_fields:
                    continue

                dev_value = values_dev.get(dev_field, '')

                # Calculate field name similarity
                field_name_similarity = self.calculate_similarity_safe(
                    prod_field, dev_field)

                # Calculate value similarity
                value_similarity = self.calculate_similarity_safe(
                    prod_value, dev_value)

                # Combined score (weighted: 30% field name, 70% value)
                combined_score = (field_name_similarity *
                                  0.3) + (value_similarity * 0.7)

                if combined_score > best_score:
                    best_score = combined_score
                    best_match = {
                        'prod_field': prod_field,
                        'dev_field': dev_field,
                        'prod_value': prod_value,
                        'dev_value': dev_value,
                        'field_name_similarity': field_name_similarity,
                        'value_similarity': value_similarity,
                        'combined_score': combined_score,
                        'confidence': self.calculate_confidence(field_name_similarity, value_similarity)
                    }

            # Categorize based on best match found
            if best_match:
                if best_match['value_similarity'] >= self.VALUE_SIMILARITY_THRESHOLD or \
                   (best_match['combined_score'] >= 0.7 and
                        best_match['field_name_similarity'] >= self.FIELD_NAME_SIMILARITY_THRESHOLD):
                    # High confidence rename
                    analysis['potential_renames'].append(best_match)
                    matched_dev_fields.add(best_match['dev_field'])
                elif best_match['combined_score'] >= 0.5:
                    # Uncertain - could be rename or different field
                    analysis['suspicious_fields'].append(best_match)
                else:
                    # Likely truly missing
                    analysis['truly_missing_in_dev'].append({
                        'field': prod_field,
                        'value': prod_value,
                        'best_match_score': best_match['combined_score'] if best_match else 0
                    })
            else:
                # No match found at all
                analysis['truly_missing_in_dev'].append({
                    'field': prod_field,
                    'value': prod_value,
                    'best_match_score': 0
                })

        # Remaining dev fields that weren't matched are truly new
        for dev_field in missing_in_prod:
            if dev_field not in matched_dev_fields:
                analysis['truly_missing_in_prod'].append({
                    'field': dev_field,
                    'value': values_dev.get(dev_field, '')
                })

        return analysis

    def calculate_confidence(self, field_name_sim, value_sim):
        """
        Calculate confidence level for rename detection
        Returns: "Very High", "High", "Medium", or "Low"
        """
        combined = (field_name_sim * 0.3) + (value_sim * 0.7)

        if combined >= 0.9 and value_sim >= 0.9:
            return "Very High"
        elif combined >= 0.8 and value_sim >= 0.85:
            return "High"
        elif combined >= 0.7 and value_sim >= 0.75:
            return "Medium"
        else:
            return "Low"

    def safe_file_read(self, file_path, max_rows=None):
        """Safely read file with size and content validation"""
        if max_rows is None:
            max_rows = self.MAX_ROWS

        try:
            file_path = Path(file_path).resolve()

            if not file_path.exists() or not os.access(file_path, os.R_OK):
                raise PermissionError(f"Cannot read file: {file_path}")

            file_extension = file_path.suffix.lower()

            if file_extension == '.csv':
                df = pd.read_csv(
                    file_path,
                    encoding='utf-8',
                    nrows=max_rows,
                    on_bad_lines='skip',
                    engine='python'
                )
            elif file_extension in ['.xlsx', '.xls']:
                df = pd.read_excel(
                    file_path,
                    engine='openpyxl' if file_extension == '.xlsx' else 'xlrd',
                    nrows=max_rows
                )
            else:
                raise ValueError(f"Unsupported file type: {file_extension}")

            if df is None or df.empty:
                raise ValueError("File is empty or unreadable")

            df.columns = [self.sanitize_string(col, self.MAX_FIELD_NAME_LENGTH)
                          for col in df.columns]

            for col in df.columns:
                if df[col].dtype == 'object':
                    df[col] = df[col].apply(lambda x: self.sanitize_string(x))

            return df

        except MemoryError:
            raise MemoryError("File too large to process. Try a smaller file.")
        except Exception as e:
            raise Exception(f"Error reading file: {str(e)}")

    def safe_export_path(self, directory):
        """Validate export directory for security"""
        try:
            dir_path = Path(directory).resolve()

            if not dir_path.exists():
                raise ValueError("Directory does not exist")

            if not dir_path.is_dir():
                raise ValueError("Path is not a directory")

            if not os.access(dir_path, os.W_OK):
                raise PermissionError("No write permission for directory")

            return dir_path

        except Exception as e:
            raise ValueError(f"Invalid export directory: {str(e)}")

    def generate_safe_filename(self, base_name, extension):
        """Generate safe filename with timestamp and validation"""
        safe_base = re.sub(r'[^a-zA-Z0-9_-]', '_', base_name)
        safe_base = safe_base[:50]

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        random_suffix = hashlib.md5(os.urandom(16)).hexdigest()[:8]

        if not extension.startswith('.'):
            extension = '.' + extension

        safe_extension = re.sub(r'[^.a-zA-Z0-9]', '', extension)

        return f"{safe_base}_{timestamp}_{random_suffix}{safe_extension}"

    def on_button_hover(self, event, button, hover_color):
        """Change button color on hover"""
        current_bg = button.cget('bg')
        # Only change if not in active (green) state
        if current_bg != self.BTN_ACTIVE_BG:
            button.config(bg=hover_color)

    def on_button_leave(self, event, button, default_color):
        """Reset button color when mouse leaves"""
        current_bg = button.cget('bg')
        # Only reset if not in active (green) state
        if current_bg != self.BTN_ACTIVE_BG:
            button.config(bg=default_color)

    def flash_button_success(self, button):
        """Flash button green to indicate successful action"""
        button.config(bg=self.BTN_ACTIVE_BG)
        # Reset to default color after 1.5 seconds
        self.root.after(1500, lambda: button.config(bg=self.BTN_DEFAULT_BG))

    def on_compare_click(self):
        """Handle compare button click with visual feedback"""
        self.flash_button_success(self.compare_button)
        self.run_comparison_secure()

    def on_export_click(self):
        """Handle export button click with visual feedback"""
        if not self.results:
            messagebox.showwarning(
                "Warning",
                "No comparison results to export. Please run a comparison first."
            )
            return
        self.flash_button_success(self.export_button)
        self.export_reports_secure()

    def on_clear_click(self):
        """Handle clear button click with visual feedback"""
        if not self.results:
            messagebox.showinfo("Info", "No results to clear.")
            return
        self.flash_button_success(self.clear_button)
        self.clear_results()

    def on_prod_browse_click(self):
        """Handle production browse button click with visual feedback"""
        self.flash_button_success(self.prod_browse_btn)
        self.browse_file_secure(self.prod_file)

    def on_dev_browse_click(self):
        """Handle development browse button click with visual feedback"""
        self.flash_button_success(self.dev_browse_btn)
        self.browse_file_secure(self.dev_file)

    def create_widgets(self):
        # Modern gradient header
        title_frame = tk.Frame(
            self.root, bg=self.COLORS['header_bg'], height=100)
        title_frame.pack(fill='x', pady=(0, 15))
        title_frame.pack_propagate(False)

        title_label = tk.Label(
            title_frame,
            text="🔍 Log Fields Comparative Analysis Tool",
            font=('Helvetica', 28, 'bold'),
            bg=self.COLORS['header_bg'],
            fg=self.COLORS['header_text']
        )
        title_label.pack(expand=True, pady=(20, 5))

        subtitle_label = tk.Label(
            title_frame,
            text="Secure • Fast • Accurate • Smart Analysis & Rename Detection",
            font=('Helvetica', 12),
            bg=self.COLORS['header_bg'],
            fg=self.COLORS['header_text']
        )
        subtitle_label.pack()

        # Security notice with softer colors
        security_notice = tk.Label(
            self.root,
            text="🛡️ Compare two exports, one from production and the other from dev, to show changes in Log Fields🛡️",
            font=('Helvetica', 9),
            bg=self.COLORS['success'],
            fg='white',
            pady=8
        )
        security_notice.pack(fill='x')

        # Main container with soft background
        main_frame = tk.Frame(self.root, bg=self.COLORS['primary_bg'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)

        # File selection with beautiful styling
        file_frame = tk.LabelFrame(
            main_frame,
            text="  📁 File Selection  ",
            font=('Helvetica', 13, 'bold'),
            bg=self.COLORS['secondary_bg'],
            fg=self.COLORS['text_primary'],
            borderwidth=2,
            relief='groove',
            padx=20,
            pady=20
        )
        file_frame.pack(fill='x', pady=(0, 15))

        # Info label
        info_label = tk.Label(
            file_frame,
            text="Select CSV or Excel files (up to 500MB each)",
            font=('Helvetica', 9, 'italic'),
            bg=self.COLORS['secondary_bg'],
            fg=self.COLORS['text_secondary']
        )
        info_label.grid(row=0, column=0, columnspan=3,
                        sticky='w', pady=(0, 10))

        # Production file
        tk.Label(
            file_frame,
            text="Production File:",
            font=('Helvetica', 11, 'bold'),
            bg=self.COLORS['secondary_bg'],
            fg=self.COLORS['text_primary']
        ).grid(row=1, column=0, sticky='w', pady=8)

        prod_entry = tk.Entry(
            file_frame,
            textvariable=self.prod_file,
            font=('Helvetica', 10),
            width=85,  # Wider for longer paths
            bg='white',
            fg=self.COLORS['text_primary'],
            relief='solid',
            borderwidth=1
        )
        prod_entry.grid(row=1, column=1, padx=10, pady=8)

        # Production Browse Button with BLACK TEXT
        self.prod_browse_btn = tk.Button(
            file_frame,
            text="📂 Browse",
            command=self.on_prod_browse_click,
            bg=self.BTN_DEFAULT_BG,
            fg=self.BTN_TEXT_COLOR,
            font=('Helvetica', 11, 'bold'),
            cursor='hand2',
            relief='raised',
            borderwidth=3,
            padx=20,
            pady=10,
            activebackground=self.BTN_ACTIVE_BG,
            activeforeground=self.BTN_TEXT_COLOR
        )
        self.prod_browse_btn.grid(row=1, column=2, pady=8)

        # Bind hover events for production browse button
        self.prod_browse_btn.bind('<Enter>', lambda e: self.on_button_hover(
            e, self.prod_browse_btn, self.BTN_HOVER_BG))
        self.prod_browse_btn.bind('<Leave>', lambda e: self.on_button_leave(
            e, self.prod_browse_btn, self.BTN_DEFAULT_BG))

        # Development file
        tk.Label(
            file_frame,
            text="Development File:",
            font=('Helvetica', 11, 'bold'),
            bg=self.COLORS['secondary_bg'],
            fg=self.COLORS['text_primary']
        ).grid(row=2, column=0, sticky='w', pady=8)

        dev_entry = tk.Entry(
            file_frame,
            textvariable=self.dev_file,
            font=('Helvetica', 10),
            width=85,  # Wider for longer paths
            bg='white',
            fg=self.COLORS['text_primary'],
            relief='solid',
            borderwidth=1
        )
        dev_entry.grid(row=2, column=1, padx=10, pady=8)

        # Development Browse Button with BLACK TEXT
        self.dev_browse_btn = tk.Button(
            file_frame,
            text="📂 Browse",
            command=self.on_dev_browse_click,
            bg=self.BTN_DEFAULT_BG,
            fg=self.BTN_TEXT_COLOR,
            font=('Helvetica', 11, 'bold'),
            cursor='hand2',
            relief='raised',
            borderwidth=3,
            padx=20,
            pady=10,
            activebackground=self.BTN_ACTIVE_BG,
            activeforeground=self.BTN_TEXT_COLOR
        )
        self.dev_browse_btn.grid(row=2, column=2, pady=8)

        # Bind hover events for development browse button
        self.dev_browse_btn.bind('<Enter>', lambda e: self.on_button_hover(
            e, self.dev_browse_btn, self.BTN_HOVER_BG))
        self.dev_browse_btn.bind('<Leave>', lambda e: self.on_button_leave(
            e, self.dev_browse_btn, self.BTN_DEFAULT_BG))

        # Action buttons with BLACK TEXT
        button_frame = tk.Frame(main_frame, bg=self.COLORS['primary_bg'])
        button_frame.pack(fill='x', pady=(0, 15))

        # Compare button with BLACK TEXT
        self.compare_button = tk.Button(
            button_frame,
            text="🔍 Compare Files",
            command=self.on_compare_click,
            bg=self.BTN_DEFAULT_BG,
            fg=self.BTN_TEXT_COLOR,
            font=('Helvetica', 13, 'bold'),
            width=18,
            height=2,
            cursor='hand2',
            relief='raised',
            borderwidth=4,
            activebackground=self.BTN_ACTIVE_BG,
            activeforeground=self.BTN_TEXT_COLOR
        )
        self.compare_button.pack(side='left', padx=5)

        # Bind hover events for compare button
        self.compare_button.bind('<Enter>', lambda e: self.on_button_hover(
            e, self.compare_button, self.BTN_HOVER_BG))
        self.compare_button.bind('<Leave>', lambda e: self.on_button_leave(
            e, self.compare_button, self.BTN_DEFAULT_BG))

        # Export button with BLACK TEXT
        self.export_button = tk.Button(
            button_frame,
            text="📊 Export Reports",
            command=self.on_export_click,
            bg=self.BTN_DEFAULT_BG,
            fg=self.BTN_TEXT_COLOR,
            font=('Helvetica', 13, 'bold'),
            width=18,
            height=2,
            cursor='hand2',
            relief='raised',
            borderwidth=4,
            activebackground=self.BTN_ACTIVE_BG,
            activeforeground=self.BTN_TEXT_COLOR
        )
        self.export_button.pack(side='left', padx=5)

        # Bind hover events for export button
        self.export_button.bind('<Enter>', lambda e: self.on_button_hover(
            e, self.export_button, self.BTN_HOVER_BG))
        self.export_button.bind('<Leave>', lambda e: self.on_button_leave(
            e, self.export_button, self.BTN_DEFAULT_BG))

        # Clear button with BLACK TEXT
        self.clear_button = tk.Button(
            button_frame,
            text="🗑️ Clear Results",
            command=self.on_clear_click,
            bg=self.BTN_DEFAULT_BG,
            fg=self.BTN_TEXT_COLOR,
            font=('Helvetica', 13, 'bold'),
            width=18,
            height=2,
            cursor='hand2',
            relief='raised',
            borderwidth=4,
            activebackground=self.BTN_ACTIVE_BG,
            activeforeground=self.BTN_TEXT_COLOR
        )
        self.clear_button.pack(side='left', padx=5)

        # Bind hover events for clear button
        self.clear_button.bind('<Enter>', lambda e: self.on_button_hover(
            e, self.clear_button, self.BTN_HOVER_BG))
        self.clear_button.bind('<Leave>', lambda e: self.on_button_leave(
            e, self.clear_button, self.BTN_DEFAULT_BG))

        # Progress bar with status
        self.progress_frame = tk.Frame(
            main_frame, bg=self.COLORS['primary_bg'])
        self.progress_frame.pack(fill='x', pady=(0, 15))

        style = ttk.Style()
        style.theme_use('default')
        style.configure("Custom.Horizontal.TProgressbar",
                        troughcolor=self.COLORS['border'],
                        background=self.COLORS['accent_blue'],
                        borderwidth=0)

        self.progress = ttk.Progressbar(
            self.progress_frame,
            mode='indeterminate',
            length=300,
            style="Custom.Horizontal.TProgressbar"
        )
        self.progress.pack(side='left', fill='x', expand=True, padx=5)

        self.status_label = tk.Label(
            self.progress_frame,
            text="✓ Ready - All systems operational",
            font=('Helvetica', 10),
            bg=self.COLORS['primary_bg'],
            fg=self.COLORS['text_secondary']
        )
        self.status_label.pack(side='left', padx=10)

        # Results notebook with custom styling
        style.configure('Custom.TNotebook',
                        background=self.COLORS['primary_bg'])
        style.configure('Custom.TNotebook.Tab',
                        padding=[20, 10],
                        font=('Helvetica', 10, 'bold'))

        self.notebook = ttk.Notebook(main_frame, style='Custom.TNotebook')
        self.notebook.pack(fill='both', expand=True)

        # Tab 1: Summary
        self.summary_tab = tk.Frame(
            self.notebook, bg=self.COLORS['secondary_bg'])
        self.notebook.add(self.summary_tab, text="📊 Summary")

        self.summary_text = scrolledtext.ScrolledText(
            self.summary_tab,
            font=('Consolas', 10),
            bg=self.COLORS['secondary_bg'],
            fg=self.COLORS['text_primary'],
            wrap=tk.WORD,
            state='disabled',
            relief='flat',
            padx=10,
            pady=10
        )
        self.summary_text.pack(fill='both', expand=True, padx=5, pady=5)

        # Tab 2: SIDE-BY-SIDE TABLE VIEW (NEW!)
        self.table_tab = tk.Frame(
            self.notebook, bg=self.COLORS['secondary_bg'])
        self.notebook.add(
            self.table_tab, text="📋 Side-by-Side Field Comparison")

        # Create treeview for table display
        self.create_table_view()

        # Tab 3: Detailed Field Analysis
        self.field_analysis_tab = tk.Frame(
            self.notebook, bg=self.COLORS['secondary_bg'])
        self.notebook.add(self.field_analysis_tab,
                          text="🔍 Detailed Field Analysis")

        self.field_analysis_text = scrolledtext.ScrolledText(
            self.field_analysis_tab,
            font=('Consolas', 10),
            bg=self.COLORS['secondary_bg'],
            fg=self.COLORS['text_primary'],
            wrap=tk.WORD,
            state='disabled',
            relief='flat',
            padx=10,
            pady=10
        )
        self.field_analysis_text.pack(fill='both', expand=True, padx=5, pady=5)

        # Tab 4: Metrics
        self.metrics_tab = tk.Frame(
            self.notebook, bg=self.COLORS['secondary_bg'])
        self.notebook.add(self.metrics_tab, text="📈 Metrics")

        self.create_metrics_view()

    def create_table_view(self):
        """Create treeview table for side-by-side comparison"""
        # Container frame
        table_container = tk.Frame(
            self.table_tab, bg=self.COLORS['secondary_bg'])
        table_container.pack(fill='both', expand=True, padx=10, pady=10)

        # Title label
        table_title = tk.Label(
            table_container,
            text="All Field Differences: Side-by-Side Comparison",
            font=('Helvetica', 14, 'bold'),
            bg=self.COLORS['secondary_bg'],
            fg=self.COLORS['text_primary']
        )
        table_title.pack(pady=(0, 10))

        # Create frame for treeview and scrollbars
        tree_frame = tk.Frame(table_container, bg=self.COLORS['secondary_bg'])
        tree_frame.pack(fill='both', expand=True)

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side='right', fill='y')

        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        hsb.pack(side='bottom', fill='x')

        # Define columns
        columns = (
            'Status',
            'Production Field',
            'Production Value',
            'Dev Field',
            'Dev Value',
            'Potential Rename',
            'Confidence',
            'Similarity'
        )

        # Create treeview
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show='headings',
            height=20,
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )

        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        # Configure column headings and widths
        self.tree.heading('Status', text='Status')
        self.tree.heading('Production Field', text='Production Field')
        self.tree.heading('Production Value', text='Production Value')
        self.tree.heading('Dev Field', text='Dev Field')
        self.tree.heading('Dev Value', text='Dev Value')
        self.tree.heading('Potential Rename', text='Potential Rename?')
        self.tree.heading('Confidence', text='Confidence')
        self.tree.heading('Similarity', text='Similarity %')

        self.tree.column('Status', width=120, anchor='center')
        self.tree.column('Production Field', width=200)
        self.tree.column('Production Value', width=250)
        self.tree.column('Dev Field', width=200)
        self.tree.column('Dev Value', width=250)
        self.tree.column('Potential Rename', width=120, anchor='center')
        self.tree.column('Confidence', width=100, anchor='center')
        self.tree.column('Similarity', width=100, anchor='center')

        # Configure row colors
        self.tree.tag_configure('rename', background='#E8F5E9')  # Light green
        self.tree.tag_configure('missing', background='#FFEBEE')  # Light red
        self.tree.tag_configure('new', background='#E3F2FD')  # Light blue
        self.tree.tag_configure(
            'different', background='#FFF3E0')  # Light orange
        self.tree.tag_configure(
            'exact', background='#F1F8E9')  # Very light green

        self.tree.pack(fill='both', expand=True)

        # Legend
        legend_frame = tk.Frame(
            table_container, bg=self.COLORS['secondary_bg'])
        legend_frame.pack(fill='x', pady=(10, 0))

        tk.Label(legend_frame, text="Legend:", font=('Helvetica', 10, 'bold'),
                 bg=self.COLORS['secondary_bg']).pack(side='left', padx=(0, 10))

        legends = [
            ('🔄 Potential Rename', '#E8F5E9'),
            ('❌ Missing', '#FFEBEE'),
            ('➕ New Field', '#E3F2FD'),
            ('⚠️ Value Diff', '#FFF3E0'),
            ('✅ Exact Match', '#F1F8E9')
        ]

        for text, color in legends:
            frame = tk.Frame(legend_frame, bg=color,
                             relief='solid', borderwidth=1)
            frame.pack(side='left', padx=5)
            tk.Label(frame, text=text, bg=color, font=('Helvetica', 9),
                     padx=8, pady=2).pack()

    def create_metrics_view(self):
        metrics_container = tk.Frame(
            self.metrics_tab, bg=self.COLORS['secondary_bg'])
        metrics_container.pack(fill='both', expand=True, padx=20, pady=20)

        # Grade display with gradient
        self.grade_frame = tk.Frame(
            metrics_container, bg=self.COLORS['border'], height=120)
        self.grade_frame.pack(fill='x', pady=(0, 25))
        self.grade_frame.pack_propagate(False)

        self.grade_label = tk.Label(
            self.grade_frame,
            text="No comparison yet - Select files to begin",
            font=('Helvetica', 18, 'bold'),
            bg=self.COLORS['border'],
            fg=self.COLORS['text_secondary']
        )
        self.grade_label.pack(expand=True)

        # Metrics bars
        self.metrics_labels = {}
        metrics = ['Field Coverage', 'Exact Match Rate',
                   'Avg Similarity', 'Overall Accuracy']

        for metric in metrics:
            frame = tk.Frame(metrics_container, bg=self.COLORS['secondary_bg'])
            frame.pack(fill='x', pady=12)

            tk.Label(
                frame,
                text=metric + ":",
                font=('Helvetica', 11, 'bold'),
                bg=self.COLORS['secondary_bg'],
                fg=self.COLORS['text_primary'],
                width=20,
                anchor='w'
            ).pack(side='left')

            bar_frame = tk.Frame(
                frame, bg=self.COLORS['border'], height=35, width=550)
            bar_frame.pack(side='left', padx=15)
            bar_frame.pack_propagate(False)

            bar = tk.Frame(bar_frame, bg=self.COLORS['accent_blue'], height=35)
            bar.place(x=0, y=0, relheight=1, relwidth=0)

            value_label = tk.Label(
                frame,
                text="0.00%",
                font=('Helvetica', 11, 'bold'),
                bg=self.COLORS['secondary_bg'],
                fg=self.COLORS['text_primary'],
                width=10
            )
            value_label.pack(side='left')

            self.metrics_labels[metric] = (bar, value_label, bar_frame)

    def browse_file_secure(self, var):
        """Secure file browsing with validation"""
        filename = filedialog.askopenfilename(
            title="Select a file (CSV or Excel)",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Excel files", "*.xlsx"),
                ("Excel files (legacy)", "*.xls"),
                ("All supported", "*.csv *.xlsx *.xls")
            ]
        )

        if filename:
            var.set(filename)
            if self.validate_file_path(var):
                self.update_status(f"✓ File selected: {Path(filename).name}")
            else:
                var.set("")

    def update_status(self, message):
        """Update status label safely"""
        safe_message = self.sanitize_string(message, 200)
        self.status_label.config(text=safe_message)
        self.root.update()

    def run_comparison_secure(self):
        """Securely run comparison with full validation"""
        if not self.prod_file.get() or not self.dev_file.get():
            messagebox.showwarning(
                "Missing Files", "Please select both production and development files.")
            return

        if not self.validate_file_path(self.prod_file):
            messagebox.showerror("Error", "Production file is invalid!")
            return

        if not self.validate_file_path(self.dev_file):
            messagebox.showerror("Error", "Development file is invalid!")
            return

        # Disable all buttons during processing
        self.compare_button.config(state='disabled', bg=self.BTN_DISABLED_BG)
        self.export_button.config(state='disabled', bg=self.BTN_DISABLED_BG)
        self.clear_button.config(state='disabled', bg=self.BTN_DISABLED_BG)
        self.prod_browse_btn.config(state='disabled', bg=self.BTN_DISABLED_BG)
        self.dev_browse_btn.config(state='disabled', bg=self.BTN_DISABLED_BG)

        self.progress.start(10)

        thread = threading.Thread(
            target=self.compare_files_secure, daemon=True)
        thread.start()

    def compare_files_secure(self):
        """Securely compare files with COMBINED field and value analysis"""
        try:
            self.update_status("🔄 Loading files...")

            df1 = self.safe_file_read(self.prod_file.get())
            df2 = self.safe_file_read(self.dev_file.get())

            self.update_status("🔍 Validating columns...")

            if 'Field' not in df1.columns or 'Values' not in df1.columns:
                self.root.after(0, lambda: messagebox.showerror(
                    "Error",
                    f"Production file must have 'Field' and 'Values' columns.\n"
                    f"Found: {', '.join(df1.columns)}"
                ))
                self.root.after(0, self.comparison_complete)
                return

            if 'Field' not in df2.columns or 'Values' not in df2.columns:
                self.root.after(0, lambda: messagebox.showerror(
                    "Error",
                    f"Development file must have 'Field' and 'Values' columns.\n"
                    f"Found: {', '.join(df2.columns)}"
                ))
                self.root.after(0, self.comparison_complete)
                return

            self.update_status("⚙️ Processing fields...")

            fields1 = set()
            for field in df1['Field'].dropna().unique():
                if self.validate_field_name(field):
                    fields1.add(self.sanitize_string(
                        field, self.MAX_FIELD_NAME_LENGTH))

            fields2 = set()
            for field in df2['Field'].dropna().unique():
                if self.validate_field_name(field):
                    fields2.add(self.sanitize_string(
                        field, self.MAX_FIELD_NAME_LENGTH))

            if not fields1 or not fields2:
                self.root.after(0, lambda: messagebox.showerror(
                    "Error",
                    "No valid field names found in one or both files."
                ))
                self.root.after(0, self.comparison_complete)
                return

            missing_in_dev = fields1 - fields2
            missing_in_prod = fields2 - fields1
            common_fields = fields1 & fields2

            self.update_status("📋 Building value dictionaries...")

            values_prod = {}
            for field, value in zip(df1['Field'], df1['Values']):
                safe_field = self.sanitize_string(
                    field, self.MAX_FIELD_NAME_LENGTH)
                if self.validate_field_name(safe_field):
                    values_prod[safe_field] = self.sanitize_string(value)

            values_dev = {}
            for field, value in zip(df2['Field'], df2['Values']):
                safe_field = self.sanitize_string(
                    field, self.MAX_FIELD_NAME_LENGTH)
                if self.validate_field_name(safe_field):
                    values_dev[safe_field] = self.sanitize_string(value)

            # COMBINED FIELD ANALYSIS
            field_analysis = self.analyze_field_discrepancies(
                missing_in_dev, missing_in_prod, values_prod, values_dev
            )

            self.update_status("🔬 Comparing values for common fields...")

            # Compare values for COMMON fields
            value_comparisons = []
            exact_matches = 0
            similarity_scores = []

            for field in common_fields:
                prod_value = values_prod.get(field, '')
                dev_value = values_dev.get(field, '')

                prod_value = self.sanitize_string(prod_value)
                dev_value = self.sanitize_string(dev_value)

                similarity = self.calculate_similarity_safe(
                    prod_value, dev_value)
                similarity_scores.append(similarity)

                is_exact_match = (prod_value.strip() == dev_value.strip())

                if is_exact_match:
                    exact_matches += 1
                    status = "✅ EXACT MATCH"
                elif similarity >= 0.9:
                    status = "⚠️ MINOR DIFF"
                elif similarity >= 0.7:
                    status = "⚠️ MODERATE DIFF"
                else:
                    status = "❌ MAJOR DIFF"

                value_comparisons.append({
                    'field': field,
                    'prod_value': prod_value,
                    'dev_value': dev_value,
                    'similarity': similarity,
                    'status': status,
                    'exact_match': is_exact_match
                })

            total_compared = len(common_fields)

            exact_match_rate = (
                exact_matches / total_compared * 100) if total_compared > 0 else 0
            avg_similarity = (
                sum(similarity_scores) / len(similarity_scores) * 100) if similarity_scores else 0
            field_coverage_dev = (
                len(common_fields) / len(fields1) * 100) if len(fields1) > 0 else 0

            overall_accuracy = (
                field_coverage_dev * 0.3 +
                exact_match_rate * 0.4 +
                avg_similarity * 0.3
            )

            if overall_accuracy >= 95:
                grade = "A+"
                grade_desc = "Excellent"
                grade_color = self.COLORS['success']
            elif overall_accuracy >= 90:
                grade = "A"
                grade_desc = "Very Good"
                grade_color = self.COLORS['success']
            elif overall_accuracy >= 80:
                grade = "B"
                grade_desc = "Good"
                grade_color = self.COLORS['info']
            elif overall_accuracy >= 70:
                grade = "C"
                grade_desc = "Fair"
                grade_color = self.COLORS['warning']
            else:
                grade = "D"
                grade_desc = "Needs Improvement"
                grade_color = self.COLORS['error']

            self.results = {
                'common_fields': sorted(common_fields),
                'value_comparisons': value_comparisons,
                'field_analysis': field_analysis,
                'values_prod': values_prod,  # Added for table view
                'values_dev': values_dev,    # Added for table view
                'metrics': {
                    'exact_match_rate': exact_match_rate,
                    'avg_similarity': avg_similarity,
                    'overall_accuracy': overall_accuracy,
                    'field_coverage': field_coverage_dev,
                    'grade': grade,
                    'grade_description': grade_desc,
                    'grade_color': grade_color
                },
                'counts': {
                    'prod_fields': len(fields1),
                    'dev_fields': len(fields2),
                    'common_fields': len(common_fields),
                    'exact_matches': exact_matches,
                    'total_compared': total_compared,
                    'potential_renames': len(field_analysis['potential_renames']),
                    'truly_missing_dev': len(field_analysis['truly_missing_in_dev']),
                    'truly_missing_prod': len(field_analysis['truly_missing_in_prod']),
                    'suspicious_fields': len(field_analysis['suspicious_fields'])
                }
            }

            self.root.after(0, self.display_results_secure)
            self.root.after(0, lambda: self.update_status(
                "✓ Analysis complete!"))

            summary_msg = f"Comparison completed successfully!\n\n"
            summary_msg += f"Grade: {grade} ({grade_desc})\n"
            summary_msg += f"Overall Accuracy: {overall_accuracy:.1f}%\n\n"
            summary_msg += f"🔄 Potential Renames: {len(field_analysis['potential_renames'])}\n"
            summary_msg += f"❌ Truly Missing: {len(field_analysis['truly_missing_in_dev'])}\n"
            summary_msg += f"➕ New Fields: {len(field_analysis['truly_missing_in_prod'])}"

            self.root.after(0, lambda: messagebox.showinfo(
                "Success", summary_msg))

        except MemoryError:
            self.root.after(0, lambda: messagebox.showerror(
                "Memory Error",
                "File too large to process. Please use a smaller file."
            ))
        except PermissionError as e:
            self.root.after(0, lambda: messagebox.showerror(
                "Permission Error",
                f"Cannot access file: {str(e)}"
            ))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror(
                "Error",
                f"An error occurred:\n{self.sanitize_string(str(e), 200)}"
            ))
            import traceback
            traceback.print_exc()
        finally:
            self.root.after(0, self.comparison_complete)

    def comparison_complete(self):
        """Clean up after comparison"""
        self.progress.stop()
        # Re-enable all buttons with default color
        self.compare_button.config(state='normal', bg=self.BTN_DEFAULT_BG)
        self.export_button.config(state='normal', bg=self.BTN_DEFAULT_BG)
        self.clear_button.config(state='normal', bg=self.BTN_DEFAULT_BG)
        self.prod_browse_btn.config(state='normal', bg=self.BTN_DEFAULT_BG)
        self.dev_browse_btn.config(state='normal', bg=self.BTN_DEFAULT_BG)

    def populate_table_view(self):
        """Populate the treeview table with all field differences"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not self.results:
            return

        field_analysis = self.results['field_analysis']
        values_prod = self.results['values_prod']
        values_dev = self.results['values_dev']
        value_comparisons = self.results['value_comparisons']

        row_number = 0

        # 1. POTENTIAL RENAMES (with both fields and values)
        for rename in field_analysis['potential_renames']:
            row_number += 1
            prod_field = self.sanitize_string(rename['prod_field'], 50)
            dev_field = self.sanitize_string(rename['dev_field'], 50)
            prod_value = self.sanitize_string(str(rename['prod_value'])[:100])
            dev_value = self.sanitize_string(str(rename['dev_value'])[:100])

            self.tree.insert('', 'end', values=(
                '🔄 RENAME',
                prod_field,
                prod_value,
                dev_field,
                dev_value,
                'YES',
                rename['confidence'],
                f"{rename['combined_score']*100:.1f}%"
            ), tags=('rename',))

        # 2. TRULY MISSING IN DEV (only in production)
        for item in field_analysis['truly_missing_in_dev']:
            row_number += 1
            prod_field = self.sanitize_string(item['field'], 50)
            prod_value = self.sanitize_string(str(item['value'])[:100])

            self.tree.insert('', 'end', values=(
                '❌ MISSING',
                prod_field,
                prod_value,
                '(not in dev)',
                '---',
                'NO',
                'N/A',
                f"{item['best_match_score']*100:.1f}%"
            ), tags=('missing',))

        # 3. NEW FIELDS IN DEV (only in development)
        for item in field_analysis['truly_missing_in_prod']:
            row_number += 1
            dev_field = self.sanitize_string(item['field'], 50)
            dev_value = self.sanitize_string(str(item['value'])[:100])

            self.tree.insert('', 'end', values=(
                '➕ NEW',
                '(not in prod)',
                '---',
                dev_field,
                dev_value,
                'NO',
                'N/A',
                '0.0%'
            ), tags=('new',))

        # 4. COMMON FIELDS WITH VALUE DIFFERENCES
        mismatches = [vc for vc in value_comparisons if not vc['exact_match']]
        for vc in mismatches:
            row_number += 1
            field = self.sanitize_string(vc['field'], 50)
            prod_value = self.sanitize_string(str(vc['prod_value'])[:100])
            dev_value = self.sanitize_string(str(vc['dev_value'])[:100])

            self.tree.insert('', 'end', values=(
                vc['status'],
                field,
                prod_value,
                field,  # Same field name
                dev_value,
                'NO',
                'Same Field',
                f"{vc['similarity']*100:.1f}%"
            ), tags=('different',))

        # 5. EXACT MATCHES (optional - comment out if you only want differences)
        exact_matches = [vc for vc in value_comparisons if vc['exact_match']]
        for vc in exact_matches[:50]:  # Limit to first 50 to avoid clutter
            row_number += 1
            field = self.sanitize_string(vc['field'], 50)
            value = self.sanitize_string(str(vc['prod_value'])[:100])

            self.tree.insert('', 'end', values=(
                '✅ EXACT',
                field,
                value,
                field,
                value,
                'NO',
                'Same Field',
                '100.0%'
            ), tags=('exact',))

        self.update_status(f"✓ Table populated with {row_number} entries")

    def display_results_secure(self):
        """Display results with COMBINED field analysis and side-by-side table"""
        if not self.results:
            return

        self.summary_text.config(state='normal')
        self.field_analysis_text.config(state='normal')

        self.summary_text.delete(1.0, tk.END)
        self.field_analysis_text.delete(1.0, tk.END)

        metrics = self.results['metrics']
        counts = self.results['counts']
        field_analysis = self.results['field_analysis']

        # SUMMARY TAB
        summary = f"""
{'='*80}
COMPREHENSIVE FIELD AND VALUE COMPARISON SUMMARY
{'='*80}

🎯 OVERALL GRADE: {metrics['grade']} ({metrics['grade_description']}) - {metrics['overall_accuracy']:.2f}%

📊 FIELD STATISTICS:
  • Production Fields:     {counts['prod_fields']}
  • Development Fields:    {counts['dev_fields']}
  • Common Fields:         {counts['common_fields']}
  
📋 FIELD DISCREPANCY ANALYSIS:
  • Potential Renames:     {counts['potential_renames']} 🔄
  • Truly Missing in Dev:  {counts['truly_missing_dev']} ❌
  • New Fields in Dev:     {counts['truly_missing_prod']} ➕
  • Suspicious Cases:      {counts['suspicious_fields']} ⚠️

📈 VALUE COMPARISON (Common Fields):
  • Total Compared:        {counts['total_compared']}
  • Exact Matches:         {counts['exact_matches']} ({metrics['exact_match_rate']:.1f}%)
  • Value Differences:     {counts['total_compared'] - counts['exact_matches']}

🎯 ACCURACY METRICS:
  • Field Coverage:        {metrics['field_coverage']:.2f}%
  • Exact Match Rate:      {metrics['exact_match_rate']:.2f}%
  • Average Similarity:    {metrics['avg_similarity']:.2f}%
  • Overall Accuracy:      {metrics['overall_accuracy']:.2f}%

💡 TIP: Check the "Side-by-Side Field Comparison" tab for a complete table view
        of all differences, including potential renames!

⏰ Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*80}
        """
        self.summary_text.insert(1.0, summary)

        # POPULATE SIDE-BY-SIDE TABLE (NEW!)
        self.populate_table_view()

        # DETAILED FIELD ANALYSIS TAB
        field_analysis_text = f"""
{'='*80}
DETAILED FIELD ANALYSIS: MISSING FIELDS & RENAME DETECTION
{'='*80}

This analysis combines missing field detection with intelligent rename detection
based on both field name similarity and value similarity.

{'='*80}
🔄 POTENTIAL RENAMES ({len(field_analysis['potential_renames'])})
{'='*80}

Fields that appear to have been renamed based on value similarity analysis.

"""

        if field_analysis['potential_renames']:
            for i, rename in enumerate(field_analysis['potential_renames'], 1):
                confidence_emoji = {
                    "Very High": "🟢",
                    "High": "🟢",
                    "Medium": "🟡",
                    "Low": "🟠"
                }.get(rename['confidence'], "⚪")

                field_analysis_text += f"\n#{i} {confidence_emoji} Confidence: {rename['confidence']}\n"
                field_analysis_text += f"{'─'*80}\n"
                field_analysis_text += f"Production Field:  {self.sanitize_string(rename['prod_field'], 100)}\n"
                field_analysis_text += f"        ↓ (likely renamed to) ↓\n"
                field_analysis_text += f"Dev Field:         {self.sanitize_string(rename['dev_field'], 100)}\n\n"

                field_analysis_text += f"Similarity Scores:\n"
                field_analysis_text += f"  • Field Name:  {rename['field_name_similarity']*100:.1f}%\n"
                field_analysis_text += f"  • Values:      {rename['value_similarity']*100:.1f}%\n"
                field_analysis_text += f"  • Combined:    {rename['combined_score']*100:.1f}%\n\n"

                field_analysis_text += f"Value Comparison:\n"
                prod_preview = self.sanitize_string(
                    str(rename['prod_value'])[:150])
                dev_preview = self.sanitize_string(
                    str(rename['dev_value'])[:150])
                field_analysis_text += f"  Prod: {prod_preview}...\n"
                field_analysis_text += f"  Dev:  {dev_preview}...\n"
                field_analysis_text += f"\n{'='*80}\n"
        else:
            field_analysis_text += "✅ No potential renames detected.\n\n"

        field_analysis_text += f"""
{'='*80}
❌ TRULY MISSING IN DEV ({len(field_analysis['truly_missing_in_dev'])})
{'='*80}

Fields that exist in production but not in development, with no strong rename match.

"""

        if field_analysis['truly_missing_in_dev']:
            for i, item in enumerate(field_analysis['truly_missing_in_dev'], 1):
                safe_field = self.sanitize_string(item['field'], 100)
                safe_value = self.sanitize_string(str(item['value'])[:200])
                field_analysis_text += f"  {i:3}. {safe_field}\n"
                field_analysis_text += f"       Value: {safe_value}\n"
                field_analysis_text += f"       Best Match Score: {item['best_match_score']*100:.1f}%\n\n"
        else:
            field_analysis_text += "  ✅ None!\n\n"

        field_analysis_text += f"""
{'='*80}
➕ NEW FIELDS IN DEV ({len(field_analysis['truly_missing_in_prod'])})
{'='*80}

Fields that exist in development but not in production.

"""

        if field_analysis['truly_missing_in_prod']:
            for i, item in enumerate(field_analysis['truly_missing_in_prod'], 1):
                safe_field = self.sanitize_string(item['field'], 100)
                safe_value = self.sanitize_string(str(item['value'])[:200])
                field_analysis_text += f"  {i:3}. {safe_field}\n"
                field_analysis_text += f"       Value: {safe_value}\n\n"
        else:
            field_analysis_text += "  ✅ None!\n\n"

        field_analysis_text += f"""
{'='*80}
⚠️  SUSPICIOUS CASES ({len(field_analysis['suspicious_fields'])})
{'='*80}

Fields with moderate similarity - manual review recommended.

"""

        if field_analysis['suspicious_fields']:
            for i, item in enumerate(field_analysis['suspicious_fields'], 1):
                field_analysis_text += f"\n#{i} Uncertain Match\n"
                field_analysis_text += f"{'─'*80}\n"
                field_analysis_text += f"Prod Field: {self.sanitize_string(item['prod_field'], 100)}\n"
                field_analysis_text += f"Dev Field:  {self.sanitize_string(item['dev_field'], 100)}\n"
                field_analysis_text += f"Similarity: Field Name {item['field_name_similarity']*100:.1f}% | "
                field_analysis_text += f"Values {item['value_similarity']*100:.1f}%\n"
                field_analysis_text += f"Combined Score: {item['combined_score']*100:.1f}%\n\n"
        else:
            field_analysis_text += "  ✅ None!\n\n"

        self.field_analysis_text.insert(1.0, field_analysis_text)

        # Disable text widgets (read-only)
        self.summary_text.config(state='disabled')
        self.field_analysis_text.config(state='disabled')

        # Update grade display
        self.grade_label.config(
            text=f"🎯 Grade: {metrics['grade']} ({metrics['grade_description']}) - {metrics['overall_accuracy']:.1f}%",
            bg=metrics['grade_color'],
            fg='white'
        )
        self.grade_frame.config(bg=metrics['grade_color'])

        # Update metric bars
        metric_values = {
            'Field Coverage': metrics['field_coverage'],
            'Exact Match Rate': metrics['exact_match_rate'],
            'Avg Similarity': metrics['avg_similarity'],
            'Overall Accuracy': metrics['overall_accuracy']
        }

        for metric, value in metric_values.items():
            bar, label, bar_frame = self.metrics_labels[metric]

            safe_value = max(0, min(100, value))

            target_width = safe_value / 100
            bar.place(x=0, y=0, relheight=1, relwidth=target_width)

            label.config(text=f"{safe_value:.2f}%")

            if safe_value >= 90:
                bar.config(bg=self.COLORS['success'])
            elif safe_value >= 70:
                bar.config(bg=self.COLORS['warning'])
            else:
                bar.config(bg=self.COLORS['error'])

    def export_reports_secure(self):
        """Securely export reports including side-by-side comparison"""
        if not self.results:
            messagebox.showwarning(
                "Warning",
                "No comparison results to export. Please run a comparison first."
            )
            return

        try:
            directory = filedialog.askdirectory(
                title="Select output directory")
            if not directory:
                return

            dir_path = self.safe_export_path(directory)

            self.update_status("📝 Exporting reports...")

            field_analysis = self.results['field_analysis']

            # Export SIDE-BY-SIDE COMPARISON TABLE (NEW!)
            side_by_side_data = []

            # Add potential renames
            for rename in field_analysis['potential_renames']:
                side_by_side_data.append({
                    'Status': 'POTENTIAL RENAME',
                    'Production_Field': self.sanitize_csv_injection(rename['prod_field']),
                    'Production_Value': self.sanitize_csv_injection(str(rename['prod_value'])[:500]),
                    'Dev_Field': self.sanitize_csv_injection(rename['dev_field']),
                    'Dev_Value': self.sanitize_csv_injection(str(rename['dev_value'])[:500]),
                    'Potential_Rename': 'YES',
                    'Confidence': rename['confidence'],
                    'Field_Name_Similarity': f"{rename['field_name_similarity']*100:.2f}%",
                    'Value_Similarity': f"{rename['value_similarity']*100:.2f}%",
                    'Combined_Score': f"{rename['combined_score']*100:.2f}%"
                })

            # Add truly missing
            for item in field_analysis['truly_missing_in_dev']:
                side_by_side_data.append({
                    'Status': 'MISSING IN DEV',
                    'Production_Field': self.sanitize_csv_injection(item['field']),
                    'Production_Value': self.sanitize_csv_injection(str(item['value'])[:500]),
                    'Dev_Field': '(not in dev)',
                    'Dev_Value': '---',
                    'Potential_Rename': 'NO',
                    'Confidence': 'N/A',
                    'Field_Name_Similarity': '0%',
                    'Value_Similarity': '0%',
                    'Combined_Score': f"{item['best_match_score']*100:.2f}%"
                })

            # Add new fields
            for item in field_analysis['truly_missing_in_prod']:
                side_by_side_data.append({
                    'Status': 'NEW IN DEV',
                    'Production_Field': '(not in prod)',
                    'Production_Value': '---',
                    'Dev_Field': self.sanitize_csv_injection(item['field']),
                    'Dev_Value': self.sanitize_csv_injection(str(item['value'])[:500]),
                    'Potential_Rename': 'NO',
                    'Confidence': 'N/A',
                    'Field_Name_Similarity': '0%',
                    'Value_Similarity': '0%',
                    'Combined_Score': '0%'
                })

            # Add value differences for common fields
            for vc in self.results['value_comparisons']:
                if not vc['exact_match']:
                    side_by_side_data.append({
                        'Status': vc['status'],
                        'Production_Field': self.sanitize_csv_injection(vc['field']),
                        'Production_Value': self.sanitize_csv_injection(str(vc['prod_value'])[:500]),
                        'Dev_Field': self.sanitize_csv_injection(vc['field']),
                        'Dev_Value': self.sanitize_csv_injection(str(vc['dev_value'])[:500]),
                        'Potential_Rename': 'NO',
                        'Confidence': 'Same Field',
                        'Field_Name_Similarity': '100%',
                        'Value_Similarity': f"{vc['similarity']*100:.2f}%",
                        'Combined_Score': f"{vc['similarity']*100:.2f}%"
                    })

            # Create DataFrame and export
            if side_by_side_data:
                side_by_side_df = pd.DataFrame(side_by_side_data)
                side_by_side_file = self.generate_safe_filename(
                    'side_by_side_comparison', 'csv')
                side_by_side_df.to_csv(
                    str(dir_path / side_by_side_file), index=False, encoding='utf-8')

            # Export individual category files
            if field_analysis['potential_renames']:
                renames_data = []
                for rename in field_analysis['potential_renames']:
                    renames_data.append({
                        'prod_field': self.sanitize_csv_injection(rename['prod_field']),
                        'dev_field': self.sanitize_csv_injection(rename['dev_field']),
                        'field_name_similarity': rename['field_name_similarity'] * 100,
                        'value_similarity': rename['value_similarity'] * 100,
                        'combined_score': rename['combined_score'] * 100,
                        'confidence': rename['confidence'],
                        'prod_value': self.sanitize_csv_injection(str(rename['prod_value'])[:500]),
                        'dev_value': self.sanitize_csv_injection(str(rename['dev_value'])[:500])
                    })

                renames_df = pd.DataFrame(renames_data)
                renames_df = renames_df.sort_values(
                    'combined_score', ascending=False)
                renames_file = self.generate_safe_filename(
                    'potential_renames_detailed', 'csv')
                renames_df.to_csv(str(dir_path / renames_file),
                                  index=False, encoding='utf-8')

            # Export summary
            summary_file = self.generate_safe_filename('summary', 'txt')
            with open(dir_path / summary_file, 'w', encoding='utf-8') as f:
                summary_content = self.summary_text.get(1.0, tk.END)
                f.write(self.sanitize_string(summary_content))

            # Export field analysis
            field_analysis_file = self.generate_safe_filename(
                'field_analysis', 'txt')
            with open(dir_path / field_analysis_file, 'w', encoding='utf-8') as f:
                field_content = self.field_analysis_text.get(1.0, tk.END)
                f.write(self.sanitize_string(field_content))

            self.update_status("✓ Export complete!")

            files_msg = f"Reports exported to:\n{dir_path}\n\n"
            files_msg += "Files created:\n"
            files_msg += f"• {side_by_side_file} (⭐ MAIN COMPARISON TABLE)\n"
            files_msg += f"• {summary_file}\n"
            files_msg += f"• {field_analysis_file}\n"
            if field_analysis['potential_renames']:
                files_msg += f"• potential_renames_detailed_*.csv ({len(field_analysis['potential_renames'])} renames)\n"

            messagebox.showinfo("Export Successful", files_msg)

        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to export reports:\n{self.sanitize_string(str(e), 200)}"
            )

    def clear_results(self):
        """Clear results safely"""
        self.summary_text.config(state='normal')
        self.field_analysis_text.config(state='normal')

        self.summary_text.delete(1.0, tk.END)
        self.field_analysis_text.delete(1.0, tk.END)

        # Clear table
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.summary_text.config(state='disabled')
        self.field_analysis_text.config(state='disabled')

        self.grade_label.config(
            text="No comparison yet - Select files to begin",
            bg=self.COLORS['border'],
            fg=self.COLORS['text_secondary']
        )
        self.grade_frame.config(bg=self.COLORS['border'])

        for metric in self.metrics_labels:
            bar, label, bar_frame = self.metrics_labels[metric]
            bar.place(x=0, y=0, relheight=1, relwidth=0)
            label.config(text="0.00%")
            bar.config(bg=self.COLORS['accent_blue'])

        self.results = None
        self.status_label.config(text="✓ Ready - All systems operational")

        messagebox.showinfo("Success", "Results cleared successfully!")


def main():
    root = tk.Tk()
    app = SecureFieldComparisonGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
