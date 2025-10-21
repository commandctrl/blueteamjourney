import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import subprocess
import os
import sys
import threading
import shutil
import re
from datetime import datetime

class VolatilityGUI:
    def __init__(self, master):
        self.master = master
        master.title("Volatility 3 GUI Analyzer")
        master.geometry("900x850")

        # --- Variables ---
        self.vmem_file_path = tk.StringVar()
        self.companion_file_path = tk.StringVar()
        
        if sys.platform == "win32":
            self.volatility_exe_path = tk.StringVar(value="volatility3.exe")
        else:
            self.volatility_exe_path = tk.StringVar(value="volatility3")
            
        self.selected_plugin = tk.StringVar()
        self.custom_args = tk.StringVar()
        self.detected_os = tk.StringVar(value="Unknown")
        self.auto_export = tk.BooleanVar(value=True)  # Auto-export results when running all

        # Define plugins by OS
        self.all_plugins = {
            "windows": [
                "windows.info",
                "windows.pslist",
                "windows.pstree",
                "windows.psscan",
                "windows.dlllist",
                "windows.handles",
                "windows.cmdline",
                "windows.netscan",
                "windows.netstat",
                "windows.filescan",
                "windows.registry.hivelist",
                "windows.registry.printkey",
                "windows.registry.userassist",
                "windows.hashdump",
                "windows.cachedump",
                "windows.lsadump",
                "windows.malfind",
                "windows.svcscan",
                "windows.driverscan",
                "windows.modscan",
                "windows.callbacks",
                "windows.ssdt",
                "windows.vadinfo",
                "windows.modules",
                "windows.envars",
                "windows.privs",
                "windows.sessions",
            ],
            "linux": [
                "linux.bash",
                "linux.check_afinfo",
                "linux.check_creds",
                "linux.check_syscall",
                "linux.elfs",
                "linux.lsmod",
                "linux.lsof",
                "linux.malfind",
                "linux.mountinfo",
                "linux.pslist",
                "linux.pstree",
                "linux.sockstat",
            ],
            "mac": [
                "mac.bash",
                "mac.check_syscall",
                "mac.ifconfig",
                "mac.lsmod",
                "mac.lsof",
                "mac.malfind",
                "mac.mount",
                "mac.netstat",
                "mac.psaux",
                "mac.pslist",
                "mac.pstree",
            ],
            "general": [
                "banners.Banners",
                "frameworkinfo.FrameworkInfo",
                "isfinfo.IsfInfo",
            ]
        }
        
        self.plugins = self.all_plugins["general"].copy()
        
        # Variables for "Run All" functionality
        self.running_all = False
        self.all_results = {}
        self.current_plugin_index = 0
        self.plugins_to_run = []
        self.output_directory = ""

        # --- GUI Elements ---

        # Frame for File/Executable Paths
        path_frame = tk.LabelFrame(master, text="Configuration", padx=10, pady=10)
        path_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(path_frame, text="Memory Dump File:").grid(row=0, column=0, sticky="w", pady=2)
        tk.Entry(path_frame, textvariable=self.vmem_file_path, width=70).grid(row=0, column=1, padx=5, pady=2)
        tk.Button(path_frame, text="Browse", command=self.browse_memory_dump_file).grid(row=0, column=2, padx=5, pady=2)

        tk.Label(path_frame, text="Companion Metadata File:").grid(row=1, column=0, sticky="w", pady=2)
        tk.Entry(path_frame, textvariable=self.companion_file_path, width=70).grid(row=1, column=1, padx=5, pady=2)
        tk.Button(path_frame, text="Browse", command=self.browse_companion_file).grid(row=1, column=2, padx=5, pady=2)
        tk.Label(path_frame, text="(Optional: .vmss, .vmsn, etc.)", font=("Arial", 9, "italic"), fg="gray").grid(row=1, column=3, sticky="w", padx=5, pady=2)

        tk.Label(path_frame, text="Volatility 3 Executable:").grid(row=2, column=0, sticky="w", pady=2)
        tk.Entry(path_frame, textvariable=self.volatility_exe_path, width=70).grid(row=2, column=1, padx=5, pady=2)
        tk.Button(path_frame, text="Browse", command=self.browse_volatility_exe).grid(row=2, column=2, padx=5, pady=2)

        # OS Detection Frame
        os_frame = tk.LabelFrame(master, text="Operating System Detection", padx=10, pady=10)
        os_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(os_frame, text="Detected OS:").grid(row=0, column=0, sticky="w", pady=2)
        self.os_label = tk.Label(os_frame, textvariable=self.detected_os, font=("Arial", 10, "bold"), fg="blue")
        self.os_label.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        tk.Button(os_frame, text="Detect OS", command=self.detect_os_thread, bg="orange", fg="black").grid(row=0, column=2, padx=5, pady=2)

        # Frame for Plugin and Arguments
        plugin_frame = tk.LabelFrame(master, text="Volatility Command", padx=10, pady=10)
        plugin_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(plugin_frame, text="Select Plugin:").grid(row=0, column=0, sticky="w", pady=2)
        
        if self.plugins:
            self.selected_plugin.set(self.plugins[0])
        
        self.plugin_combobox = tk.OptionMenu(plugin_frame, self.selected_plugin, *self.plugins)
        self.plugin_combobox.config(width=60)
        self.plugin_combobox.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        tk.Label(plugin_frame, text="Custom Arguments:").grid(row=1, column=0, sticky="w", pady=2)
        tk.Entry(plugin_frame, textvariable=self.custom_args, width=70).grid(row=1, column=1, padx=5, pady=2)
        tk.Label(plugin_frame, text="(e.g., --output-format csv)").grid(row=1, column=2, sticky="w", padx=5, pady=2)

        # Frame for Actions
        action_frame = tk.Frame(master, padx=10, pady=10)
        action_frame.pack(pady=5, padx=10, fill="x")

        self.run_button = tk.Button(action_frame, text="Run Selected Plugin", command=self.start_volatility_thread, bg="lightblue", fg="black")
        self.run_button.pack(side="left", padx=5)
        
        self.run_all_button = tk.Button(action_frame, text="🚀 Run All Compatible Plugins", command=self.run_all_plugins, bg="gold", fg="black", font=("Arial", 10, "bold"))
        self.run_all_button.pack(side="left", padx=5)
        
        self.export_button = tk.Button(action_frame, text="Export Output", command=self.export_output, bg="lightgreen", fg="black")
        self.export_button.pack(side="left", padx=5)
        
        self.clear_button = tk.Button(action_frame, text="Clear Output", command=self.clear_output, bg="lightcoral", fg="black")
        self.clear_button.pack(side="right", padx=5)

        # Output Area
        self.output_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=100, height=15, font=("Consolas", 9))
        self.output_text.pack(pady=10, padx=10, fill="both", expand=True)

        # Status Bar and Progress Bar
        status_bar_frame = tk.Frame(master, bd=1, relief=tk.SUNKEN)
        status_bar_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_bar = tk.Label(status_bar_frame, text="Ready - Please detect OS after selecting memory dump", anchor=tk.W, font=("Arial", 9))
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress_bar = ttk.Progressbar(status_bar_frame, mode='determinate', length=200)
        
        # Internal variables
        self.volatility_thread = None
        self.volatility_result = None

    def browse_memory_dump_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Memory Dump File",
            filetypes=[
                ("VMware VMEM files", "*.vmem"),
                ("Raw Memory Dumps", "*.raw *.bin"),
                ("Windows Crash Dumps", "*.dmp"),
                ("Windows Hibernation Files", "hiberfil.sys"),
                ("VirtualBox Core Dumps", "*.bin *.core"),
                ("All Supported Memory Dumps", "*.vmem *.raw *.bin *.dmp *.core"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.vmem_file_path.set(file_path)
            self.status_bar.config(text=f"Selected: {os.path.basename(file_path)} - Click 'Detect OS'")
            self.auto_detect_companion_file(file_path)
            self.detected_os.set("Unknown - Click 'Detect OS'")
            self.os_label.config(fg="orange")

    def browse_companion_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Companion Metadata File (Optional)",
            filetypes=[
                ("VMware Suspend State", "*.vmss"),
                ("VMware Snapshot", "*.vmsn"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.companion_file_path.set(file_path)
            self.status_bar.config(text=f"Selected Companion: {os.path.basename(file_path)}")

    def auto_detect_companion_file(self, memory_dump_path):
        base_name = os.path.splitext(memory_dump_path)[0]
        companion_extensions = ['.vmss', '.vmsn']
        
        for ext in companion_extensions:
            potential_companion = base_name + ext
            if os.path.exists(potential_companion):
                self.companion_file_path.set(potential_companion)
                return
        
        self.companion_file_path.set("")

    def browse_volatility_exe(self):
        file_path = filedialog.askopenfilename(
            title="Select volatility3 executable",
            filetypes=[
                ("Python Scripts", "*.py"),
                ("Executable files", "*.exe"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.volatility_exe_path.set(file_path)
            self.status_bar.config(text=f"Selected Volatility: {os.path.basename(file_path)}")

    def detect_os_thread(self):
        memory_dump_file = self.vmem_file_path.get()
        vol_exe = self.volatility_exe_path.get()

        if not memory_dump_file:
            messagebox.showwarning("Input Error", "Please select a memory dump file first.")
            return
        if not os.path.exists(memory_dump_file):
            messagebox.showwarning("File Error", "The selected memory dump file does not exist.")
            return
        if not vol_exe:
            messagebox.showwarning("Input Error", "Please specify the Volatility 3 executable path.")
            return

        self.detected_os.set("Detecting...")
        self.os_label.config(fg="orange")
        self.status_bar.config(text="Detecting operating system...")
        
        self.progress_bar.pack(side=tk.RIGHT, padx=5)
        self.progress_bar.config(mode='indeterminate')
        self.progress_bar.start(10)

        thread = threading.Thread(target=self._detect_os)
        thread.daemon = True
        thread.start()
        
        self.master.after(100, lambda: self.check_detection_thread(thread))

    def _detect_os(self):
        memory_dump_file = self.vmem_file_path.get()
        vol_exe = self.volatility_exe_path.get()
        
        self.prepare_companion_file(memory_dump_file)
        
        command = []
        if vol_exe.endswith(".py"):
            command = [sys.executable, vol_exe, "-f", memory_dump_file, "banners.Banners"]
        else:
            command = [vol_exe, "-f", memory_dump_file, "banners.Banners"]

        try:
            process = subprocess.run(command, capture_output=True, text=True, check=False, shell=False, timeout=60)
            
            output = process.stdout + process.stderr
            
            if "windows" in output.lower() or "nt kernel" in output.lower():
                detected = "Windows"
            elif "linux" in output.lower() or "vmlinux" in output.lower():
                detected = "Linux"
            elif "darwin" in output.lower() or "macos" in output.lower() or "osx" in output.lower():
                detected = "Mac"
            else:
                detected = "Unknown"
            
            self.volatility_result = {
                "detected_os": detected,
                "output": output
            }
            
        except subprocess.TimeoutExpired:
            self.volatility_result = {
                "detected_os": "Error",
                "output": "Detection timed out"
            }
        except Exception as e:
            self.volatility_result = {
                "detected_os": "Error",
                "output": str(e)
            }

    def check_detection_thread(self, thread):
        if thread.is_alive():
            self.master.after(100, lambda: self.check_detection_thread(thread))
        else:
            self.process_detection_result()

    def process_detection_result(self):
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        
        detected = self.volatility_result.get("detected_os", "Unknown")
        self.detected_os.set(detected)
        
        if detected in ["Windows", "Linux", "Mac"]:
            self.os_label.config(fg="green")
            self.update_plugin_list(detected.lower())
            self.status_bar.config(text=f"✓ OS detected: {detected} - Ready to run plugins")
        elif detected == "Error":
            self.os_label.config(fg="red")
            self.status_bar.config(text="Error detecting OS")
            messagebox.showerror("Detection Error", "Could not detect OS. Check Volatility configuration.")
        else:
            self.os_label.config(fg="red")
            self.status_bar.config(text="OS detection failed")
            messagebox.showwarning("Unknown OS", "Could not determine the operating system.")

    def update_plugin_list(self, os_type):
        """Update the plugin dropdown based on detected OS"""
        self.plugins = self.all_plugins["general"].copy()
        
        if os_type in self.all_plugins:
            self.plugins.extend(self.all_plugins[os_type])
        
        self.plugins.sort()
        
        # Rebuild the OptionMenu
        menu = self.plugin_combobox["menu"]
        menu.delete(0, "end")
        
        for plugin in self.plugins:
            menu.add_command(label=plugin, command=lambda value=plugin: self.selected_plugin.set(value))
        
        if self.plugins:
            self.selected_plugin.set(self.plugins[0])

    def prepare_companion_file(self, memory_dump_file):
        companion_file = self.companion_file_path.get()
        
        if not companion_file or not os.path.exists(companion_file):
            return None
        
        dump_dir = os.path.dirname(memory_dump_file)
        dump_base = os.path.splitext(os.path.basename(memory_dump_file))[0]
        companion_ext = os.path.splitext(companion_file)[1]
        expected_companion_path = os.path.join(dump_dir, dump_base + companion_ext)
        
        if os.path.abspath(companion_file) == os.path.abspath(expected_companion_path):
            return companion_file
        
        try:
            shutil.copy2(companion_file, expected_companion_path)
            return expected_companion_path
        except Exception:
            return None

    def run_all_plugins(self):
        """Run all compatible plugins sequentially"""
        memory_dump_file = self.vmem_file_path.get()
        vol_exe = self.volatility_exe_path.get()
        detected = self.detected_os.get()

        if not memory_dump_file:
            messagebox.showwarning("Input Error", "Please select a memory dump file.")
            return
        if not os.path.exists(memory_dump_file):
            messagebox.showwarning("File Error", "The selected memory dump file does not exist.")
            return
        if not vol_exe:
            messagebox.showwarning("Input Error", "Please specify the Volatility 3 executable path.")
            return
        
        if detected == "Unknown":
            response = messagebox.askyesno("OS Not Detected", 
                "Operating system has not been detected yet.\n\n"
                "Would you like to detect it now?")
            if response:
                self.detect_os_thread()
                return
            else:
                return
        
        # Ask user where to save results
        output_dir = filedialog.askdirectory(title="Select Output Directory for Results")
        if not output_dir:
            return
        
        # Create a subdirectory with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dump_name = os.path.splitext(os.path.basename(memory_dump_file))[0]
        self.output_directory = os.path.join(output_dir, f"{dump_name}_analysis_{timestamp}")
        os.makedirs(self.output_directory, exist_ok=True)
        
        # Prepare list of plugins to run
        os_type = detected.lower()
        self.plugins_to_run = self.all_plugins["general"].copy()
        if os_type in self.all_plugins:
            self.plugins_to_run.extend(self.all_plugins[os_type])
        
        self.all_results = {}
        self.current_plugin_index = 0
        self.running_all = True
        
        # Disable buttons
        self.run_button.config(state=tk.DISABLED)
        self.run_all_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.DISABLED)
        
        # Clear output
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"=== Running All Compatible Plugins ===\n")
        self.output_text.insert(tk.END, f"Total plugins: {len(self.plugins_to_run)}\n")
        self.output_text.insert(tk.END, f"Output directory: {self.output_directory}\n\n")
        
        # Setup progress bar
        self.progress_bar.pack(side=tk.RIGHT, padx=5)
        self.progress_bar.config(mode='determinate', maximum=len(self.plugins_to_run))
        self.progress_bar['value'] = 0
        
        # Start running plugins
        self.run_next_plugin()

    def run_next_plugin(self):
        """Run the next plugin in the queue"""
        if self.current_plugin_index >= len(self.plugins_to_run):
            # All plugins completed
            self.finish_run_all()
            return
        
        plugin = self.plugins_to_run[self.current_plugin_index]
        self.status_bar.config(text=f"Running plugin {self.current_plugin_index + 1}/{len(self.plugins_to_run)}: {plugin}")
        self.output_text.insert(tk.END, f"[{self.current_plugin_index + 1}/{len(self.plugins_to_run)}] Running {plugin}...\n")
        self.output_text.see(tk.END)
        
        # Start thread for this plugin
        thread = threading.Thread(target=self._run_single_plugin, args=(plugin,))
        thread.daemon = True
        thread.start()
        
        self.master.after(100, lambda: self.check_single_plugin_thread(thread, plugin))

    def _run_single_plugin(self, plugin):
        """Run a single plugin and store results"""
        memory_dump_file = self.vmem_file_path.get()
        vol_exe = self.volatility_exe_path.get()
        
        self.prepare_companion_file(memory_dump_file)
        
        command = []
        if vol_exe.endswith(".py"):
            command = [sys.executable, vol_exe, "-f", memory_dump_file, plugin]
        else:
            command = [vol_exe, "-f", memory_dump_file, plugin]

        try:
            process = subprocess.run(command, capture_output=True, text=True, check=False, shell=False, timeout=300)
            
            self.volatility_result = {
                "plugin": plugin,
                "stdout": process.stdout,
                "stderr": process.stderr,
                "returncode": process.returncode,
                "error": None
            }
            
        except subprocess.TimeoutExpired:
            self.volatility_result = {
                "plugin": plugin,
                "stdout": "",
                "stderr": "Plugin timed out after 5 minutes",
                "returncode": -1,
                "error": "Timeout"
            }
        except Exception as e:
            self.volatility_result = {
                "plugin": plugin,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "error": str(e)
            }

    def check_single_plugin_thread(self, thread, plugin):
        if thread.is_alive():
            self.master.after(100, lambda: self.check_single_plugin_thread(thread, plugin))
        else:
            self.process_single_plugin_result(plugin)

    def process_single_plugin_result(self, plugin):
        """Process the result of a single plugin and save it"""
        result = self.volatility_result
        returncode = result.get("returncode", -1)
        
        # Save result to file
        safe_plugin_name = plugin.replace(".", "_")
        output_file = os.path.join(self.output_directory, f"{safe_plugin_name}.txt")
        
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"Plugin: {plugin}\n")
                f.write(f"Return Code: {returncode}\n")
                f.write("=" * 80 + "\n\n")
                
                if returncode == 0:
                    f.write(result.get("stdout", ""))
                else:
                    f.write("STDERR:\n")
                    f.write(result.get("stderr", ""))
            
            if returncode == 0:
                self.output_text.insert(tk.END, f"    ✓ Success - Saved to {safe_plugin_name}.txt\n")
            else:
                self.output_text.insert(tk.END, f"    ✗ Failed - Error saved to {safe_plugin_name}.txt\n")
                
        except Exception as e:
            self.output_text.insert(tk.END, f"    ✗ Error saving output: {e}\n")
        
        self.output_text.see(tk.END)
        
        # Store result
        self.all_results[plugin] = result
        
        # Update progress
        self.current_plugin_index += 1
        self.progress_bar['value'] = self.current_plugin_index
        
        # Run next plugin
        self.run_next_plugin()

    def finish_run_all(self):
        """Finish the run all process"""
        self.running_all = False
        
        # Create summary file
        summary_file = os.path.join(self.output_directory, "_SUMMARY.txt")
        successful = sum(1 for r in self.all_results.values() if r.get("returncode") == 0)
        failed = len(self.all_results) - successful
        
        try:
            with open(summary_file, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("VOLATILITY 3 ANALYSIS SUMMARY\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Memory Dump: {self.vmem_file_path.get()}\n")
                f.write(f"Detected OS: {self.detected_os.get()}\n")
                f.write(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Output Directory: {self.output_directory}\n\n")
                f.write(f"Total Plugins Run: {len(self.all_results)}\n")
                f.write(f"Successful: {successful}\n")
                f.write(f"Failed: {failed}\n\n")
                f.write("=" * 80 + "\n")
                f.write("PLUGIN RESULTS:\n")
                f.write("=" * 80 + "\n\n")
                
                for plugin, result in sorted(self.all_results.items()):
                    status = "✓ SUCCESS" if result.get("returncode") == 0 else "✗ FAILED"
                    f.write(f"{status:12} {plugin}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"\nError creating summary: {e}\n")
        
        # Update UI
        self.output_text.insert(tk.END, f"\n{'=' * 80}\n")
        self.output_text.insert(tk.END, f"Analysis Complete!\n")
        self.output_text.insert(tk.END, f"Successful: {successful}/{len(self.all_results)}\n")
        self.output_text.insert(tk.END, f"Failed: {failed}/{len(self.all_results)}\n")
        self.output_text.insert(tk.END, f"Results saved to: {self.output_directory}\n")
        self.output_text.insert(tk.END, f"{'=' * 80}\n")
        self.output_text.see(tk.END)
        
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        
        # Re-enable buttons
        self.run_button.config(state=tk.NORMAL)
        self.run_all_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.NORMAL)
        
        self.status_bar.config(text=f"✓ Analysis complete - {successful}/{len(self.all_results)} plugins successful")
        
        # Ask if user wants to open the output directory
        response = messagebox.askyesno("Analysis Complete", 
            f"Analysis complete!\n\n"
            f"Successful: {successful}/{len(self.all_results)}\n"
            f"Failed: {failed}/{len(self.all_results)}\n\n"
            f"Would you like to open the output directory?")
        
        if response:
            if sys.platform == "win32":
                os.startfile(self.output_directory)
            elif sys.platform == "darwin":
                subprocess.run(["open", self.output_directory])
            else:
                subprocess.run(["xdg-open", self.output_directory])

    def start_volatility_thread(self):
        """Run a single selected plugin"""
        memory_dump_file = self.vmem_file_path.get()
        vol_exe = self.volatility_exe_path.get()

        if not memory_dump_file:
            messagebox.showwarning("Input Error", "Please select a memory dump file.")
            return
        if not os.path.exists(memory_dump_file):
            messagebox.showwarning("File Error", "The selected memory dump file does not exist.")
            return
        if not vol_exe:
            messagebox.showwarning("Input Error", "Please specify the Volatility 3 executable path.")
            return
        
        if self.detected_os.get() == "Unknown":
            response = messagebox.askyesno("OS Not Detected", 
                "Operating system has not been detected yet. This may cause plugin errors.\n\n"
                "Do you want to continue anyway?")
            if not response:
                return
        
        self.output_text.delete(1.0, tk.END)
        self.status_bar.config(text="Running Volatility... Please wait.")
        self.run_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.DISABLED)

        self.progress_bar.pack(side=tk.RIGHT, padx=5)
        self.progress_bar.config(mode='indeterminate')
        self.progress_bar.start(10)

        self.volatility_thread = threading.Thread(target=self._run_volatility_command)
        self.volatility_thread.daemon = True
        self.volatility_thread.start()
        
        self.master.after(100, self.check_volatility_thread)

    def _run_volatility_command(self):
        memory_dump_file = self.vmem_file_path.get()
        vol_exe = self.volatility_exe_path.get()
        plugin = self.selected_plugin.get()
        args = self.custom_args.get().strip()

        companion_result = self.prepare_companion_file(memory_dump_file)
        
        command = []
        if vol_exe.endswith(".py"):
            command = [sys.executable, vol_exe, "-f", memory_dump_file, plugin]
        else:
            command = [vol_exe, "-f", memory_dump_file, plugin]

        if args:
            command.extend(args.split())

        try:
            process = subprocess.run(command, capture_output=True, text=True, check=False, shell=False)
            self.volatility_result = {
                "stdout": process.stdout,
                "stderr": process.stderr,
                "returncode": process.returncode,
                "command": ' '.join(command),
                "error": None,
                "companion_used": companion_result is not None
            }
        except FileNotFoundError:
            self.volatility_result = {
                "error": f"Volatility 3 executable not found at '{vol_exe}'."
            }
        except Exception as e:
            self.volatility_result = {
                "error": f"An unexpected error occurred: {e}"
            }

    def check_volatility_thread(self):
        if self.volatility_thread.is_alive():
            self.master.after(100, self.check_volatility_thread)
        else:
            self.process_volatility_output()

    def process_volatility_output(self):
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.run_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.NORMAL)

        if self.volatility_result.get("error"):
            messagebox.showerror("Error", self.volatility_result["error"])
            self.status_bar.config(text="Error during execution.")
            self.output_text.insert(tk.END, f"Error: {self.volatility_result['error']}\n")
            return

        command_executed = self.volatility_result["command"]
        stdout = self.volatility_result["stdout"]
        stderr = self.volatility_result["stderr"]
        returncode = self.volatility_result["returncode"]
        companion_used = self.volatility_result.get("companion_used", False)

        if companion_used:
            self.output_text.insert(tk.END, "✓ Companion metadata file was used\n\n")
        
        self.output_text.insert(tk.END, f"Command: {command_executed}\n\n")

        if returncode == 0:
            self.output_text.insert(tk.END, stdout)
            self.status_bar.config(text="Command completed successfully.")
        else:
            self.output_text.insert(tk.END, f"Error:\n{stderr}\n")
            self.status_bar.config(text="Command failed.")
            messagebox.showerror("Volatility Error", f"Command failed. Error Code: {returncode}")

    def export_output(self):
        output_content = self.output_text.get(1.0, tk.END)
        if not output_content.strip():
            messagebox.showinfo("Export Info", "No output to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ],
            title="Save Volatility Output"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(output_content)
                self.status_bar.config(text=f"Exported to {os.path.basename(file_path)}")
                messagebox.showinfo("Export Success", f"Output saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save: {e}")

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)
        self.status_bar.config(text="Output cleared.")

def main():
    root = tk.Tk()
    app = VolatilityGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
