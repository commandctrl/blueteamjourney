import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import subprocess
import os
import sys
import threading
import shutil # For file copying

class VolatilityGUI:
    def __init__(self, master):
        self.master = master
        master.title("Volatility 3 GUI Analyzer")
        master.geometry("900x800") # Increased height for new elements

        # --- Variables ---
        self.vmem_file_path = tk.StringVar()
        self.companion_file_path = tk.StringVar() # New variable for companion files
        
        if sys.platform == "win32":
            self.volatility_exe_path = tk.StringVar(value="volatility3.exe")
        else:
            self.volatility_exe_path = tk.StringVar(value="volatility3")
            
        self.selected_plugin = tk.StringVar()
        self.custom_args = tk.StringVar()

        # --- Comprehensive Volatility 3 Plugins List ---
        self.plugins = [
            # General / Framework Info (use specific ones instead of generic "info")
            "frameworkinfo.FrameworkInfo",  # General framework information
            "isfinfo.IsfInfo",              # ISF (Intermediate Symbol Format) information
            
            # Windows Plugins
            "windows.info.Info",            # Windows system information (replaces "windows.info")
            "windows.pslist.PsList",
            "windows.pstree.PsTree",
            "windows.psscan.PsScan",
            "windows.dlllist.DllList",
            "windows.handles.Handles",
            "windows.mutantscan.MutantScan",
            "windows.netscan.NetScan",
            "windows.netstat.NetStat",
            "windows.cmdline.CmdLine",
            "windows.cmdscan.CmdScan",
            "windows.consoles.Consoles",
            "windows.registry.hivelist.HiveList",
            "windows.registry.hivescan.HiveScan",
            "windows.registry.printkey.PrintKey",
            "windows.registry.userassist.UserAssist",
            "windows.hashdump.Hashdump",
            "windows.cachedump.Cachedump",
            "windows.lsadump.Lsadump",
            "windows.svcscan.SvcScan",
            "windows.driverscan.DriverScan",
            "windows.modscan.ModScan",
            "windows.ssdt.SSDT",
            "windows.callbacks.Callbacks",
            "windows.driverirp.DriverIrp",
            "windows.drivermodnamescan.DriverModNameScan",
            "windows.filescan.FileScan",
            "windows.malfind.Malfind",
            "windows.vadinfo.VadInfo",
            "windows.memmap.Memmap",
            "windows.modules.Modules",
            "windows.poolscanner.PoolScanner",
            "windows.statistics.Statistics",
            "windows.symlinkscan.SymlinkScan",
            "windows.virtmap.VirtMap",
            "windows.crashinfo.Crashinfo",
            "windows.verinfo.VerInfo",
            "windows.mbrscan.MBRScan",
            "windows.mftscan.MFTScan",
            "windows.bigpools.BigPools",
            "windows.envars.Envars",
            "windows.getservicesids.GetServiceSIDs",
            "windows.getsids.GetSIDs",
            "windows.privileges.Privs",
            "windows.sessions.Sessions",
            "windows.skeleton_key_check.Skeleton_Key_Check",
            "windows.strings.Strings",
            "windows.vadyarascan.VadYaraScan",

            # Linux Plugins
            "linux.bash.Bash",
            "linux.check_afinfo.Check_afinfo",
            "linux.check_creds.Check_creds",
            "linux.check_idt.Check_idt",
            "linux.check_modules.Check_modules",
            "linux.check_syscall.Check_syscall",
            "linux.elfs.Elfs",
            "linux.keyboard_notifiers.Keyboard_notifiers",
            "linux.lsmod.Lsmod",
            "linux.lsof.Lsof",
            "linux.malfind.Malfind",
            "linux.mountinfo.MountInfo",
            "linux.proc.Maps",
            "linux.pslist.PsList",
            "linux.pstree.PsTree",
            "linux.sockstat.Sockstat",
            "linux.tty_check.tty_check",

            # MacOS Plugins
            "mac.bash.Bash",
            "mac.check_syscall.Check_syscall",
            "mac.check_sysctl.Check_sysctl",
            "mac.check_trap_table.Check_trap_table",
            "mac.ifconfig.Ifconfig",
            "mac.kauth_listeners.Kauth_listeners",
            "mac.kauth_scopes.Kauth_scopes",
            "mac.kevents.Kevents",
            "mac.list_files.List_Files",
            "mac.lsmod.Lsmod",
            "mac.lsof.Lsof",
            "mac.malfind.Malfind",
            "mac.mount.Mount",
            "mac.netstat.Netstat",
            "mac.proc_maps.Maps",
            "mac.psaux.Psaux",
            "mac.pslist.PsList",
            "mac.pstree.PsTree",
            "mac.socket_filters.Socket_filters",
            "mac.timers.Timers",
            "mac.trustedbsd.Trustedbsd",
            "mac.vfsevents.VFSevents",
        ]
        self.plugins.sort()
        if self.plugins:
            self.selected_plugin.set(self.plugins[0])
        else:
            self.selected_plugin.set("No plugins found")


        # --- GUI Elements ---

        # Frame for File/Executable Paths
        path_frame = tk.LabelFrame(master, text="Configuration", padx=10, pady=10)
        path_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(path_frame, text="Memory Dump File:").grid(row=0, column=0, sticky="w", pady=2)
        tk.Entry(path_frame, textvariable=self.vmem_file_path, width=70).grid(row=0, column=1, padx=5, pady=2)
        tk.Button(path_frame, text="Browse", command=self.browse_memory_dump_file).grid(row=0, column=2, padx=5, pady=2)

        # New row for companion file
        tk.Label(path_frame, text="Companion Metadata File:").grid(row=1, column=0, sticky="w", pady=2)
        tk.Entry(path_frame, textvariable=self.companion_file_path, width=70).grid(row=1, column=1, padx=5, pady=2)
        tk.Button(path_frame, text="Browse", command=self.browse_companion_file).grid(row=1, column=2, padx=5, pady=2)
        tk.Label(path_frame, text="(Optional: .vmss, .vmsn, etc.)", font=("Arial", 9, "italic"), fg="gray").grid(row=1, column=3, sticky="w", padx=5, pady=2)

        tk.Label(path_frame, text="Volatility 3 Executable:").grid(row=2, column=0, sticky="w", pady=2)
        tk.Entry(path_frame, textvariable=self.volatility_exe_path, width=70).grid(row=2, column=1, padx=5, pady=2)
        tk.Button(path_frame, text="Browse", command=self.browse_volatility_exe).grid(row=2, column=2, padx=5, pady=2)

        # Frame for Plugin and Arguments
        plugin_frame = tk.LabelFrame(master, text="Volatility Command", padx=10, pady=10)
        plugin_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(plugin_frame, text="Select Plugin:").grid(row=0, column=0, sticky="w", pady=2)
        self.plugin_combobox = tk.OptionMenu(plugin_frame, self.selected_plugin, *self.plugins)
        self.plugin_combobox.config(width=60)
        self.plugin_combobox.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        tk.Label(plugin_frame, text="Custom Arguments:").grid(row=1, column=0, sticky="w", pady=2)
        tk.Entry(plugin_frame, textvariable=self.custom_args, width=70).grid(row=1, column=1, padx=5, pady=2)
        tk.Label(plugin_frame, text="(e.g., -o output.txt --pid 1234 --output-format csv)").grid(row=1, column=2, sticky="w", padx=5, pady=2)


        # Frame for Actions
        action_frame = tk.Frame(master, padx=10, pady=10)
        action_frame.pack(pady=5, padx=10, fill="x")

        self.run_button = tk.Button(action_frame, text="Run Volatility", command=self.start_volatility_thread, bg="lightblue", fg="black")
        self.run_button.pack(side="left", padx=5)
        
        self.export_button = tk.Button(action_frame, text="Export Output", command=self.export_output, bg="lightgreen", fg="black")
        self.export_button.pack(side="left", padx=5)
        
        self.clear_button = tk.Button(action_frame, text="Clear Output", command=self.clear_output, bg="lightcoral", fg="black")
        self.clear_button.pack(side="right", padx=5)

        # Output Area
        self.output_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=100, height=22, font=("Consolas", 10))
        self.output_text.pack(pady=10, padx=10, fill="both", expand=True)

        # Status Bar and Progress Bar
        status_bar_frame = tk.Frame(master, bd=1, relief=tk.SUNKEN)
        status_bar_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_bar = tk.Label(status_bar_frame, text="Ready", anchor=tk.W)
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress_bar = ttk.Progressbar(status_bar_frame, mode='indeterminate', length=200)
        
        # Internal variables for thread communication
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
            self.status_bar.config(text=f"Selected Dump: {os.path.basename(file_path)}")
            
            # Automatically look for companion files in the same directory
            self.auto_detect_companion_file(file_path)

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
        """Automatically detect and set companion file if it exists in the same directory"""
        base_name = os.path.splitext(memory_dump_path)[0]  # Remove extension
        directory = os.path.dirname(memory_dump_path)
        
        # Common companion file extensions
        companion_extensions = ['.vmss', '.vmsn']
        
        for ext in companion_extensions:
            potential_companion = base_name + ext
            if os.path.exists(potential_companion):
                self.companion_file_path.set(potential_companion)
                self.status_bar.config(text=f"Auto-detected companion file: {os.path.basename(potential_companion)}")
                return
        
        # If no companion file found, clear the field
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
            self.status_bar.config(text=f"Selected Volatility Executable: {os.path.basename(file_path)}")

    def prepare_companion_file(self, memory_dump_file):
        """
        Ensure companion file is in the same directory as the memory dump file
        with the same base name. Volatility expects this naming convention.
        Returns the path to the companion file if successfully prepared, or None.
        """
        companion_file = self.companion_file_path.get()
        
        if not companion_file or not os.path.exists(companion_file):
            return None
        
        # Get the base name of the memory dump (without extension)
        dump_dir = os.path.dirname(memory_dump_file)
        dump_base = os.path.splitext(os.path.basename(memory_dump_file))[0]
        
        # Get the extension of the companion file
        companion_ext = os.path.splitext(companion_file)[1]
        
        # Expected companion file path (same directory, same base name as dump)
        expected_companion_path = os.path.join(dump_dir, dump_base + companion_ext)
        
        # If companion file is already in the correct location, we're done
        if os.path.abspath(companion_file) == os.path.abspath(expected_companion_path):
            return companion_file
        
        # Otherwise, we need to copy it to the correct location
        try:
            shutil.copy2(companion_file, expected_companion_path)
            self.output_text.insert(tk.END, f"Copied companion file to: {expected_companion_path}\n\n")
            return expected_companion_path
        except Exception as e:
            self.output_text.insert(tk.END, f"Warning: Could not copy companion file: {e}\n")
            self.output_text.insert(tk.END, "Proceeding without companion file...\n\n")
            return None

    def start_volatility_thread(self):
        # Input validation
        memory_dump_file = self.vmem_file_path.get()
        vol_exe = self.volatility_exe_path.get()

        if not memory_dump_file:
            messagebox.showwarning("Input Error", "Please select a memory dump file.")
            return
        if not os.path.exists(memory_dump_file):
            messagebox.showwarning("File Error", f"The selected memory dump file does not exist: {memory_dump_file}")
            return
        if not vol_exe:
            messagebox.showwarning("Input Error", "Please specify the Volatility 3 executable path.")
            return
        
        # Clear previous output and reset state
        self.output_text.delete(1.0, tk.END)
        self.status_bar.config(text="Running Volatility... Please wait.")
        self.run_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.DISABLED)

        # Show and start progress bar
        self.progress_bar.pack(side=tk.RIGHT, padx=5)
        self.progress_bar.start(10)

        # Create and start the thread
        self.volatility_thread = threading.Thread(target=self._run_volatility_command)
        self.volatility_thread.daemon = True
        self.volatility_thread.start()
        
        # Periodically check if the thread is done
        self.master.after(100, self.check_volatility_thread)

    def _run_volatility_command(self):
        # This method runs in a separate thread
        memory_dump_file = self.vmem_file_path.get()
        vol_exe = self.volatility_exe_path.get()
        plugin = self.selected_plugin.get()
        args = self.custom_args.get().strip()

        # Prepare companion file if provided
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
                "error": f"Volatility 3 executable not found at '{vol_exe}'.\n"
                         "Please ensure it's in your system's PATH, provide the full path, or select the 'vol.py' script."
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
            self.output_text.insert(tk.END, "✓ Companion metadata file was used for analysis\n\n")
        
        self.output_text.insert(tk.END, f"Executing command: {command_executed}\n\n")

        if returncode == 0:
            self.output_text.insert(tk.END, stdout)
            self.status_bar.config(text="Volatility command completed successfully.")
        else:
            self.output_text.insert(tk.END, f"Error running Volatility:\n{stderr}\n")
            self.status_bar.config(text="Volatility command failed.")
            messagebox.showerror("Volatility Error", f"Volatility command failed. Check output for details.\nError Code: {returncode}")

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
                self.status_bar.config(text=f"Output successfully exported to {os.path.basename(file_path)}")
                messagebox.showinfo("Export Success", f"Output saved to:\n{file_path}")
            except Exception as e:
                self.status_bar.config(text=f"Error exporting output: {e}")
                messagebox.showerror("Export Error", f"Failed to save output:\n{e}")

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)
        self.status_bar.config(text="Output cleared.")

def main():
    root = tk.Tk()
    app = VolatilityGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
