import tkinter as tk
# Import ttk for themed widgets like Progressbar
from tkinter import filedialog, messagebox, scrolledtext, ttk
import subprocess
import os
import sys
import threading  # Import threading for background tasks


class VolatilityGUI:
    def __init__(self, master):
        self.master = master
        master.title("Volatility 3 GUI")
        master.geometry("900x750")

        # --- Variables ---
        self.vmem_file_path = tk.StringVar()

        if sys.platform == "win32":
            self.volatility_exe_path = tk.StringVar(value="volatility3.exe")
        else:
            self.volatility_exe_path = tk.StringVar(value="volatility3")

        self.selected_plugin = tk.StringVar()
        self.custom_args = tk.StringVar()

        # --- Comprehensive Volatility 3 Plugins List ---
        self.plugins = [
            # General / Info
            "info", "config",

            # Windows Plugins
            "windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.dlllist",
            "windows.handles", "windows.mutantscan", "windows.netscan", "windows.sockscan",
            "windows.connections", "windows.connscan", "windows.cmdline", "windows.cmdscan",
            "windows.consoles", "windows.registry.hivelist", "windows.registry.hivescan",
            "windows.registry.printkey", "windows.registry.userassist", "windows.registry.amcache",
            "windows.registry.shimcache", "windows.registry.shellbags", "windows.registry.lastboot",
            "windows.registry.dumpregistry", "windows.hashdump", "windows.lsass.secrets",
            "windows.svcscan", "windows.driverscan", "windows.modscan", "windows.callbacks",
            "windows.apihooks", "windows.malfind", "windows.vadinfo", "windows.memmap",
            "windows.procdump", "windows.memdump", "windows.dumpfiles", "windows.filescan",
            "windows.mftscan", "windows.mbrscan", "windows.ssdt", "windows.gditimers",
            "windows.devicetree", "windows.sessions", "windows.shutdown", "windows.timeliner",
            "windows.prefetch", "windows.useraccounts", "windows.clipboard", "windows.iehistory",
            "windows.getservicesids", "windows.skeleton_key", "windows.kdbgscan",

            # Linux Plugins
            "linux.info", "linux.pslist", "linux.pstree", "linux.psscan", "linux.netscan",
            "linux.sockscan", "linux.ifconfig", "linux.lsof", "linux.mount", "linux.modscan",
            "linux.lsmod", "linux.dmesg", "linux.bash", "linux.malfind", "linux.procfs",
            "linux.check_syscall", "linux.check_tty", "linux.elfs", "linux.enum_kmsg",
            "linux.iomem", "linux.keyboard_notifiers", "linux.ldrmodules", "linux.lsmod",
            "linux.lsof", "linux.netstat", "linux.pidhashtable", "linux.pkt_queues",
            "linux.pstree", "linux.tty", "linux.vma", "linux.yarascan",

            # MacOS Plugins
            "mac.info", "mac.pslist", "mac.pstree", "mac.psaux", "mac.netscan",
            "mac.check_syscall", "mac.check_sysctl", "mac.check_trap_table", "mac.kextstat",
            "mac.lsmod", "mac.malfind", "mac.mount", "mac.proc_maps", "mac.socket_filters",
            "mac.tasks", "mac.trustedbsd", "mac.volshell", "mac.zone_map",
            "mac.apihooks", "mac.bash", "mac.dmesg", "mac.filevault", "mac.filescan",
            "mac.ifconfig", "mac.iomem", "mac.lsmod", "mac.lsof", "mac.memmap",
            "mac.netstat", "mac.proc_maps", "mac.sockscan", "mac.sysctl",
            "mac.timers", "mac.vma", "mac.yarascan",
        ]
        self.plugins.sort()
        if self.plugins:
            self.selected_plugin.set(self.plugins[0])
        else:
            self.selected_plugin.set("No plugins found")

        # --- GUI Elements ---

        # Frame for File/Executable Paths
        path_frame = tk.LabelFrame(
            master, text="Configuration", padx=10, pady=10)
        path_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(path_frame, text="Memory Dump File:").grid(
            row=0, column=0, sticky="w", pady=2)
        tk.Entry(path_frame, textvariable=self.vmem_file_path,
                 width=70).grid(row=0, column=1, padx=5, pady=2)
        tk.Button(path_frame, text="Browse", command=self.browse_memory_dump_file).grid(
            row=0, column=2, padx=5, pady=2)

        tk.Label(path_frame, text="Volatility 3 Executable:").grid(
            row=1, column=0, sticky="w", pady=2)
        tk.Entry(path_frame, textvariable=self.volatility_exe_path,
                 width=70).grid(row=1, column=1, padx=5, pady=2)
        tk.Button(path_frame, text="Browse", command=self.browse_volatility_exe).grid(
            row=1, column=2, padx=5, pady=2)

        # Frame for Plugin and Arguments
        plugin_frame = tk.LabelFrame(
            master, text="Volatility Command", padx=10, pady=10)
        plugin_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(plugin_frame, text="Select Plugin:").grid(
            row=0, column=0, sticky="w", pady=2)
        self.plugin_combobox = tk.OptionMenu(
            plugin_frame, self.selected_plugin, *self.plugins)
        self.plugin_combobox.config(width=60)
        self.plugin_combobox.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        tk.Label(plugin_frame, text="Custom Arguments:").grid(
            row=1, column=0, sticky="w", pady=2)
        tk.Entry(plugin_frame, textvariable=self.custom_args,
                 width=70).grid(row=1, column=1, padx=5, pady=2)
        tk.Label(plugin_frame, text="(e.g., -o output.txt --pid 1234 --output-format csv)").grid(
            row=1, column=2, sticky="w", padx=5, pady=2)

        # Frame for Actions
        action_frame = tk.Frame(master, padx=10, pady=10)
        action_frame.pack(pady=5, padx=10, fill="x")

        self.run_button = tk.Button(action_frame, text="Run Volatility",
                                    command=self.start_volatility_thread, bg="lightblue", fg="black")
        self.run_button.pack(side="left", padx=5)

        self.export_button = tk.Button(
            action_frame, text="Export Output", command=self.export_output, bg="lightgreen", fg="black")
        self.export_button.pack(side="left", padx=5)

        self.clear_button = tk.Button(
            action_frame, text="Clear Output", command=self.clear_output, bg="lightcoral", fg="black")
        self.clear_button.pack(side="right", padx=5)

        # Output Area
        self.output_text = scrolledtext.ScrolledText(
            master, wrap=tk.WORD, width=100, height=25, font=("Consolas", 10))
        self.output_text.pack(pady=10, padx=10, fill="both", expand=True)

        # Status Bar and Progress Bar
        status_bar_frame = tk.Frame(master, bd=1, relief=tk.SUNKEN)
        status_bar_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_bar = tk.Label(status_bar_frame, text="Ready", anchor=tk.W)
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress_bar = ttk.Progressbar(
            status_bar_frame, mode='indeterminate', length=200)
        # Initially hide the progress bar
        # self.progress_bar.pack(side=tk.RIGHT, padx=5) # Don't pack initially, pack/grid when needed

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
            self.status_bar.config(
                text=f"Selected Dump: {os.path.basename(file_path)}")

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
            self.status_bar.config(
                text=f"Selected Volatility Executable: {os.path.basename(file_path)}")

    def start_volatility_thread(self):
        # Input validation
        memory_dump_file = self.vmem_file_path.get()
        vol_exe = self.volatility_exe_path.get()

        if not memory_dump_file:
            messagebox.showwarning(
                "Input Error", "Please select a memory dump file.")
            return
        if not os.path.exists(memory_dump_file):
            messagebox.showwarning(
                "File Error", f"The selected memory dump file does not exist: {memory_dump_file}")
            return
        if not vol_exe:
            messagebox.showwarning(
                "Input Error", "Please specify the Volatility 3 executable path.")
            return

        # Clear previous output and reset state
        self.output_text.delete(1.0, tk.END)
        self.status_bar.config(text="Running Volatility... Please wait.")
        self.run_button.config(state=tk.DISABLED)  # Disable button
        # Disable export button during run
        self.export_button.config(state=tk.DISABLED)

        # Show and start progress bar
        self.progress_bar.pack(side=tk.RIGHT, padx=5)
        self.progress_bar.start(10)  # Start with 10ms update interval

        # Create and start the thread
        self.volatility_thread = threading.Thread(
            target=self._run_volatility_command)
        # Allow the program to exit even if thread is running
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

        command = []
        if vol_exe.endswith(".py"):
            command = [sys.executable, vol_exe, "-f", memory_dump_file, plugin]
        else:
            command = [vol_exe, "-f", memory_dump_file, plugin]

        if args:
            command.extend(args.split())

        try:
            process = subprocess.run(
                command, capture_output=True, text=True, check=False, shell=False)
            self.volatility_result = {
                "stdout": process.stdout,
                "stderr": process.stderr,
                "returncode": process.returncode,
                "command": ' '.join(command),
                "error": None
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
            # Thread is still running, check again later
            self.master.after(100, self.check_volatility_thread)
        else:
            # Thread has finished, process results
            self.process_volatility_output()

    def process_volatility_output(self):
        # This method runs in the main Tkinter thread
        self.progress_bar.stop()
        self.progress_bar.pack_forget()  # Hide progress bar
        self.run_button.config(state=tk.NORMAL)  # Re-enable button
        self.export_button.config(state=tk.NORMAL)  # Re-enable export button

        if self.volatility_result["error"]:
            messagebox.showerror("Error", self.volatility_result["error"])
            self.status_bar.config(text="Error during execution.")
            self.output_text.insert(
                tk.END, f"Error: {self.volatility_result['error']}\n")
            return

        command_executed = self.volatility_result["command"]
        stdout = self.volatility_result["stdout"]
        stderr = self.volatility_result["stderr"]
        returncode = self.volatility_result["returncode"]

        self.output_text.insert(
            tk.END, f"Executing command: {command_executed}\n\n")

        if returncode == 0:
            self.output_text.insert(tk.END, stdout)
            self.status_bar.config(
                text="Volatility command completed successfully.")
        else:
            self.output_text.insert(
                tk.END, f"Error running Volatility:\n{stderr}\n")
            self.status_bar.config(text="Volatility command failed.")
            messagebox.showerror(
                "Volatility Error", f"Volatility command failed. Check output for details.\nError Code: {returncode}")

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
                self.status_bar.config(
                    text=f"Output successfully exported to {os.path.basename(file_path)}")
                messagebox.showinfo(
                    "Export Success", f"Output saved to:\n{file_path}")
            except Exception as e:
                self.status_bar.config(text=f"Error exporting output: {e}")
                messagebox.showerror(
                    "Export Error", f"Failed to save output:\n{e}")

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)
        self.status_bar.config(text="Output cleared.")


def main():
    root = tk.Tk()
    app = VolatilityGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
