#!/usr/bin/python

import os
import hashlib
import psutil
import time
import mysql.connector
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from threading import Thread
import queue

class MalwareDetectionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ThreatScan")
        self.root.geometry("1000x700")
        
        # Configure the root window with a more modern appearance
        self.root.configure(bg='#f5f8fa')
        
        # Enhanced styling with a better color scheme
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Using clam as base theme
        
        # Configure colors
        self.primary_color = "#3498db"      # Blue
        self.secondary_color = "#2c3e50"    # Dark blue
        self.accent_color = "#e74c3c"       # Red for alerts
        self.success_color = "#2ecc71"      # Green for success
        self.neutral_color = "#7f8c8d"      # Gray for neutral text
        self.bg_color = "#f5f8fa"           # Light background
        self.fg_color = "#34495e"           # Text color
        
        # Configure component styles
        self.style.configure('Main.TFrame', background=self.bg_color)
        self.style.configure('Header.TLabel', 
                           font=('Helvetica', 24, 'bold'), 
                           background=self.bg_color,
                           foreground=self.secondary_color)
        self.style.configure('SubHeader.TLabel', 
                           font=('Helvetica', 12),
                           background=self.bg_color,
                           foreground=self.neutral_color)
        
        # Button styles
        self.style.configure('Primary.TButton',
                           font=('Helvetica', 10, 'bold'),
                           background=self.primary_color,
                           foreground='white')
        self.style.map('Primary.TButton',
                     background=[('active', '#2980b9'), ('disabled', '#bdc3c7')])
        
        self.style.configure('Secondary.TButton',
                           font=('Helvetica', 10),
                           background='#ecf0f1')
        self.style.map('Secondary.TButton',
                     background=[('active', '#dfe4ea'), ('disabled', '#ecf0f1')])
        
        self.style.configure('Danger.TButton',
                           font=('Helvetica', 10, 'bold'),
                           background=self.accent_color)
        self.style.map('Danger.TButton',
                     background=[('active', '#c0392b'), ('disabled', '#e6b0aa')])
        
        # Entry style
        self.style.configure('TEntry', 
                           font=('Helvetica', 11),
                           fieldbackground='white')
        
        # Create message queue for thread communication
        self.message_queue = queue.Queue()
        
        # Initialize database
        self.init_db()
        
        # Create main frame with padding
        self.main_frame = ttk.Frame(self.root, style='Main.TFrame', padding="40")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.create_login_frame()
        
    def init_db(self):
        try:
            conn = mysql.connector.connect(host="localhost", user="root", password="", database="malware_logs")
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                file_path TEXT,
                hash TEXT,
                status TEXT
            )""")
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )""")
            conn.commit()
            conn.close()
        except Exception as e:
            messagebox.showerror("Database Error", f"Could not initialize database: {str(e)}")
        
    def create_login_frame(self):
        # Clear main frame
        for widget in self.main_frame.winfo_children():
            widget.destroy()
            
        # Add a decorative security icon made with unicode
        shield_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        shield_frame.pack(pady=(0, 20))
        shield_label = tk.Label(shield_frame, 
                              text="🛡️", 
                              font=('Arial', 48),
                              bg=self.bg_color,
                              fg=self.primary_color)
        shield_label.pack()
        
        # Header
        header_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        header_frame.pack(pady=(0, 30))
        
        ttk.Label(header_frame, 
                 text="ThreatScan",
                 style='Header.TLabel').pack(pady=(0, 10))
        
        ttk.Label(header_frame,
                 text="Advanced malware detection and system protection",
                 style='SubHeader.TLabel').pack()
        
        # Login frame with enhanced styling
        login_frame = ttk.Frame(self.main_frame, padding="30", style='Main.TFrame')
        login_frame.pack()
        
        # Username with better label and spacing
        username_label = ttk.Label(login_frame, 
                                 text="Username",
                                 font=('Helvetica', 11, 'bold'),
                                 background=self.bg_color,
                                 foreground=self.fg_color)
        username_label.grid(row=0, column=0, padx=5, pady=(0, 5), sticky='w')
        
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(login_frame, 
                                 textvariable=self.username_var,
                                 width=30,
                                 font=('Helvetica', 11),
                                 style='TEntry')
        username_entry.grid(row=1, column=0, padx=5, pady=(0, 20), ipady=3)
        
        # Password
        password_label = ttk.Label(login_frame, 
                                 text="Password",
                                 font=('Helvetica', 11, 'bold'),
                                 background=self.bg_color,
                                 foreground=self.fg_color)
        password_label.grid(row=2, column=0, padx=5, pady=(0, 5), sticky='w')
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(login_frame, 
                                 textvariable=self.password_var,
                                 show="•",
                                 width=30,
                                 font=('Helvetica', 11),
                                 style='TEntry')
        password_entry.grid(row=3, column=0, padx=5, pady=(0, 25), ipady=3)
        
        # Buttons with improved styling
        button_frame = ttk.Frame(login_frame, style='Main.TFrame')
        button_frame.grid(row=4, column=0, pady=(0, 10))
        
        login_button = ttk.Button(button_frame, 
                                text="Login",
                                style='Primary.TButton',
                                padding=(20, 10),
                                command=self.login)
        login_button.grid(row=0, column=0, padx=5)
        
        register_button = ttk.Button(button_frame,
                                   text="Register",
                                   style='Secondary.TButton',
                                   padding=(20, 10),
                                   command=self.create_register_frame)
        register_button.grid(row=0, column=1, padx=5)
        
        # Version info at bottom
        version_label = ttk.Label(self.main_frame,
                                text="Version 1.2.0",
                                font=('Helvetica', 8),
                                background=self.bg_color,
                                foreground=self.neutral_color)
        version_label.pack(side=tk.BOTTOM, pady=(30, 0))
        
    def create_register_frame(self):
        # Clear main frame
        for widget in self.main_frame.winfo_children():
            widget.destroy()
            
        # Add a decorative icon
        user_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        user_frame.pack(pady=(0, 20))
        user_label = tk.Label(user_frame, 
                            text="👤", 
                            font=('Arial', 48),
                            bg=self.bg_color,
                            fg=self.primary_color)
        user_label.pack()
        
        # Header
        header_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        header_frame.pack(pady=(0, 30))
        
        ttk.Label(header_frame,
                 text="Create Account",
                 style='Header.TLabel').pack(pady=(0, 10))
        
        ttk.Label(header_frame,
                 text="Register to start protecting your system",
                 style='SubHeader.TLabel').pack()
        
        # Register frame
        register_frame = ttk.Frame(self.main_frame, padding="30", style='Main.TFrame')
        register_frame.pack()
        
        # Username
        username_label = ttk.Label(register_frame,
                                 text="Username",
                                 font=('Helvetica', 11, 'bold'),
                                 background=self.bg_color,
                                 foreground=self.fg_color)
        username_label.grid(row=0, column=0, padx=5, pady=(0, 5), sticky='w')
        
        self.reg_username_var = tk.StringVar()
        username_entry = ttk.Entry(register_frame,
                                 textvariable=self.reg_username_var,
                                 width=30,
                                 font=('Helvetica', 11),
                                 style='TEntry')
        username_entry.grid(row=1, column=0, padx=5, pady=(0, 20), ipady=3)
        
        # Password
        password_label = ttk.Label(register_frame,
                                 text="Password",
                                 font=('Helvetica', 11, 'bold'),
                                 background=self.bg_color,
                                 foreground=self.fg_color)
        password_label.grid(row=2, column=0, padx=5, pady=(0, 5), sticky='w')
        
        self.reg_password_var = tk.StringVar()
        password_entry = ttk.Entry(register_frame,
                                 textvariable=self.reg_password_var,
                                 show="•",
                                 width=30,
                                 font=('Helvetica', 11),
                                 style='TEntry')
        password_entry.grid(row=3, column=0, padx=5, pady=(0, 25), ipady=3)
        
        # Buttons
        button_frame = ttk.Frame(register_frame, style='Main.TFrame')
        button_frame.grid(row=4, column=0, pady=(0, 10))
        
        register_button = ttk.Button(button_frame,
                                   text="Register",
                                   style='Primary.TButton',
                                   padding=(20, 10),
                                   command=self.register)
        register_button.grid(row=0, column=0, padx=5)
        
        back_button = ttk.Button(button_frame,
                               text="Back to Login",
                               style='Secondary.TButton',
                               padding=(20, 10),
                               command=self.create_login_frame)
        back_button.grid(row=0, column=1, padx=5)
        
    def create_monitor_frame(self):
        # Clear main frame
        for widget in self.main_frame.winfo_children():
            widget.destroy()
            
        # Header with system stats
        header_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        header_frame.pack(pady=(0, 15), fill=tk.X)
        
        # Title and subtitle
        title_frame = ttk.Frame(header_frame, style='Main.TFrame')
        title_frame.pack(side=tk.LEFT)
        
        ttk.Label(title_frame,
                 text="ThreatScan",
                 style='Header.TLabel').pack(anchor="w")
        
        ttk.Label(title_frame,
                 text="Real-time threat detection and protection",
                 style='SubHeader.TLabel').pack(anchor="w")
        
        # System stats frame
        stats_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        stats_frame.pack(fill=tk.X, pady=(0, 15))
        
        # System stats with better visualization - using colors for visual appeal
        # CPU Usage
        cpu_frame = ttk.Frame(stats_frame, style='Main.TFrame')
        cpu_frame.pack(side=tk.LEFT, padx=10, expand=True)
        
        ttk.Label(cpu_frame, 
                text="CPU Usage",
                font=('Helvetica', 10, 'bold'),
                background=self.bg_color).pack(anchor="w")
        
        self.cpu_var = tk.StringVar(value="0%")
        cpu_label = ttk.Label(cpu_frame,
                            textvariable=self.cpu_var,
                            font=('Helvetica', 16),
                            foreground=self.primary_color,
                            background=self.bg_color)
        cpu_label.pack()
        
        # Memory Usage
        mem_frame = ttk.Frame(stats_frame, style='Main.TFrame')
        mem_frame.pack(side=tk.LEFT, padx=10, expand=True)
        
        ttk.Label(mem_frame, 
                text="Memory Usage",
                font=('Helvetica', 10, 'bold'),
                background=self.bg_color).pack(anchor="w")
        
        self.mem_var = tk.StringVar(value="0%")
        mem_label = ttk.Label(mem_frame,
                            textvariable=self.mem_var,
                            font=('Helvetica', 16),
                            foreground=self.primary_color,
                            background=self.bg_color)
        mem_label.pack()
        
        # Scan Status
        status_frame = ttk.Frame(stats_frame, style='Main.TFrame')
        status_frame.pack(side=tk.LEFT, padx=10, expand=True)
        
        ttk.Label(status_frame, 
                text="Protection Status",
                font=('Helvetica', 10, 'bold'),
                background=self.bg_color).pack(anchor="w")
        
        self.status_var = tk.StringVar(value="Inactive")
        status_label = ttk.Label(status_frame,
                               textvariable=self.status_var,
                               font=('Helvetica', 16),
                               foreground=self.neutral_color,
                               background=self.bg_color)
        status_label.pack()
        
        # Separator for visual clarity
        separator = ttk.Separator(self.main_frame, orient='horizontal')
        separator.pack(fill=tk.X, pady=10)
        
        # Monitor frame with improved log area
        monitor_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        monitor_frame.pack(fill=tk.BOTH, expand=True)
        
        # Enhanced log area with improved styling
        log_label = ttk.Label(monitor_frame,
                            text="Activity Log",
                            font=('Helvetica', 12, 'bold'),
                            background=self.bg_color,
                            foreground=self.fg_color)
        log_label.pack(anchor="w", padx=10, pady=(0, 5))
        
        self.log_area = scrolledtext.ScrolledText(
            monitor_frame,
            height=20,
            width=80,
            font=('Consolas', 10),
            background='white',
            foreground=self.fg_color,
            padx=10,
            pady=10,
            wrap=tk.WORD,
            borderwidth=1,
            relief=tk.SOLID
        )
        self.log_area.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        # Control buttons with improved visual hierarchy
        button_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        button_frame.pack(pady=15)
        
        self.start_button = ttk.Button(
            button_frame,
            text="Start Monitoring",
            style='Primary.TButton',
            padding=(15, 10),
            command=self.start_monitoring
        )
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(
            button_frame,
            text="Stop Monitoring",
            style='Danger.TButton',
            padding=(15, 10),
            command=self.stop_monitoring,
            state=tk.DISABLED
        )
        self.stop_button.grid(row=0, column=1, padx=5)
        
        ttk.Button(
            button_frame,
            text="Logout",
            style='Secondary.TButton',
            padding=(15, 10),
            command=self.logout
        ).grid(row=0, column=2, padx=5)
        
        # Start system stats update
        self.update_system_stats()
        
    def update_system_stats(self):
        try:
            cpu_percent = psutil.cpu_percent()
            mem_percent = psutil.virtual_memory().percent
            
            self.cpu_var.set(f"{cpu_percent}%")
            self.mem_var.set(f"{mem_percent}%")
            
            # Update status text and color based on monitoring state
            if hasattr(self, 'monitoring') and self.monitoring:
                self.status_var.set("Protected")
                self.root.nametowidget(".".join(self.status_var._name.split(".")[:-1])).configure(foreground=self.success_color)
            else:
                self.status_var.set("Inactive")
                self.root.nametowidget(".".join(self.status_var._name.split(".")[:-1])).configure(foreground=self.neutral_color)
        except:
            pass
            
        # Update every second if the monitor frame is active
        if hasattr(self, 'cpu_var'):
            self.root.after(1000, self.update_system_stats)
        
    def register(self):
        username = self.reg_username_var.get()
        password = self.reg_password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return
            
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            conn = mysql.connector.connect(host="localhost", user="root", password="", database="malware_logs")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Registration successful!")
            self.create_login_frame()
        except mysql.connector.IntegrityError:
            messagebox.showerror("Error", "Username already exists")
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {str(e)}")
            
    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            conn = mysql.connector.connect(host="localhost", user="root", password="", database="malware_logs")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s AND password_hash = %s", (username, password_hash))
            user = cursor.fetchone()
            conn.close()
            
            if user:
                self.create_monitor_frame()
            else:
                messagebox.showerror("Error", "Invalid credentials")
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {str(e)}")
            
    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.stop_monitoring()
            self.create_login_frame()
        
    def calculate_sha256(self, file_path):
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.log_message(f"Error calculating hash for {file_path}: {e}")
            return None
            
    def load_malware_hashes(self):
        try:
            with open("malwarehashes.txt", "r") as file:
                return set(line.strip() for line in file.readlines())
        except FileNotFoundError:
            self.log_message(f"[ERROR] Malware hash file not found. Create a file named 'malwarehashes.txt' with known malware hashes.")
            return set()
        except Exception as e:
            self.log_message(f"[ERROR] Error reading malware hash file: {e}")
            return set()
            
    def get_running_processes(self):
        running_processes = {}
        for proc in psutil.process_iter(['pid', 'cmdline']):
            try:
                pid = proc.info['pid']
                cmdline = proc.info['cmdline']
                if isinstance(cmdline, str):
                    cmdline = [cmdline]
                if cmdline:
                    running_processes[pid] = cmdline
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return running_processes
        
    def check_processes(self, running_processes, malware_hashes):
        for pid, cmdline in running_processes.items():
            for part in cmdline:
                if isinstance(part, str) and os.path.isfile(part):
                    try:
                        absolute_path = os.path.abspath(part)
                        file_hash = self.calculate_sha256(absolute_path)
                        if file_hash and file_hash in malware_hashes:
                            self.log_message(f"[ALERT] Malware detected in PID {pid}: {absolute_path} (Hash: {file_hash})")
                            try:
                                os.kill(pid, 9)
                                self.log_message(f"[INFO] Terminated Process {pid}: {absolute_path}")
                                self.log_malware(absolute_path, file_hash)
                            except Exception as e:
                                self.log_message(f"[ERROR] Failed to terminate process {pid}: {str(e)}")
                    except Exception as e:
                        continue
                            
    def log_malware(self, file_path, file_hash):
        try:
            conn = mysql.connector.connect(host="localhost", user="root", password="", database="malware_logs")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO logs (file_path, hash, status) VALUES (%s, %s, 'INFECTED')", 
                         (file_path, file_hash))
            conn.commit()
            conn.close()
        except Exception as e:
            self.log_message(f"[ERROR] Failed to log malware detection: {str(e)}")
            
    def log_message(self, message):
        self.message_queue.put(message)
        
    def update_log_area(self):
        while True:
            try:
                message = self.message_queue.get_nowait()
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                formatted_message = f"[{timestamp}] {message}"
                
                # Color-code messages based on type and improve visibility
                if "[ALERT]" in message:
                    self.log_area.tag_config("alert", foreground="red", font=('Consolas', 10, 'bold'))
                    self.log_area.insert(tk.END, formatted_message + "\n", "alert")
                elif "[ERROR]" in message:
                    self.log_area.tag_config("error", foreground="#e74c3c")
                    self.log_area.insert(tk.END, formatted_message + "\n", "error")
                elif "[INFO]" in message:
                    self.log_area.tag_config("info", foreground="#2980b9")
                    self.log_area.insert(tk.END, formatted_message + "\n", "info")
                else:
                    self.log_area.insert(tk.END, formatted_message + "\n")
                    
                self.log_area.see(tk.END)
            except queue.Empty:
                break
        if hasattr(self, 'monitoring') and self.monitoring:
            self.root.after(100, self.update_log_area)
            
    def monitor_processes(self):
        malware_hashes = self.load_malware_hashes()
        if not malware_hashes:
            self.log_message("[ERROR] No malware hashes loaded. Stopping monitoring.")
            self.stop_monitoring()
            return
            
        self.log_message("[INFO] Starting malware monitoring...")
        self.log_message("[INFO] Scanning system processes...")
        
        scan_count = 0
        while hasattr(self, 'monitoring') and self.monitoring:
            running_processes = self.get_running_processes()
            self.check_processes(running_processes, malware_hashes)
            
            # Log periodic scan completions for better user feedback
            scan_count += 1
            if scan_count % 10 == 0:  # Log every 10 scans
                self.log_message(f"[INFO] Completed scan cycle #{scan_count//10}. System secure.")
                
            time.sleep(1)
            
    def start_monitoring(self):
        self.monitoring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Visual indicator that monitoring is active
        self.log_area.tag_config("system", foreground="#27ae60", font=('Consolas', 10, 'bold'))
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        self.log_area.insert(tk.END, f"[{timestamp}] [SYSTEM] ThreatScan Protection activated\n", "system")
        self.log_area.see(tk.END)
        
        Thread(target=self.monitor_processes, daemon=True).start()
        self.update_log_area()
        
    def stop_monitoring(self):
        if hasattr(self, 'monitoring'):
            self.monitoring = False
            
        if hasattr(self, 'start_button'):
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
            # Visual indicator that monitoring is stopped
            if hasattr(self, 'log_area'):
                self.log_area.tag_config("system", foreground="#e67e22", font=('Consolas', 10, 'bold'))
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                self.log_area.insert(tk.END, f"[{timestamp}] [SYSTEM] ThreatScan Protection deactivated\n", "system")
                self.log_area.see(tk.END)
                self.log_message("[INFO] Monitoring stopped.")
            
def center_window(window):
    """Center the window on the screen"""
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')

if __name__ == "__main__":
    root = tk.Tk()
    root.configure(bg='#f5f8fa')
    root.title("ThreatScan Pro")
    
    # Set window icon (if available)
    try:
        root.iconbitmap("shield.ico")
    except:
        pass
    
    app = MalwareDetectionGUI(root)
    center_window(root)
    root.mainloop()
