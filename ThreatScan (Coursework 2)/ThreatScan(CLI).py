#!/usr/bin/python

import os
import hashlib
import psutil
import time
import mysql.connector
import getpass

# Path to the file containing known malicious hashes
MALWARE_HASH_FILE = "malwarehashes.txt"

# Function to calculate the SHA-256 hash of a file
def calculate_sha256(file_path):
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None

# Load the malicious hashes from the file
def load_malware_hashes():
    try:
        with open(MALWARE_HASH_FILE, "r") as file:
            return set(line.strip() for line in file.readlines())
    except Exception as e:
        print(f"Error reading malware hash file: {e}")
        return set()

# Function to get current running processes
def get_running_processes():
    running_processes = {}
    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            pid = proc.info['pid']
            cmdline = proc.info['cmdline']
            if isinstance(cmdline, str):
                cmdline = [cmdline]  # If cmdline is a single string, convert it to a list
            if cmdline:
                running_processes[pid] = cmdline
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass  # Ignore processes that have ended or that we cannot access
    return running_processes

# Function to check all processes (both new and existing)
def check_processes(running_processes, malware_hashes):
    for pid, cmdline in running_processes.items():
        # Check if we can find a file in the process
        for part in cmdline:
            if os.path.isfile(part):
                # Get the absolute path of the file
                absolute_path = os.path.abspath(part)
                
                # Calculate the SHA-256 hash for the file
                file_hash = calculate_sha256(absolute_path)
                if file_hash:
                    # Check for a match with any malware hashes
                    if file_hash in malware_hashes:
                        print(f"[ALERT] Malware detected in PID {pid}: {absolute_path} (Hash: {file_hash})")
                        os.kill(pid, 9)  # Terminate the process with SIGKILL
                        print(f"[INFO] Terminated Process {pid}: {absolute_path}")
                        log_malware(absolute_path, file_hash)

# Database setup
def init_db():
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

# User authentication
def register_user(username, password):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = mysql.connector.connect(host="localhost", user="root", password="", database="malware_logs")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
        conn.commit()
        print("User registered successfully!")
    except mysql.connector.IntegrityError:
        print("Error: Username already exists.")
    conn.close()

def login_user(username, password):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = mysql.connector.connect(host="localhost", user="root", password="", database="malware_logs")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s AND password_hash = %s", (username, password_hash))
    user = cursor.fetchone()
    conn.close()
    if user:
        print("Login successful!")
        return True
    else:
        print("Invalid credentials.")
        return False

# Log malware detection to database
def log_malware(file_path, file_hash):
    conn = mysql.connector.connect(host="localhost", user="root", password="", database="malware_logs")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (file_path, hash, status) VALUES (%s, %s, 'INFECTED')", (file_path, file_hash))
    conn.commit()
    conn.close()

# Main loop for malware monitoring
def monitor_processes():
    malware_hashes = load_malware_hashes()
    if not malware_hashes:
        print("[ERROR] No malware hashes loaded. Exiting.")
        return
    
    print("[INFO] Starting malware monitoring...")
    running_processes = get_running_processes()

    while True:
        # Continuously check both existing and new processes
        check_processes(running_processes, malware_hashes)
        
        # Update the running processes snapshot
        running_processes = get_running_processes()
        
# Entry point for user authentication
if __name__ == "__main__":
    init_db()
    print(r'''
  ________  ______  _________  ___________ _________    _   __
 /_  __/ / / / __ \/ ____/   |/_  __/ ___// ____/   |  / | / /
  / / / /_/ / /_/ / __/ / /| | / /  \__ \/ /   / /| | /  |/ / 
 / / / __  / _, _/ /___/ ___ |/ /  ___/ / /___/ ___ |/ /|  /  
/_/ /_/ /_/_/ |_/_____/_/  |_/_/  /____/\____/_/  |_/_/ |_/   
                                                              
''')
    print("1. Register\n2. Login")
    choice = input("Choose an option: ")
    if choice == "1":
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        register_user(username, password)
    elif choice == "2":
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        if login_user(username, password):
            print("Starting Malware Detection Tool...")
            monitor_processes()
    else:
        print("Invalid option.")
