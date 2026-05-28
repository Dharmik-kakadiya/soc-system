import subprocess
import sys
import time
import os
import requests

# 1. Define base directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(SCRIPT_DIR) == "scripts":
    BASE_DIR = os.path.dirname(SCRIPT_DIR)
else:
    BASE_DIR = SCRIPT_DIR

os.chdir(BASE_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

processes = []

def cleanup():
    print("\n[STOP] Shutting down all SOC services gracefully...")
    for name, p in processes:
        if p.poll() is None:  # If process is still running
            print(f"Stopping {name} (PID: {p.pid})...")
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill() # Force kill if it hangs
    print("[SUCCESS] All services stopped. Goodbye!")

def wait_for_api():
    print("[WAIT] Waiting for API Server to be ready...", end="", flush=True)
    max_retries = 30
    for _ in range(max_retries):
        try:
            response = requests.get("http://127.0.0.1:8001/health", timeout=1)
            if response.status_code == 200:
                print(" Ready!")
                return True
        except requests.ConnectionError:
            pass
        print(".", end="", flush=True)
        time.sleep(1)
    print(" FAILED!")
    return False

def check_paths():
    print("[CHECK] Verifying paths...")
    required_files = [
        "api/main.py",
        "dashboard/app.py",
        "scripts/sniffer.py"
    ]
    for rel_path in required_files:
        full_path = os.path.join(BASE_DIR, rel_path.replace("/", os.sep))
        if not os.path.exists(full_path):
            print(f"[ERROR] Missing required file: {full_path}")
            sys.exit(1)
    
    # Ensure alerts.json exists
    alert_file = os.path.join(BASE_DIR, "scripts", "alerts.json")
    if not os.path.exists(alert_file):
        with open(alert_file, "w") as f:
            pass
    print("[CHECK] All paths verified!")

def release_port(port=8001):
    print(f"[CLEANUP] Ensuring port {port} is free...")
    if sys.platform.startswith('win'):
        try:
            result = subprocess.check_output(f"netstat -ano | findstr :{port}", shell=True).decode()
            for line in result.splitlines():
                if "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    print(f"          Found ghost process (PID: {pid}) using port {port}. Terminating...")
                    subprocess.run(f"taskkill /F /PID {pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass

def main():
    print("\n" + "="*60)
    print("[START] STARTING SOC SYSTEM PIPELINE")
    print("="*60 + "\n")
    
    # 2. Check Paths
    check_paths()

    # 2.5 Release port if stuck
    release_port(8001)

    python_exec = sys.executable
    import copy
    child_env = copy.copy(os.environ)
    child_env["PYTHONIOENCODING"] = "utf-8"
    child_env["PYTHONUTF8"] = "1"

    try:
        # 3. Start API
        print("\n[1/3] [API] Starting FastAPI Server (Port 8001)...")
        api_cmd = [python_exec, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8001"]
        api_process = subprocess.Popen(api_cmd, env=child_env)
        processes.append(("API Server", api_process))
        
        # 4. Wait for API (/health)
        if not wait_for_api():
            print("[ERROR] API Server failed to start in time. Aborting.")
            cleanup()
            sys.exit(1)
        
        # 5. Start Sniffer
        print("\n[2/3] [NET] Starting Network Sniffer (Requires Administrator Privileges)...")
        sniffer_cmd = [python_exec, "-X", "utf8", "scripts/sniffer.py"]
        sniffer_process = subprocess.Popen(sniffer_cmd, env=child_env)
        processes.append(("Sniffer", sniffer_process))
        
        # Give Sniffer a second to attach to network interfaces
        time.sleep(2)

        # 6. Start Dashboard
        print("\n[3/3] [GUI] Starting Streamlit Dashboard...")
        dashboard_cmd = [python_exec, "-m", "streamlit", "run", "dashboard/app.py"]
        dashboard_process = subprocess.Popen(dashboard_cmd, env=child_env)
        processes.append(("Dashboard", dashboard_process))

        print("\n" + "="*60)
        print("[SUCCESS] ALL SERVICES RUNNING SUCCESSFULLY!")
        print("[INFO] Press [Ctrl + C] in this terminal to STOP all services.")
        print("="*60 + "\n")

        # 7. Monitor processes
        while True:
            for name, p in processes:
                if p.poll() is not None:
                    print(f"\n[CRITICAL] Service '{name}' exited unexpectedly with code {p.returncode}!")
                    cleanup()
                    sys.exit(1)
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[STOP] KeyboardInterrupt detected!")
        # 8. Graceful shutdown
        cleanup()
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")
        cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()