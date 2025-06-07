#!/usr/bin/env python3

import subprocess
import time
import threading
import os
import re
import sys
import requests # Add this at the top
from flask import Flask, request, render_template_string, redirect, url_for, make_response

# --- Configuration ---
# Try to autodetect, or set this manually if detection fails or is wrong.
# Example: WIFI_IFACE = "wlan0"
WIFI_IFACE = None # Will be auto-detected
AP_SSID = "AlbumPlayerWifiConfig"  # SSID for the captive portal AP
AP_PSK = "playjams"     # Password for the captive portal AP (at least 8 chars)
AP_IP_ADDRESS = "192.168.42.1" # IP address of this device when in AP mode
AP_CONNECTION_NAME = "captive-portal-ap" # nmcli connection name for the AP
FLASK_PORT = 5000          # Port for the captive portal web server
MONITOR_INTERVAL = 30      # Seconds to wait between internet checks when connected
RETRY_INTERVAL_AFTER_FAIL = 10 # Seconds to wait before retrying AP mode or connection

# --- Flask App ---
flask_app = Flask(__name__)
# Shared data between main thread and Flask thread
credentials_received_event = None
received_credentials_store = {}
flask_ap_ssid = AP_SSID # Used in connecting template

HTML_FORM_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Configure WiFi</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; text-align: center; }
        .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); display: inline-block; max-width: 400px; width: 90%; }
        h1 { color: #333; }
        label { display: block; margin-top: 10px; text-align: left; color: #555; font-weight: bold; }
        input[type="text"], input[type="password"] { width: calc(100% - 22px); padding: 10px; margin-top: 5px; border: 1px solid #ddd; border-radius: 4px; }
        input[type="submit"] { background-color: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 20px; width: 100%; }
        input[type="submit"]:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Set Up WiFi Connection</h1>
        <p>Connect this device to a WiFi network.</p>
        <form action="/configure" method="post">
            <label for="ssid">WiFi Name (SSID):</label>
            <input type="text" id="ssid" name="ssid" required><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password"><br>
            <input type="submit" value="Connect">
        </form>
    </div>
</body>
</html>
"""

HTML_CONNECTING_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Connecting...</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Attempt to redirect to a common site after a delay to check connectivity -->
    <meta http-equiv="refresh" content="15;url=http://connectivitycheck.gstatic.com">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; text-align: center; }
        .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); display: inline-block; }
        h1 { color: #333; }
        p { font-size: 1.1em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Attempting to Connect</h1>
        <p>This device will now try to connect to the WiFi network you specified.</p>
        <p>You will be disconnected from the '{{ ap_ssid }}' network. If the new connection is successful, your device (phone/laptop) should regain internet access through the new network if it's configured to auto-reconnect.</p>
        <p>This page will try to redirect in 15 seconds. If it doesn't, please check your WiFi settings.</p>
    </div>
</body>
</html>
"""

def init_flask_shared_data(event, creds_store, ap_ssid_for_template):
    """Initializes shared data for Flask app running in a thread."""
    global credentials_received_event, received_credentials_store, flask_ap_ssid
    credentials_received_event = event
    received_credentials_store = creds_store
    flask_ap_ssid = ap_ssid_for_template


def run_flask_app_threaded(host_ip, port):
    """Runs the Flask app. Designed to be called in a separate thread."""
    try:
        # Use '0.0.0.0' to listen on all available interfaces within the AP network
        flask_app.run(host='0.0.0.0', port=port, debug=False)
    except Exception as e:
        print(f"Flask app failed: {e}")

@flask_app.route('/')
def index_route():
    return render_template_string(HTML_FORM_TEMPLATE)

@flask_app.route('/configure', methods=['POST'])
def configure_route():
    global received_credentials_store, credentials_received_event, flask_ap_ssid
    ssid = request.form.get('ssid')
    password = request.form.get('password')

    if not ssid: # Basic validation
        return "SSID is required.", 400

    if received_credentials_store is not None:
        received_credentials_store['ssid'] = ssid
        received_credentials_store['password'] = password
    
    if credentials_received_event:
        credentials_received_event.set()
        
    return render_template_string(HTML_CONNECTING_TEMPLATE, ap_ssid=flask_ap_ssid)

@flask_app.route('/<path:path>')
def catch_all_route(path):
    # Handle common captive portal detection paths
    # Android often uses generate_204
    if path == "generate_204" or path == "gen_204":
        print(f"Captive portal check: /{path} -> 204 No Content")
        return redirect(url_for("index_route"))
    
    # iOS, Windows, Kindle etc.
    common_detection_strings = ["hotspot-detect.html", "success.html", "ncsi.txt", "check_network_status", "kindle-wifi/wifistub.html"]
    if any(detect_str in path for detect_str in common_detection_strings):
        print(f"Captive portal check: /{path} -> Redirect to /")
        return redirect(url_for('index_route'))

    portal_url = f"http://{AP_IP_ADDRESS}:{FLASK_PORT}/"
    print(f"Catch-all for path '/{path}', request.host: '{request.host}'. Redirecting to portal: {portal_url}")
    return redirect(portal_url)


# --- Helper Functions ---
def run_command(command, check=True, timeout=15):
    print(f"Executing: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=check, timeout=timeout)
        if result.stdout.strip():
            print(f"Stdout: {result.stdout.strip()}")
        if result.stderr.strip() and not check:
             print(f"Stderr: {result.stderr.strip()}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(command)}")
        print(f"Return code: {e.returncode}")
        if e.stdout: print(f"Stdout: {e.stdout.strip()}")
        if e.stderr: print(f"Stderr: {e.stderr.strip()}")
        if check: raise
        return None
    except subprocess.TimeoutExpired:
        print(f"Timeout executing command: {' '.join(command)}")
        if check: raise
        return None
    except FileNotFoundError:
        print(f"Error: Command '{command[0]}' not found. Is it installed and in PATH?")
        if check: raise
        return None

def get_wifi_interface_name():
    global WIFI_IFACE
    if WIFI_IFACE:
        return WIFI_IFACE
    try:
        output = run_command(["iw", "dev"], check=False)
        if output:
            for line in output.splitlines():
                if line.strip().startswith("Interface"):
                    WIFI_IFACE = line.split("Interface")[1].strip()
                    print(f"Auto-detected WiFi interface using 'iw dev': {WIFI_IFACE}")
                    return WIFI_IFACE
        
        output = run_command(["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"], check=False)
        if output:
            for line in output.splitlines():
                if ":wifi" in line:
                    WIFI_IFACE = line.split(":")[0]
                    print(f"Auto-detected WiFi interface using 'nmcli': {WIFI_IFACE}")
                    return WIFI_IFACE
    except Exception as e:
        print(f"Could not auto-detect WiFi interface: {e}")

    if not WIFI_IFACE:
        print("ERROR: No WiFi interface could be auto-detected. Please set WIFI_IFACE manually in the script.")
        return None
    return WIFI_IFACE


def check_internet_connection(iface):
    if not iface: return False

    # Check NetworkManager's general status.
    # "full" means link and IP are likely okay, but internet access is not guaranteed.
    # "limited" or "none" often means no internet.
    # We use this as an early indicator but will always proceed to more robust checks
    # unless connectivity is clearly "none".
    try:
        status_output = run_command(["nmcli", "general", "status"], timeout=5, check=True)
        if status_output:
            # Extract the first line which contains the connectivity state
            first_line = status_output.splitlines()[0] if status_output.splitlines() else ""
            print(f"NetworkManager general status: {first_line}")
            if "connectivity: none" in first_line:
                print("NetworkManager reports no connectivity. Internet check failed.")
                return False
            # If "full", "limited", or "portal", we still need to verify actual internet.
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print("Could not get NetworkManager general status or command failed. Proceeding with ping/HTTP checks.")
    except Exception as e:
        print(f"Error during nmcli general status check: {e}. Proceeding with ping/HTTP checks.")

    print("Attempting robust internet checks (ping and HTTP)...")

    # Ping check
    ping_targets = ["8.8.8.8", "1.1.1.1"] # Reliable public DNS servers
    ping_successful_for_any_target = False
    for target_ip in ping_targets:
        try:
            # Send 1 ping packet, wait up to 2 seconds for a reply. Command timeout 3s.
            run_command(["ping", "-I", iface, "-c", "1", "-W", "2", target_ip], check=True, timeout=3)
            print(f"Ping to {target_ip} successful.")
            ping_successful_for_any_target = True
            break # Exit loop if one target is reachable
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            print(f"Ping to {target_ip} failed.")
        except Exception as e: # Catch other potential errors like FileNotFoundError for ping
            print(f"Unexpected error during ping to {target_ip}: {e}")
            # Continue to next target or fail if this was the last one

    if not ping_successful_for_any_target:
        print("All ping targets failed. Internet connection likely down.")
        return False

    # HTTP check (only if at least one ping was successful)
    try:
        # Google's generate_204 is a standard check; it should return HTTP 204 No Content.
        response = requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=5)
        if response.status_code == 204:
            print("HTTP check to Google's connectivity endpoint successful (204 No Content). Internet confirmed.")
            return True
        else:
            print(f"HTTP check to Google's connectivity endpoint returned status {response.status_code} (expected 204). Internet not confirmed.")
            return False
    except requests.exceptions.RequestException as e:
        print(f"HTTP check failed: {e}")
        return False

    # Should not be reached if logic above is correct, but as a fallback:
    return False

dnsmasq_process = None # Global variable to hold the dnsmasq subprocess
DNSMASQ_LOG_LINES = [] # Store recent dnsmasq log lines

def start_access_point_manual_ip(iface):
    """Starts the AP using nmcli with manual IP, no shared/internal dnsmasq."""
    print(f"Attempting to start AP (Manual IP): {AP_SSID} on {iface}")
    if not iface: return False
    try:
        run_command(["nmcli", "radio", "wifi", "on"], check=False)
        run_command(["nmcli", "device", "set", iface, "managed", "yes"], check=False)
        run_command(["nmcli", "device", "disconnect", iface], check=False)
        time.sleep(1)
        run_command(["nmcli", "connection", "delete", AP_CONNECTION_NAME], check=False)
        time.sleep(1)

        print(f"Creating AP connection profile '{AP_CONNECTION_NAME}' with manual IP...")
        cmd_add_ap = [
            "nmcli", "connection", "add", "type", "wifi", "ifname", iface,
            "con-name", AP_CONNECTION_NAME, "autoconnect", "no", "ssid", AP_SSID,
            "mode", "ap", "802-11-wireless.band", "bg",
            "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", AP_PSK,
            "ipv4.method", "manual", "ipv4.addresses", f"{AP_IP_ADDRESS}/24"
        ]
        run_command(cmd_add_ap)
        time.sleep(1)

        print(f"Activating AP connection '{AP_CONNECTION_NAME}'...")
        run_command(["nmcli", "connection", "up", AP_CONNECTION_NAME])
        # time.sleep(3) # Replaced by a more robust IP check

        print(f"Verifying IP address {AP_IP_ADDRESS} on interface {iface}...")
        ip_assigned_successfully = False
        # Check for up to 10 seconds for the IP to be assigned
        for i in range(10): 
            # Use check=False as 'ip addr show' might return non-zero if IP not yet assigned or iface is briefly down
            # A short timeout for the command itself is also good.
            ip_output = run_command(["ip", "-4", "addr", "show", iface], check=False, timeout=3)
            if ip_output and AP_IP_ADDRESS in ip_output:
                print(f"IP address {AP_IP_ADDRESS} confirmed on {iface}.")
                ip_assigned_successfully = True
                break
            else:
                print(f"Attempt {i+1}/10: IP address {AP_IP_ADDRESS} not yet found on {iface}. Waiting 1s...")
                time.sleep(1)
        
        if not ip_assigned_successfully:
            print(f"CRITICAL: Failed to confirm IP address {AP_IP_ADDRESS} on {iface} after AP activation. dnsmasq will likely fail.")
            return False # This will trigger cleanup and retry logic in main loop
        return True
    except Exception as e:
        print(f"Failed to start AP (manual IP setup): {e}")
        run_command(["nmcli", "connection", "delete", AP_CONNECTION_NAME], check=False)
        return False

def stop_access_point(iface):
    print(f"Stopping AP '{AP_CONNECTION_NAME}'...")
    if not iface: return True
    try:
        run_command(["nmcli", "connection", "down", AP_CONNECTION_NAME], check=False, timeout=10)
        run_command(["nmcli", "connection", "delete", AP_CONNECTION_NAME], check=False, timeout=10)
        
        iptables_cmd_delete = ["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{AP_IP_ADDRESS}:{FLASK_PORT}"]
        run_command(iptables_cmd_delete, check=False)
        print("Removed iptables port redirection rule (if it existed).")

        run_command(["nmcli", "device", "wifi", "rescan"], check=False)
        return True
    except Exception as e:
        print(f"Error stopping AP: {e}")
        return False

def start_manual_dnsmasq(iface):
    global dnsmasq_process, DNSMASQ_LOG_LINES
    DNSMASQ_LOG_LINES = [] # Clear previous logs

    print(f"Starting manual dnsmasq on {iface} ({AP_IP_ADDRESS})...")

    ip_parts = AP_IP_ADDRESS.split('.')
    if len(ip_parts) != 4:
        print(f"Invalid AP_IP_ADDRESS format: {AP_IP_ADDRESS}")
        return False
    subnet_base = ".".join(ip_parts[:3]) + "."
    
    # Try to stop potentially conflicting services
    try: 
        run_command(["sudo", "systemctl", "stop", "dnsmasq.service"], check=False)
    except Exception as e:
        print(f"Note: Could not stop system dnsmasq.service (may not be running or installed): {e}")
    try:
        run_command(["sudo", "systemctl", "stop", "systemd-resolved.service"], check=False)
        print("Attempted to stop systemd-resolved.service to free up port 53 if it was in use.")
    except Exception as e:
        print(f"Note: Could not stop systemd-resolved.service (may not be running or installed): {e}")

    try: # Kill any old instances we might have started or that conflict on the interface
        pids_output = run_command(["pgrep", "-f", f"dnsmasq.*{iface}"], check=False)
        if pids_output:
            pids = pids_output.splitlines()
            for pid in pids:
                if pid:
                    print(f"Killing existing dnsmasq process {pid} for interface {iface}")
                    run_command(["sudo", "kill", "-9", pid], check=False)
    except Exception as e:
        print(f"Error trying to kill old dnsmasq processes for {iface}: {e}")

    dnsmasq_cmd = [
        "sudo", "/usr/sbin/dnsmasq",
        "-k", # Keep running, do not fork
        "-d", # Log to stderr (DEBUG MODE - VERY VERBOSE for troubleshooting)
        "--log-dhcp", # Log DHCP transactions
        "-i", iface,
        f"--address=/#/{AP_IP_ADDRESS}",
        f"--dhcp-range={subnet_base}100,{subnet_base}200,12h",
        f"--dhcp-option=option:router,{AP_IP_ADDRESS}",
        f"--dhcp-option=option:dns-server,{AP_IP_ADDRESS}",
        "--no-resolv", # Do not use /etc/resolv.conf for upstream
        "--user=root", # Run as root to avoid chown issues for PID file
        f"--pid-file=/run/dnsmasq-manual-{iface}.pid"
    ]
    print(f"Executing manual dnsmasq command: {' '.join(dnsmasq_cmd)}")
    try:
        # Using Popen with line-buffered stderr reading is complex.
        # For now, let's check exit status and then dump stderr if it fails.
        # If it runs, the -d flag will make it log to its stderr, which won't be directly visible
        # unless we read it asynchronously or it crashes.
        # A simpler approach for now: if it crashes, its stderr will be available via communicate().
        dnsmasq_process = subprocess.Popen(dnsmasq_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
        
        time.sleep(2) # Give dnsmasq a moment to start and potentially fail or log initial messages

        if dnsmasq_process.poll() is not None: # Check if it exited immediately
            print("CRITICAL: Manual dnsmasq process exited prematurely.")
            # Capture all output
            stdout, stderr = dnsmasq_process.communicate(timeout=5) 
            if stdout: 
                print(f"dnsmasq stdout:\n{stdout}")
                DNSMASQ_LOG_LINES.extend(stdout.splitlines())
            if stderr: 
                print(f"dnsmasq stderr (this should contain debug info):\n{stderr}")
                DNSMASQ_LOG_LINES.extend(stderr.splitlines())
            dnsmasq_process = None
            return False
        
        print("Manual dnsmasq process appears to be running. The -d flag means it will log verbosely to its stderr.")
        print("If captive portal issues persist, check system logs for dnsmasq or stop this script and run the dnsmasq command manually in a terminal to see live output.")
        return True
    except subprocess.TimeoutExpired: # From communicate() if poll() was not None
        print("CRITICAL: Timeout while trying to get output from (likely failed) dnsmasq process.")
        if dnsmasq_process:
            dnsmasq_process.kill() # Ensure it's killed
            # Try to get any remaining output
            stdout, stderr = dnsmasq_process.communicate()
            if stdout: print(f"dnsmasq stdout (on timeout kill):\n{stdout}")
            if stderr: print(f"dnsmasq stderr (on timeout kill):\n{stderr}")
        dnsmasq_process = None
        return False
    except Exception as e:
        print(f"CRITICAL: Exception during manual dnsmasq startup: {e}")
        if dnsmasq_process and dnsmasq_process.poll() is None: # If it's still running despite exception
            dnsmasq_process.kill()
        # Attempt to get output if Popen object exists
        if dnsmasq_process:
            stdout, stderr = dnsmasq_process.communicate(timeout=2) # Try to get output
            if stdout: print(f"dnsmasq stdout (on exception):\n{stdout}")
            if stderr: print(f"dnsmasq stderr (on exception):\n{stderr}")
        dnsmasq_process = None
        return False

def stop_manual_dnsmasq():
    global dnsmasq_process
    if dnsmasq_process:
        print("Stopping manual dnsmasq process...")
        try:
            # dnsmasq_process.terminate() # Send SIGTERM
            # dnsmasq is often run as root, so we need sudo to kill it by PID
            pid_file_path = f"/run/dnsmasq-manual-{get_wifi_interface_name()}.pid" # Assuming WIFI_IFACE is set
            if os.path.exists(pid_file_path):
                with open(pid_file_path, 'r') as f:
                    pid = f.read().strip()
                if pid:
                    print(f"Found PID {pid} from {pid_file_path}. Attempting to kill...")
                    run_command(["sudo", "kill", pid], check=False) # SIGTERM
                    time.sleep(1)
                    run_command(["sudo", "kill", "-0", pid], check=False) # Check if process still exists
                    # If it still exists, SIGKILL
                    if run_command(["pgrep", "-f", f"dnsmasq.*{get_wifi_interface_name()}"], check=False): # Re-check if any dnsmasq for iface exists
                         print(f"dnsmasq (PID {pid}) did not terminate with SIGTERM, sending SIGKILL.")
                         run_command(["sudo", "kill", "-9", pid], check=False)
            else: # Fallback if PID file not found or empty
                print("PID file for manual dnsmasq not found. Attempting general terminate/kill.")
                dnsmasq_process.terminate()
                dnsmasq_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            print("dnsmasq (via Popen object) did not terminate, killing...")
            dnsmasq_process.kill()
        except Exception as e:
            print(f"Error stopping manual dnsmasq: {e}. Trying to kill any remaining dnsmasq for the interface.")
            # General cleanup for any dnsmasq on the interface
            iface = get_wifi_interface_name()
            if iface:
                pids_output = run_command(["pgrep", "-f", f"dnsmasq.*{iface}"], check=False)
                if pids_output:
                    pids = pids_output.splitlines()
                    for pid_val in pids:
                        if pid_val:
                            print(f"Force killing dnsmasq process {pid_val}")
                            run_command(["sudo", "kill", "-9", pid_val], check=False)
        finally:
            dnsmasq_process = None
            # Clean up PID file
            iface = get_wifi_interface_name()
            if iface:
                pid_file_path = f"/run/dnsmasq-manual-{iface}.pid"
                if os.path.exists(pid_file_path):
                    try:
                        run_command(["sudo", "rm", "-f", pid_file_path], check=False)
                    except Exception as e_rm:
                        print(f"Could not remove dnsmasq PID file {pid_file_path}: {e_rm}")
        print("Manual dnsmasq process stopped.")


def connect_to_target_wifi(iface, ssid, password):
    print(f"Attempting to connect to WiFi: {ssid}")
    if not iface: return False
    try:
        run_command(["nmcli", "device", "disconnect", iface], check=False, timeout=10)
        time.sleep(2)
        run_command(["nmcli", "connection", "delete", ssid], check=False, timeout=10) # Delete by SSID
        time.sleep(1)
        
        print(f"Connecting {iface} to SSID '{ssid}'...")
        cmd_connect = ["nmcli", "device", "wifi", "connect", ssid, "password", password, "ifname", iface]
        run_command(cmd_connect, timeout=45)
        
        print("Waiting for connection to establish and verify internet (up to 30s)...")
        for _ in range(6):
            time.sleep(5)
            if check_internet_connection(iface):
                print(f"Successfully connected to {ssid} and internet access verified.")
                return True
        
        print(f"Connected to {ssid} but failed to verify internet access after timeout.")
        run_command(["nmcli", "connection", "delete", ssid], check=False) # Clean up by SSID
        return False

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"Failed to connect to {ssid} via nmcli.") # Error details already printed by run_command
        run_command(["nmcli", "connection", "delete", ssid], check=False)
        return False
    except Exception as e:
        print(f"An unexpected error occurred while trying to connect to {ssid}: {e}")
        return False

# --- Main Application Logic ---
def main():
    if os.geteuid() != 0:
        print("This script needs to be run as root (sudo). Exiting.")
        return

    current_wifi_iface = get_wifi_interface_name()
    if not current_wifi_iface:
        return

    print(f"Using WiFi interface: {current_wifi_iface}")
    print(f"Captive Portal AP will be: SSID='{AP_SSID}', Password='{AP_PSK}'")
    print(f"Captive Portal Web UI will be at: http://{AP_IP_ADDRESS}:{FLASK_PORT}")

    _credentials_store = {} 
    _credentials_event = threading.Event()
    init_flask_shared_data(_credentials_event, _credentials_store, AP_SSID)
    
    flask_server_thread = None

    try:
        while True:
            if check_internet_connection(current_wifi_iface):
                print(f"Internet connection active on {current_wifi_iface}. Monitoring...")
                time.sleep(MONITOR_INTERVAL)
                continue

            # No internet connection found by the primary check.
            # Attempt to start AP mode.
            print("No internet connection detected. Starting AP mode for WiFi configuration...")
            
            _credentials_event.clear()
            _credentials_store.clear()
            ap_started_successfully = False
            dnsmasq_started_successfully = False

            if start_access_point_manual_ip(current_wifi_iface): # Try to start AP
                ap_started_successfully = True
                if start_manual_dnsmasq(current_wifi_iface): # Try to start DNS/DHCP
                    dnsmasq_started_successfully = True
                    # Add iptables rule AFTER AP and dnsmasq are up
                    iptables_cmd_delete = ["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-i", current_wifi_iface, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{AP_IP_ADDRESS}:{FLASK_PORT}"]
                    iptables_cmd_add = ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", current_wifi_iface, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{AP_IP_ADDRESS}:{FLASK_PORT}"]
                    run_command(iptables_cmd_delete, check=False)
                    run_command(iptables_cmd_add)
                    print(f"Added iptables rule: redirect port 80 on {current_wifi_iface} to {AP_IP_ADDRESS}:{FLASK_PORT}")

                    print(f"AP '{AP_SSID}' and manual dnsmasq started. Waiting for client...")
                    
                    flask_server_thread = threading.Thread(
                        target=run_flask_app_threaded,
                        args=(AP_IP_ADDRESS, FLASK_PORT),
                        daemon=True
                    )
                    flask_server_thread.start()
                    print(f"Captive portal web server running. Access at http://{AP_IP_ADDRESS}:{FLASK_PORT}")

                    credentials_received = _credentials_event.wait(timeout=600)

                    # Before stopping dnsmasq, if it's still running, let's try to grab recent stderr if any
                    if dnsmasq_process and dnsmasq_process.poll() is None:
                        # This is hard to do reliably without async I/O or threads for Popen's streams.
                        # The -d output is best viewed by running dnsmasq manually if issues persist.
                        pass

                    # Teardown AP components regardless of how we exited the wait/connection attempt
                    stop_manual_dnsmasq() # Stop dnsmasq first
                    stop_access_point(current_wifi_iface) # Then stop AP

                    if credentials_received and _credentials_store.get('ssid'):
                        print("Credentials received.")
                        target_ssid = _credentials_store['ssid']
                        target_password = _credentials_store['password']
                        time.sleep(3) # Brief pause before attempting connection
                        if connect_to_target_wifi(current_wifi_iface, target_ssid, target_password):
                            print("Successfully connected to the new WiFi network!")
                            run_command(["sudo", "systemctl", "stop", "wificonnect.service"], check=False)
                            sys.exit(0)
                        else:
                            print("Failed to connect to the new WiFi. Retrying AP mode.")
                            # Fall through to post AP mode check and retry logic
                    else:
                        if not credentials_received: print("Timed out waiting for credentials.")
                        else: print("Credentials event set, but no credentials found (or SSID missing).")
                        # Fall through to post AP mode check and retry logic

                    # --- POST AP MODE CHECK ---
                    # AP mode has ended (either by creds processing which failed, or timeout).
                    # Give NetworkManager a chance to reconnect to a known network.
                    print("AP mode ended. Checking for auto-reconnection to known networks for up to 30 seconds...")
                    reconnection_wait_total = 30  # seconds
                    reconnection_wait_interval = 5 # seconds
                    reconnected_externally = False
                    for i in range(reconnection_wait_total // reconnection_wait_interval):
                        print(f"Auto-reconnection check ({i+1}/{reconnection_wait_total // reconnection_wait_interval})...")
                        if check_internet_connection(current_wifi_iface):
                            print("Successfully reconnected to a known network with internet.")
                            reconnected_externally = True
                            break
                        if i < (reconnection_wait_total // reconnection_wait_interval) - 1: # Don't sleep after last check
                             time.sleep(reconnection_wait_interval)
                    
                    if reconnected_externally:
                        # Loop will restart, primary check_internet_connection at the top will pass.
                        print("Proceeding to monitor mode.")
                        continue # Continue to the top of the main while loop
                    else:
                        print("Failed to auto-reconnect to a known network with internet after AP mode.")
                        print(f"Will retry AP mode after a delay of {RETRY_INTERVAL_AFTER_FAIL} seconds.")
                        time.sleep(RETRY_INTERVAL_AFTER_FAIL)
                        continue # Continue to the top of the main while loop (which will likely re-enter AP)

                else: # Failed to start manual dnsmasq
                    print("Failed to start manual dnsmasq. Stopping AP and retrying.")
                    # Print any captured dnsmasq logs if it failed
                    if DNSMASQ_LOG_LINES:
                        print("Recent dnsmasq log lines during failed start attempt:")
                        for line in DNSMASQ_LOG_LINES: print(line)
                    if ap_started_successfully: # Only stop AP if it was started
                        stop_access_point(current_wifi_iface)
                    time.sleep(RETRY_INTERVAL_AFTER_FAIL)
                    continue # Continue to the top of the main while loop
            else: # Failed to start AP (manual IP)
                print("Failed to start AP (manual IP). Retrying after a delay...")
                stop_access_point(current_wifi_iface) # Attempt cleanup just in case
                time.sleep(RETRY_INTERVAL_AFTER_FAIL)
                continue # Continue to the top of the main while loop

    except KeyboardInterrupt:
        print("\nScript interrupted by user. Cleaning up...")
    finally:
        print("Performing final cleanup...")
        stop_manual_dnsmasq()
        stop_access_point(current_wifi_iface) # current_wifi_iface might be None if detection failed early
        print("Cleanup complete. Exiting.")


if __name__ == "__main__":
    main()
