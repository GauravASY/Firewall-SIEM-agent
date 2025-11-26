import requests
import json
import urllib3

# Disable warnings for self-signed certificates (common in Wazuh setups)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
WAZUH_URL = "https://<YOUR_WAZUH_IP>:55000"
WAZUH_USER = "wazuh"
WAZUH_PASS = "wazuh"
LIST_PATH = "etc/lists/poc-allowlist"  # Relative path in Wazuh manager

def get_token():
    """Authenticates and returns the JWT token."""
    url = f"{WAZUH_URL}/security/user/authenticate"
    response = requests.get(url, auth=(WAZUH_USER, WAZUH_PASS), verify=False)
    
    if response.status_code == 200:
        return response.json()['data']['token']
    else:
        raise Exception(f"Authentication Failed: {response.text}")

def add_ip_to_allowlist(ip_address, reason="Authorized by AI"):
    """
    1. Reads current list (optional, omitted here for simplicity).
    2. Overwrites list with new data.
    3. Restarts Manager.
    """
    token = get_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/octet-stream' # Required for file uploads
    }

    # STEP 1: PREPARE THE DATA
    # For this POC, we are just writing the new IP to the file.
    file_content = f"{ip_address}:{reason}\n"

    # STEP 2: UPDATE THE FILE
    # query params: path to file, overwrite=true
    upload_url = f"{WAZUH_URL}/manager/files?path={LIST_PATH}&overwrite=true"
    
    print(f"Adding {ip_address} to allowlist...")
    upload_response = requests.put(upload_url, headers=headers, data=file_content, verify=False)
    
    if upload_response.status_code != 200:
        return f"Error updating file: {upload_response.text}"

    # STEP 3: RESTART MANAGER
    print("Restarting Wazuh Manager to apply changes...")
    restart_url = f"{WAZUH_URL}/manager/restart"
    restart_response = requests.put(restart_url, headers=headers, verify=False)

    if restart_response.status_code == 200:
        return "Success: IP added and Manager restarting."
    else:
        return f"File updated, but restart failed: {restart_response.text}"

# --- EXECUTION ---
# This is how your Agent would call the tool
result = add_ip_to_allowlist("10.0.0.50", reason="False Positive - Dev Server")
print(result)