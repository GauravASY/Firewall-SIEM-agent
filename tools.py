import requests
import json
import urllib3

# Disable warnings for self-signed certificates (common in Wazuh setups)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---

LIST_PATH = "etc/lists/poc-blocklist" #relative path on Wazuh manager

tools_schema = [
    {
        "type": "function",
        "function": {
            "name": "add_ip_to_blocklist",
            "description": "Adds the specified IP address to the Wazuh blocklist file and restarts the manager.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "The IP address to allow (e.g., 192.168.1.50)."
                    },
                    "reason": {
                        "type": "string",
                        "description": "The reason for blocking this IP."
                    }
                },
                "required": ["ip_address"]
            }
        }
    }
] 

def get_token(WAZUH_URL, WAZUH_USER, WAZUH_PASS):
    """Authenticates and returns the JWT token."""
    url = f"{WAZUH_URL}/security/user/authenticate"
    response = requests.get(url, auth=(WAZUH_USER, WAZUH_PASS), verify=False)
    
    if response.status_code == 200:
        return response.json()['data']['token']
    else:
        raise Exception(f"Authentication Failed: {response.text}")

def add_ip_to_blocklist(ip_address: str, WAZUH_URL: str, WAZUH_USER: str, WAZUH_PASS: str, reason: str="Authorized by AI") -> str:
    """
    Adds the specified IP address to the Wazuh blocklist file and restarts the manager.
    Args:
        ip_address : The IP address to add.
        WAZUH_URL : The URL of the Wazuh manager.
        WAZUH_USER : The username for authentication.
        WAZUH_PASS : The password for authentication.
        reason : The reason for adding the IP. Defaults to "Authorized by AI".
    Returns:
        str: A message indicating the success or failure of the operation.
    """
    yield f"Starting process to add {ip_address} to blocklist..."
    token = get_token(WAZUH_URL, WAZUH_USER, WAZUH_PASS)
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
    
    print(f"Adding {ip_address} to blocklist...")
    upload_response = requests.put(upload_url, headers=headers, data=file_content, verify=False)
    
    if upload_response.status_code != 200:
        yield f"Error updating file: {upload_response.text}"

    # STEP 3: RESTART MANAGER
    print("Restarting Wazuh Manager to apply changes...")
    restart_url = f"{WAZUH_URL}/manager/restart"
    restart_response = requests.put(restart_url, headers=headers, verify=False)

    if restart_response.status_code == 200:
        yield "Success: IP added and Manager restarting."
    else:
        yield f"File updated, but restart failed: {restart_response.text}"