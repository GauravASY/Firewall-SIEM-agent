import requests
import json
import urllib3

# Disable warnings for self-signed certificates (common in Wazuh setups)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---

LIST_PATH = "lists/files/poc-blocklist" #relative path on Wazuh manager

tools_schema = [
    {
        "type": "function",
        "function": {
            "name": "add_ip_to_blocklist",
            "description": "Adds the specified IP address to the Wazuh blocklist file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "The IP address to block (e.g., 192.168.1.50)."
                    },
                    "reason": {
                        "type": "string",
                        "description": "The reason for blocking this IP."
                    }
                },
                "required": ["ip_address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "restart_wazuh_manager",
            "description": "Restarts the Wazuh manager.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    }
] 

def get_token(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS):
    """Authenticates and returns the JWT token."""

    url = f"{WAZUH_API_URL}/security/user/authenticate"
    response = requests.post(url, auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False)
    if response.status_code == 200:
        return response.json()['data']['token']
    else:
        raise Exception(f"Authentication Failed: {response.text}")

def add_ip_to_blocklist(ip_address: str, WAZUH_API_URL: str, WAZUH_API_USER: str, WAZUH_API_PASS: str, reason: str="Authorized by AI") -> str:
    """
    Adds the specified IP address to the Wazuh blocklist file and restarts the manager.
    Args:
        ip_address : The IP address to add.
        WAZUH_API_URL : The URL of the Wazuh manager.
        WAZUH_API_USER : The username for authentication.
        WAZUH_API_PASS : The password for authentication.
        reason : The reason for adding the IP. Defaults to "Authorized by AI".
    Returns:
        str: A message indicating the success or failure of the operation.
    """

    token = get_token(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS)
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/octet-stream' # Required for file uploads
    }

    # STEP 1: GET EXISTING CONTENT
    # We need to read the file first to append to it, otherwise we overwrite it.
    get_url = f"{WAZUH_API_URL}/{LIST_PATH}?raw=true"
    print(f"Reading existing blocklist from {LIST_PATH}...")
    
    try:
        get_response = requests.get(get_url, headers=headers, verify=False)
        if get_response.status_code == 200:
            existing_content = get_response.text
            print(f"Exisiting Content: \n {existing_content}")
        elif get_response.status_code == 404:
            # File might not exist yet, which is fine
            print("Blocklist file not found, creating new one.")
            existing_content = ""
        else:
            yield f"Error reading existing file: {get_response.text}"
            return
    except Exception as e:
        yield f"Exception reading file: {str(e)}"
        return

    # STEP 2: PREPARE THE DATA
    if ip_address in existing_content:
        yield f"### IP {ip_address} is already in the blocklist."
        return

    # Append the new IP
    # Ensure there is a newline before adding if the file is not empty and doesn't end with one
    if existing_content and not existing_content.endswith('\n'):
        existing_content += "\n"
        
    new_content = existing_content + f"{ip_address}:{reason}\n"

    # STEP 3: UPDATE THE FILE
    # query params: path to file, overwrite=true
    upload_url = f"{WAZUH_API_URL}/{LIST_PATH}?overwrite=true"
    
    print(f"Adding {ip_address} to blocklist...")
    upload_response = requests.put(upload_url, headers=headers, data=new_content, verify=False)
    
    if upload_response.status_code != 200:
        yield f"Error updating file: {upload_response.text}"
    else:
        print("-------------------\n" + upload_response.text + "\n-------------------")
        yield f"### Success: {ip_address} added to blocklist."
        

def restart_wazuh_manager(WAZUH_API_URL: str, WAZUH_API_USER: str, WAZUH_API_PASS: str) -> str:
    """
    Restarts the Wazuh Manager.
    Returns:
        str: A message indicating the success or failure of the operation.
    """   
    yield "### Starting process to restart Wazuh Manager...\n"
    restart_url = f"{WAZUH_API_URL}/manager/restart"
    token = get_token(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS)
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/octet-stream' # Required for file uploads
    }
    restart_response = requests.put(restart_url, headers=headers, verify=False)

    if restart_response.status_code == 200:
        yield "### Success: Manager restarting."
    else:
        yield f"### Manager restart failed: {restart_response.text}"