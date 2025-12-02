import requests, os, json
from tools import tools_schema, add_ip_to_blocklist, restart_wazuh_manager
import time


def checkEnvVariable(var_name):
    """Check if an environment variable is set and return its value."""
    env_var  = os.environ.get(var_name)
    if not env_var: 
        return "Missing the environment variable: " + var_name
    return env_var


def analyzeThreats(size=20, query_string="*"):
    """
    Analyzes system threats using the SIEM(Wazuh) data, generates AI insights on the basis of that data and performs actions if approved.
    This function is a generator that yields updates for the Gradio UI.
    """
    yield " ### [*] Pulling FortiGate SIEM alerts from Wazuh...", ""
    WAZUH_URL = checkEnvVariable("WAZUH_URL")
    WAZUH_USER = checkEnvVariable("WAZUH_USER")
    WAZUH_PASS = checkEnvVariable("WAZUH_PASS")
    WAZUH_API_USER = checkEnvVariable("WAZUH_API_USER")
    WAZUH_API_PASS = checkEnvVariable("WAZUH_API_PASS")
    WAZUH_API_URL = checkEnvVariable("WAZUH_API_URL")

    body = {
        "size": int(size),
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "query": {
            "query_string": {
                "query": query_string or "*"
            }
        }
    }

    resp = requests.post(
        WAZUH_URL,
        auth=(WAZUH_USER, WAZUH_PASS),
        headers={"Content-Type": "application/json"},
        json=body,
        verify=False
    )

    hits = resp.json().get("hits", {}).get("hits", [])
    events = [hit["_source"] for hit in hits]

    yield f"### [*] Pulling FortiGate SIEM alerts from Wazuh...\n ### [*] Retrieved {len(events)} events from Wazuh SIEM", ""

    # If no events, don’t bother calling AI
    if not events:
        print("[!] No FortiGate events found, exiting.")
        yield "No FortiGate events found, exiting.", ""
        return

    yield f"### [*] Pulling FortiGate SIEM alerts from Wazuh...\n ### [*] Retrieved {len(events)} events from Wazuh SIEM\n ### [*] Sending events to AI for analysis...", ""
    prompt = f"""
    You are an AI SOC Analyst.

    Here are FortiGate firewall VPN logs from a SIEM (Wazuh):

    {json.dumps(events, indent=2)}

    Your tasks:
    1. Identify attack types (brute force, scanner, credential spraying, etc.)
    2. Identify top attacker IPs and usernames.
    3. Check for SSL alerts, IPsec tunnel failures, suspicious patterns.
    4. Provide a risk score from 1 to 10.
    5. Provide recommended next actions (clear and actionable).
    6. Provide a human-readable summary for SOC team.

    Respond in JSON only with keys:
    - summary
    - top_attackers
    - targeted_users
    - attack_type
    - risk_score
    - recommendations
    """
    LMAAS_URL = checkEnvVariable("LMAAS_URL")
    LMAAS_KEY = checkEnvVariable("LMAAS_KEY")
    MODEL = checkEnvVariable("MODEL")

    yield f"### [*] Pulling FortiGate SIEM alerts from Wazuh...\n ### [*] Retrieved {len(events)} events from Wazuh SIEM\n ### [*] Sending events to AI for analysis...", ""


    ai_resp = requests.post(
        LMAAS_URL,
        headers={
            "Authorization": f"Bearer {LMAAS_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "model": MODEL,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "stream": True
        },
        verify=False,
        stream=True
    )

    full_response = ""
    # Initial message for the UI
    yield f"### [*] Pulling FortiGate SIEM alerts from Wazuh...\n ### [*] Retrieved {len(events)} events from Wazuh SIEM\n ### [*] Sending events to AI for analysis...\n ### [*] Analysing....", ""

    for line in ai_resp.iter_lines():
        if line:
            decoded_line = line.decode('utf-8')
            if decoded_line.startswith('data:'):
                data_str = decoded_line[len('data: '):].strip()

                if data_str == '[DONE]':
                    break
                try:
                    chunk = json.loads(data_str)
                    if 'choices' in chunk and len(chunk['choices']) > 0:
                        choice = chunk['choices'][0]
                        content_chunk = None
                        if 'delta' in choice and 'content' in choice['delta']:
                            content_chunk = choice['delta']['content']
                        elif 'message' in choice and 'content' in choice['message']:
                            content_chunk = choice['message']['content']
                        
                        if content_chunk:
                            full_response += content_chunk
                            # Stream the raw accumulating response to the summary box
                            yield full_response, ""
                except json.JSONDecodeError:
                    print(f"\nError decoding JSON chunk: {data_str}")


    if not full_response.strip():
        print("AI response was empty.")
        yield "AI response was empty.", ""
        return

    try:
        # The response might be wrapped in markdown JSON
        if full_response.strip().startswith("```json"):
            clean_response = full_response.strip()[7:-4]
        else:
            clean_response = full_response

        # Parse the final JSON
        data = json.loads(clean_response)

        summary = data.get("summary", "No summary provided.")
        recommendations = data.get("recommendations", [])

        # Yield the final, structured data to the UI
        yield full_response, json.dumps(recommendations, indent=2)
    
        ## Passing the Analysis to the AI model for performing actions on the Wazuh Manager if needed
        action_prompt = f"""
            Here is the threat analysis:
            {full_response}

            MANDATORY INSTRUCTION:
            - If high-risk IPs are identified in the analysis, you MUST use the `add_ip_to_blocklist` tool to block them immediately. 
            - Call the function once for each IP that needs blocking
            - Once all the high-risk IPs are blocked, use the `restart_wazuh_manager` tool to restart the Wazuh manager.
            - Do NOT just describe what to do - actually call the functions
            """
        yield full_response + "\n ### Checking if I have required tools to perform actions...", json.dumps(recommendations, indent=2)
        ai_action_resp = requests.post(
            LMAAS_URL,
            headers={
                "Authorization": f"Bearer {LMAAS_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": "You are a Security Enforcement Agent. Your job is to perform actions based on threat analysis report using the available tools."},
                    {"role": "user", "content": action_prompt}
                ],
                "temperature": 0.1,
                "tools": tools_schema,
                "tool_choice": "auto"
            },
            verify=False,
            stream=False
      )


    # Parse the response
        response_data = ai_action_resp.json()
        msg_2 = response_data['choices'][0]['message']
        print(f"=============AI Action Response Message============================\n\n {msg_2}")
        if msg_2.get('content'):
            content_str = msg_2['content']
            content_data = json.loads(content_str)
            for tool in content_data:
             #   print(f"Tool inside loop : {tool}")
                if tool['name'] == "add_ip_to_blocklist":
                    
                    # 1. Parse Args
                    args = tool['arguments']
                    target_ip = args.get('ip_address')
                    
                    yield full_response + f"\n[Action] Initiating Block for {target_ip}...", json.dumps(recommendations, indent=2)

                    # 2. THE BRIDGE (Inject Credentials)
                    action_gen = add_ip_to_blocklist(
                        ip_address=target_ip,
                        reason=args.get('reason'),
                        WAZUH_API_URL=WAZUH_API_URL,
                        WAZUH_API_USER=WAZUH_API_USER,
                        WAZUH_API_PASS=WAZUH_API_PASS
                    )

                    # 3. Stream the Tool's progress to UI
                    # The tool yields "Updating file..."
                    # We append this to the UI stream
                    tool_output_log = ""
                    for status in action_gen:
                        tool_output_log = f"\n> {status}"
                        # We keep the original text and append the tool status
                        yield full_response + tool_output_log, json.dumps(recommendations, indent=2)
                        time.sleep(1)
                elif tool['name'] == "restart_wazuh_manager":
                    action_gen = restart_wazuh_manager(
                        WAZUH_API_URL=WAZUH_API_URL,
                        WAZUH_API_USER=WAZUH_API_USER,
                        WAZUH_API_PASS=WAZUH_API_PASS
                    )
                    tool_output_log = ""
                    for status in action_gen:
                        tool_output_log = f"\n> {status}"
                        yield full_response + tool_output_log, json.dumps(recommendations, indent=2)
        else:
            yield full_response + "\n ### No automated actions required", json.dumps(recommendations, indent=2)
    

    except json.JSONDecodeError as e:
        print(f"Failed to parse the final JSON response: {e}")
        error_message = f"Error: Could not parse AI response.\n\nRaw response:\n{full_response}"
        yield error_message, ""