

# Firewall-SIEM Agentic System

### Introduction

The **Firewall-SIEM Agentic System** is an AI-powered SOC (Security Operations Center) analyst designed to automate the detection and remediation of network threats. It integrates **Wazuh SIEM** (monitoring FortiGate firewall logs) with **Large Language Models (LLMs)** to analyze security events, provide human-readable insights, and execute automated defensive actions like IP blocking.

### Core Features

* **AI Threat Analysis:** Automatically pulls FortiGate SIEM alerts from Wazuh and uses an AI model to identify attack types (e.g., brute force, credential spraying) and severity levels.
* **Automated Remediation:** Once a threat is confirmed and approved (via a 'Y' input), the agent can automatically add offending IPs to a Wazuh blocklist and restart the Wazuh manager to apply changes.
* **Interactive UI:** A Gradio-based dark-mode dashboard for real-time monitoring, Lucene-based log querying, and one-click action execution.

### Repository Structure

* `main.py`: The entry point that launches the Gradio web interface.
* `helper.py`: Contains the logic for fetching SIEM alerts, interacting with the AI model, and orchestrating remediation workflows.
* `tools.py`: Defines the specific technical functions (tool schemas) for blocking IPs and managing the Wazuh API.
* `pyproject.toml`: Manages project dependencies including `gradio`, `requests`, and `python-dotenv`.

---

### Setup & Installation

#### 1. Prerequisites

* Python **>= 3.13**.
* A running **Wazuh** instance with API access.
* Access to an **LLM API** (compatible with the OpenAI-style schema used in the code).

#### 2. Environment Configuration

Create a `.env` file in the root directory and populate it with the following variables:

```env
# Wazuh Configuration
WAZUH_URL=<Your_Wazuh_Index_URL>
WAZUH_USER=<Wazuh_Username>
WAZUH_PASS=<Wazuh_Password>
WAZUH_API_URL=<Wazuh_API_Endpoint>
WAZUH_API_USER=<Wazuh_API_Username>
WAZUH_API_PASS=<Wazuh_API_Password>

# AI Model Configuration
LMAAS_URL=<LLM_API_Endpoint>
LMAAS_KEY=<Your_API_Key>
MODEL=<Model_Name>

```

#### 3. Install Dependencies

The project uses `uv` or `pip`. Install the required libraries:

```bash
pip install .

```

#### 4. Run the Application

Start the agentic dashboard:

```bash
python main.py

```

### Usage

1. **Analyze:** Set the number of alerts to fetch and click **"Analyze System Threats"**.
2. **Review:** Examine the "AI Analyst Insights" and the "Proposed Actions" (JSON).
3. **Approve:** To execute the suggested blocks, type **"Y"** in the "Approval Authorization" box and click **"Execute Actions"**.
