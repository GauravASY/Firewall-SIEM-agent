import os
from dotenv import load_dotenv
import urllib3
import json
import gradio as gr
# [CHANGE] Keeping your original backend import
from helper import analyzeThreats

# Unset the SSL_CERT_FILE environment variable if it's set
if "SSL_CERT_FILE" in os.environ:
    del os.environ["SSL_CERT_FILE"]

# Load environment variables from .env file
load_dotenv()

CERTIN_LOGO = "https://www.presentations.gov.in/wp-content/uploads/2020/06/Preview-21.png"
REDHAT_LOGO = "https://www.logo.wine/a/logo/Red_Hat/Red_Hat-Logo.wine.svg"

def main():
    urllib3.disable_warnings()

    # [CHANGE] NEW CSS FROM TARGET UI (Dark Mode + Orange Accents)
    security_css = """
    /* ===== GLOBAL ===== */
    body, .gradio-container {
        background-color: #050505 !important;   /* almost pure black */
        color: #ff8c1a !important;              /* default text orange */
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    /* Headings */
    .gradio-container h1, .gradio-container h2, .gradio-container h3, .gradio-container h4 {
        color: #ff8c1a !important;
    }

    /* Normal UI text */
    .gradio-container p, .gradio-container span, label, .gr-markdown p, .gr-markdown span {
        color: #ff8c1a !important;
    }

    /* ===== PANELS (LEFT + RIGHT COLUMNS) ===== */
    .gr-column:nth-of-type(1), .gr-column:nth-of-type(2) {
        background: #0b0b0b;
        border: 1px solid #262626;
        border-radius: 10px;
        padding: 12px;
    }

    /* ===== TEXTBOXES & CODE ===== */
    .gr-textbox textarea, .gr-code pre, .gr-code code {
        background-color: #090909 !important;
        color: #ff8c1a !important;
        border: 1px solid #ff8c1a !important;
        border-radius: 6px !important;
        font-family: "JetBrains Mono", "Fira Code", monospace !important;
        font-size: 13px !important;
    }
    .gr-textbox label { color: #ffcc99 !important; font-weight: 600; }

    /* ===== TABS ===== */
    .gr-tabs > div[role="tablist"] > button {
        background-color: #050505;
        color: #ff8c1a !important;
        border: none !important;
    }
    .gr-tabs > div[role="tablist"] > button[aria-selected="true"] {
        color: #ff8c1a !important;
        border-bottom: 2px solid #ff8c1a !important;
    }
    .gr-panel, .gr-tabitem {
        background-color: #050505 !important;
        border-radius: 6px;
        color: #ff8c1a !important;
    }

    /* ===== AI SUMMARY CARD (RIGHT SIDE) ===== */
    #ai_summary_md {
        background-color: #0d1b3a !important;      /* midnight blue */
        border: 1px solid #ff8c1a !important;      /* orange border */
        border-radius: 8px;
        padding: 12px;
        margin-top: 6px;
        white-space: pre-wrap;
        font-family: "JetBrains Mono", monospace;
        font-size: 13px;
    }
    #ai_summary_md, #ai_summary_md p, #ai_summary_md span {
        color: #ffffff !important; /* White text for contrast on blue */
    }

    /* ===== SEVERITY BANNER (Visual Only) ===== */
    .sev-banner {
        display: flex; justify-content: space-between; align-items: center;
        gap: 12px; padding: 8px 10px; border-radius: 8px;
        background: linear-gradient(90deg, #111827, #020617);
        border: 1px solid #1f2937; margin-bottom: 10px;
    }
    .sev-pill {
        display: inline-flex; align-items: center; gap: 6px; padding: 2px 10px;
        border-radius: 999px; border: 1px solid #6b7280; font-size: 12px; color: #fff;
    }
    .sev-icon { width: 8px; height: 8px; border-radius: 999px; background: #eab308; }

    /* ===== BUTTON ===== */
    .gr-button {
        background: linear-gradient(90deg, #ff6b00, #ffa733) !important;
        color: #050505 !important;
        border-radius: 999px !important;
        font-weight: 700 !important;
        border: 1px solid #ff8c1a !important;
        box-shadow: 0 0 14px rgba(255, 140, 26, 0.55);
    }
    .gr-button:hover {
        filter: brightness(1.1);
        box-shadow: 0 0 22px rgba(255, 140, 26, 0.9);
    }
    """

    # [CHANGE] Using the new CSS block
    with gr.Blocks(css=security_css, title="IPSec Tunnel-SIEM AI AGENT POC") as demo:
        
        # [CHANGE] Header Layout matching Target UI (Logos in Row)
        with gr.Row():
            gr.Image(value=REDHAT_LOGO, show_label=False, interactive=False, height=60, container=False)
            gr.Image(value=CERTIN_LOGO, show_label=False, interactive=False, height=60, container=False)

        gr.Markdown(
            """
            ## 🛡️ IPSec Tunnel-SIEM AI AGENT POC
            <span style="color:#ff8c1a;">
            Analyze Wazuh SIEM alerts, generate AI insights, and perform automated remediation.
            </span>
            """
        )

        with gr.Row():
            # [CHANGE] Left Column: Inputs & Controls
            with gr.Column(scale=1):
                gr.Markdown("### ⚙️ Controls")

                #slider for the fetch size
                size = gr.Slider(
                    label="Number of alerts to fetch",
                    minimum=1,
                    maximum=200,
                    step=1,
                    value=20,
                )
                query_string = gr.Textbox(
                    label="Query String (Lucene)",
                    value="*",
                    placeholder='e.g. rule.id:(910000 OR 910010 OR 910020)',
                )
                
                # Your original input
                approve = gr.Textbox(placeholder="Type Y / N", label="Approval Authorization", lines=1)
                
                # [CHANGE] Button styled via CSS to match Target UI
                analyze_btn = gr.Button("Analyze System Threats", variant="primary")

            # [CHANGE] Right Column: Intelligence Board
            with gr.Column(scale=2):
                gr.Markdown("### 🧠 AI Analyst Insights")
                
                # [CHANGE] Visual Banner to match Target UI look (Static placeholder)
                severity_banner = gr.HTML(
                value="",
                elem_id="severity_banner",
            )

                # [CHANGE] Summary Box with specific ID for "Midnight Blue" styling
                summary_md = gr.Markdown(value="Waiting for analysis...", label="Summary", elem_id="ai_summary_md")
                
                # [CHANGE] Tabs for structured data outputs
                with gr.Tabs():
                    with gr.Tab("Proposed Actions"):
                        actions_code = gr.Code(label="Actions (JSON)", language="json")
                    with gr.Tab("Approved Actions"):
                        # Your original output placeholder
                        approved_code = gr.Code(label="Approved Actions (JSON)", language="json")

                # Your original State variables
                summary_state = gr.State("")
                actions_state = gr.State("")

        # [CHANGE] Event Wiring - keeping YOUR logic 100% intact
        # Just mapping the outputs to the new UI components
        analyze_btn.click(
            analyzeThreats,
            inputs=[size, query_string],
            outputs=[summary_md, actions_code],
            api_name="analyse",
        )

    demo.launch()

if __name__ == "__main__":
    main()