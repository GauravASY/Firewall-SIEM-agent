import os
from dotenv import load_dotenv

# Unset the SSL_CERT_FILE environment variable if it's set
# This is a workaround for issues where the environment variable points to a
# non-existent file, often from a different Python/conda installation.
if "SSL_CERT_FILE" in os.environ:
    del os.environ["SSL_CERT_FILE"]

# Load environment variables from .env file
load_dotenv()

import urllib3
from helper import analyzeThreats
import json
import gradio as gr

CERTIN_LOGO = "https://www.presentations.gov.in/wp-content/uploads/2020/06/Preview-21.png"
REDHAT_LOGO = "https://www.logo.wine/a/logo/Red_Hat/Red_Hat-Logo.wine.svg"


def main():
    urllib3.disable_warnings()
    css = """
    body { background:#f7f7fb;height:100vh; width:100 vw; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color:#111; }
    .gradio-container { max-width: 100%; background:#ffffff; }
    #app-header { display:flex; align-items:center; gap:16px; border-bottom:1px solid #eee; padding-bottom:12px; margin-bottom:20px; }
    #app-header .logos { display:flex; align-items:center; gap:12px; }
    #app-header img { height:70px; width:auto; object-fit:contain; display:block; }
    #app-title { flex:4; text-align:center; font-weight:700; font-size:20px; color:#1f3a5f; }
    #summary-box { color:black !important; background:#27272a !important; border:1px solid #eee; border-radius:12px; padding:14px 16px; line-height:1.55; max-height:460px; overflow:auto; }
    .gr-code { border-radius:12px !important; border:1px solid #e5e7eb !important; }
    .gr-code>pre, .gr-code code, #summary-box pre, #summary-box code {
      background:#ffffff !important; color:#111111 !important; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace !important;
      font-size:13px !important; line-height:1.55 !important; white-space: pre-wrap !important; word-break: break-word !important;
    }
    textarea, input[type="text"] { background:#fff !important; color:#111 !important; border-radius:10px !important; border:1px solid #e5e7eb !important; }
    button { background:#1f3a5f !important; color:#fff !important; font-weight:600 !important; border-radius:10px !important; }
    """

    with gr.Blocks(css=css) as demo:
        gr.HTML(f"""
        <div id="app-header">
          <div class="logos"><img src="{CERTIN_LOGO}" alt="CERT-In"/></div>
          <div id="app-title">IPSec Tunnel-SIEM AI AGENT POC</div>
          <div class="logos"><img src="{REDHAT_LOGO}" alt="Red Hat"/></div>
        </div>
        """)

        summary_md = gr.Markdown(label="Summary", elem_id="summary-box")
        actions_code = gr.Code(label="Proposed Actions (JSON)", language="json")
        approved_code = gr.Code(label="Approved Actions (JSON)", language="json")

        summary_state = gr.State("")
        actions_state = gr.State("")

        with gr.Row():
            with gr.Column(scale=3):
                approve = gr.Textbox(placeholder="Type Y / N", label="Approval", lines=1)
               

            analyze_btn = gr.Button("Analyze System Threats", variant="primary", scale=1)
            analyze_btn.click(
                analyzeThreats,
                inputs=None,
                outputs=[summary_md, actions_code],
                api_name="analyse",
            )

    demo.launch()


if __name__ == "__main__":
    main()
