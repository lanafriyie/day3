# --- Colab widget setup: MUST run before the UI is built, or widgets print as ---
# --- raw text (HBox(children=(...))) instead of rendering as an actual UI.    ---
try:
    from google.colab import output as _colab_output
    _colab_output.enable_custom_widget_manager()
except ImportError:
    pass  # not running in Colab — ipywidgets should render natively (e.g. Jupyter)

import ipywidgets as widgets
from IPython.display import display, HTML
from guard_hook import check_prompt_with_hook
from secure_pipeline import call_llm, check_response  # the REAL LLM + response-check calls

# Styled UI components
title_html = HTML("<h2>🛡️ SecureAI Guard Agent: Live Protection Console</h2><p>Testing real-time prompt interception and link-cloaking defense.</p>")

chat_input = widgets.Text(
    placeholder='Type a prompt (e.g. check out bit.ly/xyz or ask a question)...',
    description='User Input:',
    layout={'width': '80%'}
)
submit_btn = widgets.Button(description='Send to Agent', button_style='primary')
output_display = widgets.Output()

def handle_submission(b):
    with output_display:
        output_display.clear_output()
        prompt_text = chat_input.value
        if not prompt_text.strip():
            print("Please enter a prompt.")
            return

        print(f"⏳ Intercepting user prompt: '{prompt_text}'...\n")

        # Stage 1: run the security hook (Guard + link-cloaking fix)
        result = check_prompt_with_hook(prompt_text, verbose=False)

        print("=== Security Telemetry ===")
        print(f"Original Guard Allowed: {result['original_guard_result'].get('allowed')}")
        print(f"Original Guard Flags:   {result['original_guard_result'].get('flags')}")

        if result['hook_findings']:
            print("\n🔗 Link Cloaking Detected & Unmasked:")
            for finding in result['hook_findings']:
                print(f"   - Target: {finding.get('resolved_url')}")
                if finding.get('heuristic_reasons'):
                    print(f"   - Heuristic Alerts: {finding.get('heuristic_reasons')}")

        print("\n" + "=" * 30)

        if not result["allowed"]:
            display(HTML("<h3 style='color:#d9534f; background-color:#f9f2f2; padding:10px; border-radius:5px;'>🚨 BLOCKED BY HOOK: Threat Mitigated!</h3>"))
            print(f"Final Flags: {result['flags']}")
            print("(The LLM was never called — blocked before it could be reached.)")
            return

        # Stage 2: REAL LLM call (this was previously a hardcoded fake string — now it's not)
        print("✅ Prompt cleared security. Calling the real LLM...\n")
        try:
            llm_reply = call_llm(prompt_text)
        except Exception as e:
            display(HTML(f"<h3 style='color:#d9534f;'>⚠️ LLM call failed</h3>"))
            print(str(e))
            return

        # Stage 3: REAL response check (Guard screens what the model said, before showing it)
        response_result = check_response(llm_reply)

        print(f"Response check — Allowed: {response_result.get('allowed')}  Flags: {response_result.get('flags')}")
        print("\n" + "=" * 30)

        if not response_result.get("allowed", True):
            display(HTML("<h3 style='color:#d9534f; background-color:#f9f2f2; padding:10px; border-radius:5px;'>🚨 LLM RESPONSE BLOCKED</h3>"))
            print(f"Reason: {response_result.get('flags')}")
        else:
            display(HTML("<h3 style='color:#5cb85c; background-color:#f2f9f2; padding:10px; border-radius:5px;'>✅ SAFE — Response from real LLM:</h3>"))
            print(llm_reply)

submit_btn.on_click(handle_submission)

display(title_html, widgets.HBox([chat_input, submit_btn]), output_display)
