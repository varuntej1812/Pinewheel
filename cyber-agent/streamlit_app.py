import streamlit as st
import time
import traceback
from models.scope import ScopeDefinition, ScopeValidator
from agents.workflow import app

# Initialize session state
if 'wf_state' not in st.session_state:
    st.session_state.wf_state = {
        'tasks': [],
        'results': {},
        'scope': None,
        'logs': [],
        'iteration': 0,
        'running': False
    }

# UI components
st.set_page_config(page_title="AI Cybersecurity Auditor", layout="wide")
with st.sidebar:
    # Scope configuration
    domains = st.text_input("Allowed Domains", "example.com")
    ip_ranges = st.text_input("IP Ranges", "192.168.1.0/24")
    if st.button("Set Scope"):
        scope = ScopeValidator(ScopeDefinition(
            domains=[d.strip() for d in domains.split(",")],
            ip_ranges=[r.strip() for r in ip_ranges.split(",")]
        ))
        st.session_state.wf_state['scope'] = scope
        st.success("Scope set!")

# Main interface
st.title("🛡️ AI Cybersecurity Auditor")
task_input = st.text_input("Enter task:", "Scan example.com for open ports")

# Workflow control
if st.button("Start Audit") and not st.session_state.wf_state['running']:
    target = next((p for p in task_input.split() if '.' in p), 'example.com')
    st.session_state.wf_state.update({
        'tasks': [{'tool': 'nmap', 'target': target, 'status': 'pending', 'retries': 0}],
        'running': True,
        'iteration': 0
    })
    st.rerun()

# Workflow execution
if st.session_state.wf_state['running']:
    try:
        app.invoke(st.session_state.wf_state)
        if st.session_state.wf_state['running']:
            time.sleep(1)
            st.rerun()
        else:
            st.success("✅ Audit completed!")
    except Exception as e:
        st.error(f"❌ Workflow failed: {str(e)}")
        st.code(traceback.format_exc())

# Live display
col1, col2 = st.columns(2)
with col1:
    st.subheader("Execution Logs")
    for log in st.session_state.wf_state.get('logs', []):
        st.code(log)

with col2:
    st.subheader("Scan Results")
    if st.session_state.wf_state['results']:
        for target, scans in st.session_state.wf_state['results'].items():
            with st.expander(target):
                st.json(scans)
    else:
        st.info("No results yet")