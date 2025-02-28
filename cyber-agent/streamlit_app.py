import streamlit as st
import time
import traceback
from models.scope import ScopeDefinition, ScopeValidator
from agents.workflow import app, MAX_ITERATIONS

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
    st.header("Configuration")
    domains = st.text_input("Allowed Domains", "nmap.org")
    ip_ranges = st.text_input("IP Ranges", "192.168.1.0/24")
    if st.button("Set Audit Scope"):
        try:
            scope = ScopeValidator(ScopeDefinition(
                domains=[d.strip().lower() for d in domains.split(",")],
                ip_ranges=[r.strip() for r in ip_ranges.split(",")]
            ))
            st.session_state.wf_state['scope'] = scope
            st.success("🔒 Audit scope configured!")
        except Exception as e:
            st.error(f"❌ Invalid scope configuration: {str(e)}")

# Main interface
st.title("🛡️ AI Cybersecurity Auditor")
target_input = st.text_input("Enter target to scan:", "scanme.nmap.org")

# Workflow control
if st.button("Start Security Audit"):
    if not st.session_state.wf_state['scope']:
        st.error("⛔ Please configure audit scope first!")
        st.stop()
    
    try:
        if not st.session_state.wf_state['scope'].validate_target(target_input):
            st.error(f"❌ Target {target_input} is out of scope!")
            st.stop()
    except Exception as e:
        st.error(f"🔴 Scope validation failed: {str(e)}")
        st.stop()

    st.session_state.wf_state.update({
        'tasks': [{
            'tool': 'nmap',
            'target': target_input,
            'status': 'pending',
            'retries': 0
        }],
        'logs': ["🚀 Starting security audit workflow"],
        'results': {},
        'iteration': 0,
        'running': True
    })
    st.rerun()


if st.session_state.wf_state['running']:
    try:
        start_time = time.time()
        MAX_RUNTIME = 300  # 5 minutes
        
        while st.session_state.wf_state['running']:
            # Force state update before invocation
            st.session_state.wf_state = dict(st.session_state.wf_state)
            
            app.invoke(
                st.session_state.wf_state,
                config={"recursion_limit": MAX_ITERATIONS}
            )
            
            # Force state update after invocation
            st.session_state.wf_state = dict(st.session_state.wf_state)
            
            # Check timeout
            if time.time() - start_time > MAX_RUNTIME:
                st.session_state.wf_state['running'] = False
                st.session_state.wf_state['logs'].append("⏰ Timeout reached")
                break

            # Check completion
            pending_tasks = any(
                task['status'] in ['pending', 'running']
                for task in st.session_state.wf_state['tasks']
            )
            
            if not pending_tasks:
                st.session_state.wf_state['running'] = False
                st.session_state.wf_state['logs'].append("✅ Audit complete")
                break
                
            st.rerun()

    except Exception as e:
        st.session_state.wf_state['running'] = False
        st.error(f"Critical failure: {str(e)}")

# Display results
col1, col2 = st.columns([3, 2])

with col1:
    st.subheader("Audit Logs")
    log_container = st.container(height=400)
    for log in reversed(st.session_state.wf_state.get('logs', [])):
        log_container.markdown(f"`{log}`")

with col2:
    st.subheader("Scan Results")
    if st.session_state.wf_state['results']:
        for target, scans in st.session_state.wf_state['results'].items():
            with st.expander(f"Results for {target}", expanded=True):
                for tool, result in scans.items():
                    st.markdown(f"**{tool.upper()}**")
                    if isinstance(result, dict):
                        st.json(result)
                    else:
                        st.text(str(result))
    else:
        st.info("No results yet. Start an audit to begin scanning.")

# System status
st.sidebar.divider()
if st.session_state.wf_state['running']:
    st.sidebar.warning(f"""
    🚨 Audit in progress
    Iteration: {st.session_state.wf_state['iteration']}
    Tasks: {len(st.session_state.wf_state['tasks'])}
    """)
else:
    st.sidebar.success("System ready for new audit")