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

# Workflow execution
# In the workflow execution section:
if st.session_state.wf_state['running']:
    try:
        start_time = time.time()
        MAX_RUNTIME = 300  # 5 minutes timeout

        while st.session_state.wf_state['running']:
            # Execute with timeout controls
            app.invoke(
                st.session_state.wf_state,
                config={"recursion_limit": MAX_ITERATIONS}
            )
            
            # Force state update
            st.session_state.wf_state = dict(st.session_state.wf_state)
            
            # Check timeout
            if time.time() - start_time > MAX_RUNTIME:
                st.session_state.wf_state.update({
                    'running': False,
                    'logs': st.session_state.wf_state['logs'] + ["🛑 System timeout - audit stopped"]
                })
                break

            # Check completion
            pending_tasks = any(
                task['status'] in ['pending', 'running']
                for task in st.session_state.wf_state['tasks']
            )
            
            if not pending_tasks or st.session_state.wf_state['iteration'] >= MAX_ITERATIONS:
                st.session_state.wf_state.update({
                    'running': False,
                    'logs': st.session_state.wf_state['logs'] + ["✅ Audit completed successfully"]
                })
                break
                
            # Controlled refresh
            time.sleep(0.5)
            st.rerun()

    except Exception as e:
        st.session_state.wf_state.update({
            'running': False,
            'logs': st.session_state.wf_state['logs'] + [f"🔥 Critical failure: {str(e)}"]
        })
        st.error(f"❌ Workflow execution failed: {str(e)}")
        st.code(traceback.format_exc())

# Display panels
col1, col2 = st.columns([2, 3])

with col1:
    st.subheader("Audit Progress Logs")
    log_container = st.container(height=600)
    if st.session_state.wf_state['logs']:
        for log in reversed(st.session_state.wf_state['logs']):
            log_container.code(log, language="log")
    else:
        log_container.info("No audit logs yet")

with col2:
    st.subheader("Scan Results")
    
    if st.session_state.wf_state['results']:
        tabs = st.tabs([f"Results for {target}" for target in st.session_state.wf_state['results'].keys()])
        
        for tab, (target, results) in zip(tabs, st.session_state.wf_state['results'].items()):
            with tab:
                st.subheader(f"Scan results for {target}")
                for tool, output in results.items():
                    with st.expander(f"{tool.upper()} Results", expanded=True):
                        if isinstance(output, dict):
                            st.json(output)
                        else:
                            st.text(str(output))
    else:
        st.info("No scan results available yet. Start an audit to see results.")

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