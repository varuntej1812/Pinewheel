from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Optional
from models.scope import ScopeValidator
from tools.scanners import NmapScanner, GobusterScanner, FfufScanner, SQLMapScanner
import traceback

MAX_ITERATIONS = 25

class WorkflowState(TypedDict):
    tasks: List[dict]
    results: dict
    scope: ScopeValidator
    logs: List[str]
    iteration: int
    running: bool

def initialize_workflow(state: WorkflowState):
    state.update({
        'logs': [f"🚀 Initialized workflow with {len(state['tasks'])} tasks"],
        'results': {},
        'iteration': 0,
        'running': True
    })
    return state

def execute_task(state: WorkflowState):
    state['iteration'] += 1
    new_tasks = []

    # Safety check for maximum iterations
    if state['iteration'] > MAX_ITERATIONS:
        state['running'] = False
        state['logs'].append("⚠️ Maximum iterations reached")
        return state

    for task in [t for t in state['tasks'] if t['status'] == 'pending']:
        try:
            task['status'] = 'running'
            target = task['target']

            # Validate target format
            if not any(c in target for c in ['.', ':']):
                raise ValueError(f"Invalid target format: {target}")

            # Validate scope
            if not state['scope'].validate_target(target):
                raise PermissionError(f"Target {target} out of scope")

            # Execute security tool
            if task['tool'] == 'nmap':
                result = NmapScanner.run(target)
                state['logs'].append(f"🔍 Running nmap on {target}")

                # Process nmap results
                if 'ports' in result:
                    open_ports = [p for p in result['ports'] if p.get('state') == 'open']
                    if open_ports:
                        state['logs'].append(f"🔓 Found {len(open_ports)} open ports")
                        base_url = f"http://{target}" if not target.startswith(('http://', 'https://')) else target
                        new_tasks.extend([
                            {'tool': 'gobuster', 'target': base_url, 'status': 'pending', 'retries': 0},
                            {'tool': 'ffuf', 'target': base_url, 'status': 'pending', 'retries': 0}
                        ])

            elif task['tool'] == 'gobuster':
                result = GobusterScanner.run(target)
                state['logs'].append(f"📂 Running gobuster on {target}")
                if result.get('success'):
                    new_tasks.append({'tool': 'sqlmap', 'target': target, 'status': 'pending', 'retries': 0})

            elif task['tool'] == 'ffuf':
                result = FfufScanner.run(target)
                state['logs'].append(f"🌀 Running ffuf on {target}")

            elif task['tool'] == 'sqlmap':
                result = SQLMapScanner.run(target)
                state['logs'].append(f"💉 Running sqlmap on {target}")

            # Store results
            task['result'] = result
            task['status'] = 'completed'
            if target not in state['results']:
                state['results'][target] = {}
            state['results'][target][task['tool']] = result

        except Exception as e:
            task['status'] = 'failed'
            error_msg = f"❌ {task['tool']} failed: {str(e)}"
            state['logs'].append(error_msg)
            state['logs'].append(f"🔧 Debug: {traceback.format_exc()}")

    # Update task list and running status
    state['tasks'].extend(new_tasks)
    state['running'] = any(t['status'] in ['pending', 'running'] for t in state['tasks'])
    
    return state

def handle_failures(state: WorkflowState):
    for task in [t for t in state['tasks'] if t['status'] == 'failed']:
        if task.get('retries', 0) < 3:
            task.update({
                'status': 'pending',
                'retries': task.get('retries', 0) + 1
            })
            state['logs'].append(f"🔄 Retrying {task['tool']} (attempt {task['retries']})")
    return state

# Workflow configuration
workflow = StateGraph(WorkflowState)
workflow.add_node("init", initialize_workflow)
workflow.add_node("execute", execute_task)
workflow.add_node("retry", handle_failures)

workflow.set_entry_point("init")
workflow.add_edge("init", "execute")
workflow.add_edge("execute", "retry")
workflow.add_conditional_edges(
    "retry",
    lambda state: END if not state['running'] else "execute"
)

app = workflow.compile()