from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Optional
from models.scope import ScopeValidator
from tools.scanners import NmapScanner, GobusterScanner, FfufScanner, SQLMapScanner
import traceback
import time

MAX_ITERATIONS = 15  

class WorkflowState(TypedDict):
    tasks: List[dict]
    results: dict
    scope: Optional[ScopeValidator]
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
    print(f"\n=== ITERATION {state['iteration']} ===")
    
    if state['iteration'] > MAX_ITERATIONS:
        state['running'] = False
        state['logs'].append("🛑 Emergency stop: Max iterations reached")
        return state

    current_tasks = [t for t in state['tasks'] if t['status'] == 'pending']
    new_tasks = []
    
    for task in current_tasks:
        result = None
        try:
            # Mark as running and process
            task['status'] = 'running'
            target = task['target']
            print(f"Processing {task['tool']} on {target}")

            # Execute security tool
            if task['tool'] == 'nmap':
                result = NmapScanner.run(target)
                state['logs'].append(f"🔍 Nmap scan completed for {target}")
                
                # Only create web tasks if HTTP ports found
                if result.get('success'):
                    http_ports = [
                        p for p in result.get('ports', [])
                        if p['service'] in ['http', 'https'] 
                        or p['port'] in ['80', '443']
                    ]
                    if http_ports:
                        scheme = 'https' if 443 in [int(p['port']) for p in http_ports] else 'http'
                        base_url = f"{scheme}://{target.split('://')[-1]}"
                        new_tasks.extend([
                            {'tool': 'gobuster', 'target': base_url, 'status': 'pending', 'retries': 0},
                            {'tool': 'ffuf', 'target': base_url, 'status': 'pending', 'retries': 0}
                        ])

            elif task['tool'] == 'gobuster':
                result = GobusterScanner.run(target)
                state['logs'].append(f"📂 Gobuster completed for {target}")
                if result.get('success') and result.get('directories'):
                    new_tasks.append({'tool': 'sqlmap', 'target': target, 'status': 'pending', 'retries': 0})

            elif task['tool'] == 'ffuf':
                result = FfufScanner.run(target)
                state['logs'].append(f"🌐 FFUF completed for {target}")

            elif task['tool'] == 'sqlmap':
                result = SQLMapScanner.run(target)
                state['logs'].append(f"💉 SQLMap completed for {target}")

            # Update task status
            if result and result.get('success'):
                task['status'] = 'completed'
                state['results'].setdefault(target, {})[task['tool']] = result
            else:
                raise ValueError(result.get('error', 'Scan failed without error message'))

        except Exception as e:
            task['status'] = 'failed'
            error_msg = f"❌ {task['tool']} failed: {str(e)}"
            state['logs'].append(error_msg)
            print(f"Error: {error_msg}")

    # Update task list (remove completed, keep others + new tasks)
    state['tasks'] = [t for t in state['tasks'] if t['status'] != 'completed']
    state['tasks'].extend(new_tasks)
    
    # Update running status
    state['running'] = any(
        t['status'] in ['pending', 'running']
        for t in state['tasks']
    ) and state['iteration'] < MAX_ITERATIONS

    print(f"Next tasks: {[t['tool'] for t in state['tasks']]}")
    return state

def handle_failures(state: WorkflowState):
    for task in [t.copy() for t in state['tasks'] if t['status'] == 'failed']:
        if task.get('retries', 0) < 2:
            task['status'] = 'pending'
            task['retries'] += 1
            state['logs'].append(f"🔄 Retrying {task['tool']} (attempt {task['retries']})")
    return state

# Configure workflow
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