# workflow.py
from __future__ import annotations
from typing import TypedDict, List, Optional
from langgraph.graph import StateGraph, END
from models.scope import ScopeValidator
from tools.scanners import NmapScanner, GobusterScanner, FfufScanner, SQLMapScanner
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
            task['status'] = 'running'
            target = task['target']
            tool = task['tool']
            print(f"Processing {tool} on {target}")

            # Execute tool
            if tool == 'nmap':
                result = NmapScanner.run(target)
                if result.get('success'):
                    http_ports = [p for p in result.get('ports', []) 
                                if str(p.get('port')) in ['80', '443']]
                    if http_ports:
                        scheme = 'https' if '443' in http_ports else 'http'
                        base_url = f"{scheme}://{target.split('://')[-1]}"
                        new_tasks.extend([
                            {'tool': 'gobuster', 'target': base_url, 'status': 'pending', 'retries': 0},
                            {'tool': 'ffuf', 'target': base_url, 'status': 'pending', 'retries': 0}
                        ])

            elif tool == 'gobuster':
                result = GobusterScanner.run(target)
                if result.get('success'):
                    if result.get('directories'):
                        new_tasks.append({'tool': 'sqlmap', 'target': target, 'status': 'pending', 'retries': 0})
                    else:
                        state['logs'].append(f"ℹ️ No directories found at {target}")
                else:
                    state['logs'].append(f"🔴 Gobuster error: {result.get('error', 'Unknown error')}")

            # Handle other tools...
            
            # Update task status
            if result and result.get('success'):
                task['status'] = 'completed'
                state['results'].setdefault(target, {})[tool] = result
                state['logs'].append(f"✅ {tool} completed successfully")
            else:
                raise ValueError(result.get('error', 'Scan failed'))

        except Exception as e:
            task['status'] = 'failed'
            error_msg = f"❌ {tool} failed: {str(e)}"
            state['logs'].append(error_msg)
            
            # Retry logic with max 2 attempts
            if task.get('retries', 0) < 2:
                new_task = {
                    **task,
                    'status': 'pending',
                    'retries': task.get('retries', 0) + 1
                }
                new_tasks.append(new_task)
                state['logs'].append(f"🔄 Retrying {tool} (attempt {new_task['retries']})")

    # Update tasks
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
    return state  # Handled in execute_task now

# Build workflow
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