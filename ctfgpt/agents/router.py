import re
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from ctfgpt.blackboard import Blackboard
from ctfgpt.config import get_llm
from ctfgpt.agents.recon_agent import ReconAgent
from ctfgpt.agents.exploit_agent import ExploitAgent
from ctfgpt.agents.privesc_agent import PrivEscAgent

console = Console(force_terminal=True)

class MultiAgentRouter:
    """Orchestrates the specialized sub-agents."""
    
    def __init__(self, target: str, category: str, session_id: str):
        self.target = target
        self.category = category
        self.session_id = session_id
        
        # Shared blackboard
        self.bb = Blackboard(session_id=session_id, category=category)
        
        # Instantiate agents
        self.agents = {
            "recon": ReconAgent(self.bb),
            "exploit": ExploitAgent(self.bb),
            "privesc": PrivEscAgent(self.bb),
        }
        
        self.llm = get_llm(role="planner")

    def run(self, max_handoffs: int = 5) -> str:
        """Run the multi-agent router loop."""
        
        console.print(Panel(
            f"[bold cyan]🎯 Multi-Agent Mode Started[/bold cyan]\nTarget: {self.target}\nCategory: {self.category}",
            border_style="cyan"
        ))
        
        current_task = f"Begin attacking target {self.target}."
        
        for i in range(max_handoffs):
            # 1. Router decides which agent to call
            prompt = f"""You are the CTF-GPT Router.
Target: {self.target}
Category: {self.category}

Current state of evidence:
{self.bb.summary()}

Available agents:
- RECON: Port scanning, directory brute-forcing, enumeration
- EXPLOIT: Gaining initial access, running exploits
- PRIVESC: Local privilege escalation

Based on the evidence, decide which agent should run next.
Output format:
AGENT: <agent_name>
TASK: <specific instruction for the agent>

If the root flag is found or the challenge is completely solved, output:
DONE
SUMMARY: <final summary>
"""
            try:
                response = self.llm.invoke(prompt)
                content = response.content if hasattr(response, "content") else str(response)
            except Exception as exc:
                return f"Router failed: {exc}"
                
            if re.search(r'(?m)^DONE\b', content):
                console.print("\n[bold green]🏁 Router decided the challenge is complete![/bold green]")
                return content
                
            agent_match = re.search(r"AGENT:\s*(recon|exploit|privesc)", content, re.IGNORECASE)
            task_match = re.search(r"TASK:\s*(.+?)(?:\nAGENT:|$)", content, re.IGNORECASE | re.DOTALL)
            
            if not agent_match or not task_match:
                console.print("[red]❌ Router failed to pick an agent.[/red]")
                break
                
            agent_name = agent_match.group(1).lower()
            task = task_match.group(1).strip()
            
            console.print(f"\n[bold blue]🔄 Router delegating to {agent_name.upper()}[/bold blue]")
            console.print(f"[dim]Task: {task}[/dim]\n")
            
            if agent_name not in self.agents:
                console.print(f"[red]❌ Router chose unknown agent '{agent_name}'. Valid: {list(self.agents.keys())}. Skipping.[/red]")
                continue

            # 2. Run the chosen agent
            agent = self.agents[agent_name]
            agent_result = agent.run(task)
            
            console.print(f"[dim]Agent result: {agent_result}[/dim]")
            
        return "Max handoffs reached."
