"""Base agent class for CTF-GPT specialized sub-agents."""

import re
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel

from ctfgpt.config import get_llm
from ctfgpt.mcp_client import get_mcp_client

console = Console(force_terminal=True)

class BaseAgent:
    """Base class for domain-specific agents (Recon, Exploit, etc.)."""
    
    name: str = "base"
    allowed_tools: list[str] = []
    
    def __init__(self, bb: Any):
        """
        Parameters
        ----------
        bb:
            The Blackboard instance used to share state among agents.
        """
        self.bb = bb
        self.mcp = get_mcp_client()
        self.llm = get_llm(role="planner") # Deep reasoning
        
    def is_tool_allowed(self, command: str) -> bool:
        """Check if the agent's proposed command uses a whitelisted tool."""
        # Simple extraction of the primary binary name
        binary = command.strip().split()[0].lower()
        # Allow safe read-only core utils (NO write/delete/permission tools)
        if binary in ["cat", "ls", "grep", "echo", "pwd", "curl", "wget"]:
            return True
        # Check against agent's specific whitelist
        return any(binary.startswith(t.lower()) for t in self.allowed_tools)
        
    def execute_command(self, command: str) -> dict[str, Any]:
        """Execute a command via MCP if allowed."""
        if not self.is_tool_allowed(command):
            return {"success": False, "stdout": "", "stderr": f"Error: Tool '{command.split()[0]}' is not whitelisted for the {self.name.upper()} agent."}
            
        try:
            return self.mcp.execute(command, timeout=120)
        except Exception as exc:
            return {"success": False, "stdout": "", "stderr": f"MCP execution failed: {exc}"}

    def run(self, instruction: str) -> str:
        """Run a ReAct loop tailored to this specialized agent."""
        console.print(f"  [bold magenta]🤖 [{self.name.upper()}] Agent started:[/bold magenta] {instruction}")
        
        history = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": f"Task: {instruction}\nEvidence so far:\n{self.bb.summary()}"}
        ]
        
        for step in range(5):  # Max 5 steps per agent invocation
            try:
                response = self.llm.invoke(history)
                content = response.content if hasattr(response, "content") else str(response)
            except Exception as exc:
                return f"Agent failed: {exc}"
                
            history.append({"role": "assistant", "content": content})
            
            # Check for command execution
            cmd_match = re.search(r"COMMAND:\s*(.+)", content, re.IGNORECASE)
            if cmd_match:
                command = cmd_match.group(1).strip()
                console.print(f"  [cyan][{self.name.upper()}] $ {command}[/cyan]")
                
                result = self.execute_command(command)
                output = result.get("stdout", "") or result.get("stderr", "") or "(no output)"
                
                console.print(f"  [dim]{output[:200]}{'...' if len(output) > 200 else ''}[/dim]")
                
                # Write finding to blackboard
                success = result.get("success", False)
                weight = 0.8 if success and output.strip() else 0.3
                self.bb.write_finding(
                    agent=self.name,
                    tool=command.split()[0],
                    command=command,
                    result=output,
                    weight=weight
                )
                
                history.append({"role": "user", "content": f"Observation:\n{output[:2000]}"})
                continue
                
            # Check for completion
            if "DONE" in content:
                console.print(f"  [bold green]✅ [{self.name.upper()}] Agent finished.[/bold green]")
                # Extract summary if present
                summary_match = re.search(r"SUMMARY:\s*(.+)", content, re.IGNORECASE | re.DOTALL)
                return summary_match.group(1).strip() if summary_match else "Done."
                
            history.append({"role": "user", "content": "You didn't issue a COMMAND: or say DONE. Please do one."})
            
        console.print(f"  [yellow]⚠️ [{self.name.upper()}] Agent hit max iterations.[/yellow]")
        return "Max iterations reached."

    def get_system_prompt(self) -> str:
        raise NotImplementedError("Subclasses must implement get_system_prompt()")
