from __future__ import annotations

from typing import Optional

from agents.base import AbstractAgent


class AgentRegistry:
    def __init__(self):
        self._agents: dict[str, AbstractAgent] = {}

    def register(self, agent: AbstractAgent):
        self._agents[agent.name] = agent

    def get(self, name: str) -> Optional[AbstractAgent]:
        return self._agents.get(name)

    def all(self) -> dict[str, AbstractAgent]:
        return dict(self._agents)

    def names(self) -> list[str]:
        return list(self._agents.keys())

    def get_all_manifests(self) -> list[dict]:
        manifests = []
        for agent in self._agents.values():
            manifests.append(agent.get_capabilities_manifest())
        return manifests

    def get_all_tool_definitions(self) -> list[dict]:
        tools = []
        for agent in self._agents.values():
            manifest = agent.get_capabilities_manifest()
            for tool in manifest.get("tools", []):
                tools.append(tool)
        return tools

    def find_agent_for_tool(self, tool_name: str) -> Optional[AbstractAgent]:
        for agent in self._agents.values():
            manifest = agent.get_capabilities_manifest()
            for tool in manifest.get("tools", []):
                if tool["name"] == tool_name:
                    return agent
        return None


registry = AgentRegistry()


def auto_discover():
    """Import all agent modules to trigger registration."""
    from agents.recon.agent import ReconAgent
    from agents.execution.agent import ExecutionAgent
    from agents.persistence.agent import PersistenceAgent
    from agents.intelligence.agent import IntelligenceAgent
    from agents.credential.agent import CredentialAgent
    from agents.lateral_movement.agent import LateralMovementAgent
    from agents.privilege_escalation.agent import PrivilegeEscalationAgent
    from agents.exfiltration.agent import ExfiltrationAgent
    from agents.cleanup.agent import CleanupAgent
    from agents.reporting.agent import ReportingAgent

    agents = [
        ReconAgent(),
        ExecutionAgent(),
        PersistenceAgent(),
        IntelligenceAgent(),
        CredentialAgent(),
        LateralMovementAgent(),
        PrivilegeEscalationAgent(),
        ExfiltrationAgent(),
        CleanupAgent(),
        ReportingAgent(),
    ]
    for agent in agents:
        registry.register(agent)

    return registry
