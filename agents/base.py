from abc import ABC, abstractmethod
from orchestrator.task import Task, TaskResult


class AbstractAgent(ABC):
    name: str = ""
    description: str = ""
    capabilities: list = []

    @abstractmethod
    async def execute(self, task: Task) -> TaskResult:
        """Execute a task and return structured result."""

    @abstractmethod
    def get_capabilities_manifest(self) -> dict:
        """Return capabilities for Claude tool-use schema."""

    def can_handle(self, action: str) -> bool:
        return action in self.capabilities
