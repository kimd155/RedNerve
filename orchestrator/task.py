from dataclasses import dataclass, field
from typing import Optional
import uuid


@dataclass
class Task:
    agent: str
    action: str
    params: dict
    session_id: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    priority: int = 5
    parent_task_id: Optional[str] = None

    def to_dict(self):
        return {
            "id": self.id,
            "agent": self.agent,
            "action": self.action,
            "params": self.params,
            "priority": self.priority,
            "session_id": self.session_id,
            "parent_task_id": self.parent_task_id,
        }


@dataclass
class TaskResult:
    task_id: str
    status: str  # "success" | "failure" | "partial"
    data: dict
    summary: str
    artifacts: list = field(default_factory=list)
    subtasks: list = field(default_factory=list)

    def to_dict(self):
        return {
            "task_id": self.task_id,
            "status": self.status,
            "data": self.data,
            "summary": self.summary,
            "artifacts": self.artifacts,
            "subtasks": [s.to_dict() if hasattr(s, "to_dict") else s for s in self.subtasks],
        }
