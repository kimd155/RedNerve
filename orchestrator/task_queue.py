"""Priority task queue for dispatching to agents."""
from __future__ import annotations

import heapq
from orchestrator.task import Task


class TaskQueue:
    def __init__(self):
        self._queue: list[tuple[int, int, Task]] = []
        self._counter = 0

    def push(self, task: Task):
        heapq.heappush(self._queue, (task.priority, self._counter, task))
        self._counter += 1

    def pop(self) -> Task | None:
        if self._queue:
            _, _, task = heapq.heappop(self._queue)
            return task
        return None

    def is_empty(self) -> bool:
        return len(self._queue) == 0

    def size(self) -> int:
        return len(self._queue)

    def drain(self) -> list[Task]:
        tasks = []
        while not self.is_empty():
            tasks.append(self.pop())
        return tasks


task_queue = TaskQueue()
