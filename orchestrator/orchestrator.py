"""
Core Orchestrator — The brain of RedNerve.

Flow:
  1. Operator sends message via WebSocket
  2. Build system prompt with all findings from prior kill chain stages
  3. Send to Claude with tool definitions from all agents
  4. Claude decides what to do → returns tool calls
  5. Dispatch tool calls to agents → agents send commands to beacons
  6. Collect results → store findings → send results back to Claude
  7. Claude produces human-readable summary
  8. Emit response to operator via WebSocket
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from config import Config
from orchestrator.intent_parser import intent_parser
from orchestrator.memory import session_memory
from orchestrator.task import Task, TaskResult
from orchestrator.task_queue import TaskQueue
from services.chat_service import chat_service
from services.findings_service import findings_service
from services.log_service import log_service
from services.session_service import session_service
from database.db import async_session
from database.models import TaskRecord, gen_uuid


class CancelledError(Exception):
    pass


class Orchestrator:
    def __init__(self):
        # session_id -> asyncio.Event (set = cancelled)
        self._cancel_flags: dict[str, asyncio.Event] = {}

    def cancel(self, session_id: str):
        """Signal cancellation for the current operation on a session."""
        flag = self._cancel_flags.get(session_id)
        if flag:
            flag.set()

    def _check_cancelled(self, session_id: str):
        """Raise CancelledError if the operation was cancelled."""
        flag = self._cancel_flags.get(session_id)
        if flag and flag.is_set():
            raise CancelledError("Operation cancelled by operator")

    async def handle_message(self, session_id: str, content: str, sio=None) -> dict:
        """
        Handle an operator message end-to-end.
        Returns the final message dict to emit to the client.
        """
        # Ensure session exists
        if not session_id:
            session = await session_service.get_or_create_session()
            session_id = session["id"]

        # Check for API key before proceeding
        if not Config.ANTHROPIC_API_KEY:
            return await self._respond(
                session_id,
                "**Configuration Error**: No `ANTHROPIC_API_KEY` set. "
                "Create a `.env` file in the rednerve directory with:\n"
                "```\nANTHROPIC_API_KEY=sk-ant-...\n```\n"
                "Then restart the server.",
                sio,
            )

        # Set up cancellation flag for this session
        self._cancel_flags[session_id] = asyncio.Event()

        try:
            return await self._execute(session_id, content, sio)
        except CancelledError:
            await log_service.log("orchestrator", "Operation cancelled", session_id=session_id)
            return await self._respond(session_id, "**Operation cancelled** by operator.", sio)
        finally:
            self._cancel_flags.pop(session_id, None)

    async def _execute(self, session_id: str, content: str, sio=None) -> dict:
        await log_service.log("orchestrator", f"Received: {content[:100]}", session_id=session_id)

        # Look up session's beacon_id for scoped context
        session_info = await session_service.get_session(session_id)
        beacon_id = session_info.get("beacon_id") if session_info else None

        # Build context BEFORE storing current message (parse() appends it)
        system_prompt = await session_memory.build_system_prompt(session_id, beacon_id=beacon_id)
        conversation = await session_memory.get_conversation_context(session_id)

        # Store user message (client renders locally, no need to emit back)
        user_msg = await chat_service.add_message(session_id, "user", content)

        self._check_cancelled(session_id)

        # Parse intent with Claude
        try:
            parsed = await intent_parser.parse(content, system_prompt, conversation)
        except Exception as e:
            error_msg = f"Failed to parse intent: {str(e)}"
            await log_service.log("orchestrator", error_msg, level="error", session_id=session_id)
            return await self._respond(session_id, error_msg, sio)

        self._check_cancelled(session_id)

        # If Claude just responded with text (no tool calls), return it
        if not parsed["tool_calls"]:
            return await self._respond(session_id, parsed["text_response"], sio)

        # Dispatch tool calls to agents
        tool_results = []
        for tc in parsed["tool_calls"]:
            self._check_cancelled(session_id)

            agent = tc["agent"]
            if not agent:
                tool_results.append({
                    "tool_call_id": tc["id"],
                    "tool_name": tc["tool_name"],
                    "tool_input": tc["tool_input"],
                    "result": {"status": "failure", "error": f"No agent for tool: {tc['tool_name']}"},
                })
                continue

            # Emit agent activity to UI
            if sio:
                await sio.emit("agent_status_update", {
                    "agent_name": agent.name,
                    "status": "executing",
                    "current_task": tc["tool_name"],
                })
                await sio.emit("typing_start", {
                    "session_id": session_id,
                    "status": f"Waiting for beacon — {agent.name}:{tc['tool_name']}...",
                })

            await log_service.log(
                agent.name,
                f"Executing {tc['tool_name']} with params: {json.dumps(tc['tool_input'], default=str)[:200]}",
                session_id=session_id,
            )

            # Strip agent name prefix from tool name to get internal action
            # e.g. "recon_ad_enum_users" -> "ad_enum_users"
            action_name = tc["tool_name"]
            prefix = agent.name + "_"
            if action_name.startswith(prefix):
                action_name = action_name[len(prefix):]

            # Create task
            task = Task(
                agent=agent.name,
                action=action_name,
                params=tc["tool_input"],
                session_id=session_id,
            )

            # Store task in DB
            async with async_session() as db:
                task_record = TaskRecord(
                    id=task.id,
                    session_id=session_id,
                    beacon_id=tc["tool_input"].get("beacon_id"),
                    agent_name=agent.name,
                    action=tc["tool_name"],
                    params=tc["tool_input"],
                    status="running",
                    priority=task.priority,
                )
                db.add(task_record)
                await db.commit()

            # Execute via agent
            try:
                result = await agent.execute(task)

                self._check_cancelled(session_id)

                # Store findings from the result
                await self._store_findings(session_id, agent.name, task.id, result)

                # Update task record
                async with async_session() as db:
                    tr = await db.get(TaskRecord, task.id)
                    if tr:
                        tr.status = result.status
                        tr.result = result.data
                        tr.completed_at = datetime.now(timezone.utc)
                        await db.commit()

                tool_results.append({
                    "tool_call_id": tc["id"],
                    "tool_name": tc["tool_name"],
                    "tool_input": tc["tool_input"],
                    "result": result.to_dict(),
                })

                if sio:
                    await sio.emit("task_progress", {
                        "task_id": task.id,
                        "agent": agent.name,
                        "status": result.status,
                        "summary": result.summary,
                    })

            except CancelledError:
                # Mark task as cancelled in DB
                async with async_session() as db:
                    tr = await db.get(TaskRecord, task.id)
                    if tr:
                        tr.status = "cancelled"
                        tr.completed_at = datetime.now(timezone.utc)
                        await db.commit()
                # Reset agent status before re-raising
                if sio:
                    await sio.emit("agent_status_update", {
                        "agent_name": agent.name,
                        "status": "ready",
                        "current_task": None,
                    })
                raise

            except Exception as e:
                error = f"Agent {agent.name} failed: {str(e)}"
                await log_service.log(agent.name, error, level="error", session_id=session_id)
                tool_results.append({
                    "tool_call_id": tc["id"],
                    "tool_name": tc["tool_name"],
                    "tool_input": tc["tool_input"],
                    "result": {"status": "failure", "error": error},
                })

            # Reset agent status
            if sio:
                await sio.emit("agent_status_update", {
                    "agent_name": agent.name,
                    "status": "ready",
                    "current_task": None,
                })

        self._check_cancelled(session_id)

        # Send results back to Claude for human-readable summary
        if sio:
            await sio.emit("typing_start", {
                "session_id": session_id,
                "status": "Generating summary...",
            })
        try:
            summary = await intent_parser.format_results(
                tool_results, system_prompt, conversation, content,
                original_text=parsed.get("text_response", ""),
            )
        except Exception as e:
            # Fallback: just summarize the results ourselves
            summaries = []
            for tr in tool_results:
                r = tr["result"]
                if isinstance(r, dict):
                    summaries.append(f"**{tr['tool_name']}**: {r.get('summary', r.get('status', 'done'))}")
                else:
                    summaries.append(f"**{tr['tool_name']}**: {r}")
            summary = "\n".join(summaries)

        return await self._respond(session_id, summary, sio)

    async def _respond(self, session_id: str, content: str, sio=None) -> dict:
        """Store and return an assistant message."""
        msg = await chat_service.add_message(session_id, "assistant", content)
        return msg

    async def _store_findings(self, session_id: str, agent_name: str,
                              task_id: str, result: TaskResult):
        """Extract and store findings from a task result into the chain memory."""
        if result.status == "failure":
            return

        data = result.data
        if not isinstance(data, dict):
            return

        # The agent's result data may contain categorized findings
        # Agents should include a "findings" key with structured data
        findings_data = data.get("findings", {})

        for category, items in findings_data.items():
            if isinstance(items, list):
                for item in items:
                    key = item.get("key", item.get("name", item.get("username", str(item)[:50])))
                    await findings_service.store(
                        session_id=session_id,
                        category=category,
                        key=str(key),
                        data=item,
                        source_agent=agent_name,
                        task_id=task_id,
                    )
            elif isinstance(items, dict):
                await findings_service.store(
                    session_id=session_id,
                    category=category,
                    key=str(items.get("key", category)),
                    data=items,
                    source_agent=agent_name,
                    task_id=task_id,
                )


orchestrator = Orchestrator()
