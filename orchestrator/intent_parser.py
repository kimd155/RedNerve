"""
Claude API intent parser — uses tool-use to get structured output.

Sends the operator's message + all findings context to Claude.
Claude responds with tool calls that map to agent actions.
"""
from __future__ import annotations

import anthropic

from config import Config
from agents.registry import registry


class IntentParser:
    def __init__(self):
        self.client = None

    def _ensure_client(self):
        if not self.client:
            self.client = anthropic.Anthropic(api_key=Config.ANTHROPIC_API_KEY)

    def _build_tools(self) -> list[dict]:
        """Build tool definitions from all registered agents."""
        return registry.get_all_tool_definitions()

    async def parse(self, message: str, system_prompt: str,
                    conversation: list[dict]) -> dict:
        """
        Parse a user message using Claude tool-use.

        Returns:
            {
                "text_response": str,      # Claude's text response to the operator
                "tool_calls": [            # Actions to dispatch to agents
                    {
                        "tool_name": str,
                        "tool_input": dict,
                        "agent": AbstractAgent,
                    },
                    ...
                ]
            }
        """
        self._ensure_client()

        tools = self._build_tools()

        # Build messages for Claude
        messages = list(conversation)
        messages.append({"role": "user", "content": message})

        response = self.client.messages.create(
            model=Config.ANTHROPIC_MODEL,
            max_tokens=4096,
            system=system_prompt,
            tools=tools,
            messages=messages,
        )

        text_response = ""
        tool_calls = []

        for block in response.content:
            if block.type == "text":
                text_response += block.text
            elif block.type == "tool_use":
                agent = registry.find_agent_for_tool(block.name)
                tool_calls.append({
                    "id": block.id,
                    "tool_name": block.name,
                    "tool_input": block.input,
                    "agent": agent,
                })

        return {
            "text_response": text_response,
            "tool_calls": tool_calls,
            "stop_reason": response.stop_reason,
        }

    async def format_results(self, tool_results: list[dict],
                             system_prompt: str,
                             conversation: list[dict],
                             original_message: str,
                             original_text: str = "") -> str:
        """
        Send tool results back to Claude to get a human-readable summary.
        """
        import json

        self._ensure_client()

        tools = self._build_tools()

        # Build the conversation with tool use and results
        messages = list(conversation)
        messages.append({"role": "user", "content": original_message})

        # Reconstruct assistant message with text + tool use blocks
        assistant_content = []
        if original_text:
            assistant_content.append({"type": "text", "text": original_text})
        for tr in tool_results:
            assistant_content.append({
                "type": "tool_use",
                "id": tr["tool_call_id"],
                "name": tr["tool_name"],
                "input": tr["tool_input"],
            })

        messages.append({"role": "assistant", "content": assistant_content})

        # Tool results as user message
        tool_result_content = []
        for tr in tool_results:
            result_str = json.dumps(tr["result"], default=str)
            # Truncate very large results to avoid token limits
            if len(result_str) > 8000:
                result_str = result_str[:8000] + '..."}'
            tool_result_content.append({
                "type": "tool_result",
                "tool_use_id": tr["tool_call_id"],
                "content": result_str,
            })

        messages.append({"role": "user", "content": tool_result_content})

        response = self.client.messages.create(
            model=Config.ANTHROPIC_MODEL,
            max_tokens=4096,
            system=system_prompt,
            tools=tools,
            messages=messages,
        )

        # Extract text from response; if Claude tries more tool calls,
        # just grab the text portion
        text = ""
        for block in response.content:
            if block.type == "text":
                text += block.text

        return text


intent_parser = IntentParser()
