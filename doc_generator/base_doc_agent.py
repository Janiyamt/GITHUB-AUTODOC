"""
BASE DOC AGENT
===============
All 6 doc generator agents inherit from this
Handles common logic:
- Receiving UKG slice
- Calling LLM
- Returning structured output
"""

import logging
from utils.llm_client import LLMClient

log = logging.getLogger(__name__)


class BaseDocAgent:
    """Base class for all 6 doc generator agents"""

    agent_name  = "BaseDocAgent"
    doc_type    = "base"

    def __init__(self):
        self.llm = LLMClient()

    def run(self, ctx) -> dict:
        """
        Main entry point called by Orchestrator

        Returns:
            dict with:
            - doc_type:  type of document
            - content:   generated markdown
            - status:    SUCCESS / FAILED
            - agent:     agent name
        """
        log.info(f"[{self.agent_name}] Starting...")

        try:
            # Build prompt from context
            system_prompt = self.get_system_prompt()
            user_prompt   = self.build_prompt(ctx)

            # Call OCI Gen AI
            content = self.llm.generate(
                system_prompt = system_prompt,
                user_prompt   = user_prompt,
                max_tokens    = 2048
            )

            log.info(f"[{self.agent_name}] ✅ Generated {len(content)} chars")

            return {
                "doc_type": self.doc_type,
                "content":  content,
                "status":   "SUCCESS",
                "agent":    self.agent_name
            }

        except Exception as e:
            log.error(f"[{self.agent_name}] ❌ Failed: {e}")
            return {
                "doc_type": self.doc_type,
                "content":  "",
                "status":   "FAILED",
                "agent":    self.agent_name,
                "error":    str(e)
            }

    def get_system_prompt(self) -> str:
        """Override in each agent"""
        return "You are a technical documentation expert."

    def build_prompt(self, ctx) -> str:
        """Override in each agent"""
        raise NotImplementedError