"""
WORKFLOW DOC AGENT
===================
Generates: Overall workflow of the project
- How functions connect to each other
- Entry points and triggers
- Data flow between components
- Mermaid flowchart TD diagram
Output: workflow.md
"""

from doc_generator.base_doc_agent import BaseDocAgent
import json


class WorkflowDocAgent(BaseDocAgent):

    agent_name = "WorkflowDocAgent"
    doc_type   = "workflow"

    def get_system_prompt(self) -> str:
        return """You are a senior technical architect specializing in system workflow documentation.

Your job is to write clear workflow documentation in markdown format.

STRICT RULES:
- Always include a mermaid flowchart TD diagram showing function connections
- Show how each function/component connects to others
- Show entry points and triggers clearly
- Show data flow between all components
- Use simple language anyone can understand
- Format as proper markdown with clear headings

MERMAID RULES:
- Use flowchart TD (top down) 
-It should b
- Show every major function as a node
- Show connections with arrows and labels
- Group related functions together
- Show error paths too"""

    def build_prompt(self, ctx) -> str:
        ukg = ctx.ukg if ctx.ukg else self._mock_ukg(ctx)

        return f"""Generate comprehensive workflow documentation for this repository:

Repository: {ctx.repo_name}
Branch: {ctx.branch}
Author: {ctx.author}
Change Type: {ctx.change_type}
Changed Files: {json.dumps(ctx.changed_files, indent=2)}

Code Structure:
{json.dumps(ukg, indent=2)}

Generate workflow.md with EXACTLY this structure:

# Workflow Documentation
## 1. System Overview
(2-3 sentences about what this system does)

## 2. Main Flow Diagram
```mermaid
flowchart TD
(show ALL functions and how they connect)
(show entry points)
(show data flow)
(show error paths)
```

## 3. Entry Points
(what triggers the system)

## 4. Function Connection Map
(explain how each function calls others)

## 5. Data Flow
(how data moves through the system)

## 6. Error Handling Flow
(what happens when things go wrong)"""

    def _mock_ukg(self, ctx) -> dict:
        return {
            "repo":        ctx.repo_name,
            "branch":      ctx.branch,
            "change_type": ctx.change_type,
            "functions": [
                {"name": "main",         "file": "main.py",         "calls": ["process", "validate"]},
                {"name": "process",      "file": "processor.py",    "calls": ["save"]},
                {"name": "validate",     "file": "validator.py",    "calls": []},
                {"name": "save",         "file": "storage.py",      "calls": []},
                {"name": "handle_error", "file": "main.py",         "calls": ["log_error"]}
            ],
            "files_changed": ctx.changed_files
        }