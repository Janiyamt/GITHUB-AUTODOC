"""
ORCHESTRATOR AGENT — FULL IMPLEMENTATION
==========================================
The brain of the entire pipeline.

Responsibilities (as per diagram):
1. Receives webhook event from Poller
2. Loads previous symbol table from Oracle ATP (cache)
3. Classifies the change type
4. Decides which agents to run
5. Runs Secret Scanner FIRST always
6. Runs only needed agents in parallel
7. Runs Knowledge Fusion
8. Runs 6 Doc Generator agents in parallel
9. Runs Validation
10. Saves to Oracle ATP + OCI Storage
11. Updates cache in Oracle ATP
"""

import asyncio
import json
import logging
import oracledb
import os
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)


class ChangeType:
    NEW_FEATURE   = "NEW_FEATURE"
    BUG_FIX       = "BUG_FIX"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    DOC_CHANGE    = "DOC_CHANGE"
    REFACTOR      = "REFACTOR"
    PR_MERGE      = "PR_MERGE"
    PR_OPENED     = "PR_OPENED"
    MIXED         = "MIXED"


@dataclass
class PipelineContext:
    # From webhook
    event_id:       int
    event_type:     str
    repo_name:      str
    repo_url:       str
    commit_sha:     str
    branch:         str
    author:         str
    changed_files:  dict
    commits:        list
    pr_number:      Optional[int] = None
    pr_title:       Optional[str] = None
    pr_action:      Optional[str] = None

    # Orchestrator decisions
    change_type:    Optional[str] = None
    agents_to_run:  list = field(default_factory=list)
    cache:          Optional[dict] = None

    # Agent outputs
    scan_result:    Optional[dict] = None
    ast_output:     Optional[dict] = None
    git_output:     Optional[dict] = None
    env_output:     Optional[dict] = None
    ukg:            Optional[dict] = None
    doc_outputs:    dict = field(default_factory=dict)
    validation:     Optional[dict] = None

    # Tracking
    started_at:     str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at:   Optional[str] = None
    status:         str = "STARTED"
    errors:         list = field(default_factory=list)


class OrchestratorAgent:

    CONFIG_EXTENSIONS = {".env",".yaml",".yml",".toml",".ini",".cfg",".conf","config.py","settings.py","Dockerfile","docker-compose.yml"}
    DOC_EXTENSIONS    = {".md",".rst",".txt","README","CHANGELOG","LICENSE"}
    CODE_EXTENSIONS   = {".py",".js",".ts",".java",".go",".rb",".php",".cs",".cpp",".c",".swift",".kt",".rs"}

    def __init__(self):
        self._load_agents()

    def _load_agents(self):
        from scanner.pii_scanner import SecretScanner
        from agents.ast_agent import ASTAgent
        from agents.git_agent import GitAgent
        from agents.env_agent import EnvAgent
        from fusion.knowledge_fusion import KnowledgeFusionLayer
        from doc_generator.workflow_agent import WorkflowAgent
        from doc_generator.code_doc_agent import CodeDocAgent
        from doc_generator.pr_agent import PRAgent
        from doc_generator.api_agent import APIAgent
        from doc_generator.secret_doc_agent import SecretDocAgent
        from doc_generator.pr_merge_agent import PRMergeAgent
        from validator.validator import ValidationAgent
        from storage.oracle_storage import OracleStorage

        self.scanner    = SecretScanner()
        self.ast_agent  = ASTAgent()
        self.git_agent  = GitAgent()
        self.env_agent  = EnvAgent()
        self.fusion     = KnowledgeFusionLayer()
        self.doc_agents = {
            "workflow":      WorkflowAgent(),
            "code_docs":     CodeDocAgent(),
            "pr_list":       PRAgent(),
            "api_endpoints": APIAgent(),
            "secrets_env":   SecretDocAgent(),
            "pr_merges":     PRMergeAgent(),
        }
        self.validator  = ValidationAgent()
        self.storage    = OracleStorage()

    async def run(self, event: dict) -> PipelineContext:
        ctx = self._build_context(event)
        log.info(f"[Orchestrator] {'='*50}")
        log.info(f"[Orchestrator] Event {ctx.event_id} | Repo: {ctx.repo_name} | Branch: {ctx.branch} | Author: {ctx.author}")

        try:
            # Step 1: Load cache
            log.info("[Orchestrator] Step 1: Loading cache from Oracle ATP")
            ctx = await self._load_cache(ctx)

            # Step 2: Classify change
            log.info("[Orchestrator] Step 2: Classifying change")
            ctx = self._classify_change(ctx)
            log.info(f"[Orchestrator] Change type → {ctx.change_type}")

            # Step 3: Decide agents
            log.info("[Orchestrator] Step 3: Deciding agents")
            ctx = self._decide_agents(ctx)
            log.info(f"[Orchestrator] Agents to run → {ctx.agents_to_run}")

            # Step 4: Secret Scanner (ALWAYS FIRST)
            log.info("[Orchestrator] Step 4: Secret Scanner")
            ctx = await self._run_secret_scanner(ctx)
            if ctx.status == "BLOCKED":
                log.warning("[Orchestrator] ⛔ BLOCKED — secrets found!")
                await self.storage.save(ctx)
                return ctx

            # Step 5: Parallel agents
            log.info("[Orchestrator] Step 5: Parallel agents")
            ctx = await self._run_parallel_agents(ctx)

            # Step 6: Knowledge Fusion
            log.info("[Orchestrator] Step 6: Knowledge Fusion")
            ctx = await self._run_fusion(ctx)

            # Step 7: Doc Generators
            log.info("[Orchestrator] Step 7: Doc Generators")
            ctx = await self._run_doc_generators(ctx)

            # Step 8: Validation
            log.info("[Orchestrator] Step 8: Validation")
            ctx = await self._run_validation(ctx)

            # Step 9: Storage
            log.info("[Orchestrator] Step 9: Storage")
            await self.storage.save(ctx)

            # Step 10: Update cache
            log.info("[Orchestrator] Step 10: Updating cache")
            await self._update_cache(ctx)

            ctx.status = "DONE"
            ctx.completed_at = datetime.utcnow().isoformat()
            log.info(f"[Orchestrator] ✅ Pipeline complete!")

        except Exception as e:
            ctx.status = "ERROR"
            ctx.errors.append(str(e))
            log.error(f"[Orchestrator] ❌ Failed: {e}")

        return ctx

    async def _load_cache(self, ctx):
        try:
            conn = self._get_db()
            cur = conn.cursor()
            cur.execute("""
                SELECT symbol_table, last_commit, last_processed
                FROM autodoc_cache
                WHERE repo_name = :repo_name
            """, {"repo_name": ctx.repo_name})
            row = cur.fetchone()
            if row:
                ctx.cache = {
                    "symbol_table":   json.loads(row[0]) if row[0] else {},
                    "last_commit":    row[1],
                    "last_processed": row[2]
                }
                log.info(f"[Orchestrator] Cache found — last commit: {row[1]}")
            else:
                ctx.cache = {"symbol_table": {}, "last_commit": None}
                log.info("[Orchestrator] No cache — first time processing this repo")
            cur.close()
            conn.close()
        except Exception as e:
            log.warning(f"[Orchestrator] Cache load failed (continuing): {e}")
            ctx.cache = {"symbol_table": {}, "last_commit": None}
        return ctx

    def _classify_change(self, ctx):
        if ctx.event_type == "pull_request":
            ctx.change_type = ChangeType.PR_MERGE if ctx.pr_action == "closed" else ChangeType.PR_OPENED
            return ctx

        changed = ctx.changed_files
        if isinstance(changed, str):
            changed = json.loads(changed)

        all_files = changed.get("added",[]) + changed.get("modified",[]) + changed.get("removed",[])
        if not all_files:
            ctx.change_type = ChangeType.MIXED
            return ctx

        code_files = config_files = doc_files = 0
        for f in all_files:
            ext = "." + f.split(".")[-1] if "." in f else ""
            fname = f.split("/")[-1]
            if ext in self.CODE_EXTENSIONS:     code_files += 1
            elif ext in self.CONFIG_EXTENSIONS or fname in self.CONFIG_EXTENSIONS: config_files += 1
            elif ext in self.DOC_EXTENSIONS or fname in self.DOC_EXTENSIONS:       doc_files += 1

        has_new    = len(changed.get("added",[])) > 0
        has_modify = len(changed.get("modified",[])) > 0

        if doc_files and not code_files and not config_files:
            ctx.change_type = ChangeType.DOC_CHANGE
        elif config_files and not code_files:
            ctx.change_type = ChangeType.CONFIG_CHANGE
        elif code_files and has_new and not has_modify:
            ctx.change_type = ChangeType.NEW_FEATURE
        elif code_files and has_modify and len(all_files) > 5:
            ctx.change_type = ChangeType.REFACTOR
        elif code_files and has_modify:
            ctx.change_type = ChangeType.BUG_FIX
        else:
            ctx.change_type = ChangeType.MIXED
        return ctx

    def _decide_agents(self, ctx):
        change = ctx.change_type
        if change == ChangeType.DOC_CHANGE:
            ctx.agents_to_run = []
        elif change == ChangeType.CONFIG_CHANGE:
            ctx.agents_to_run = ["env_agent"]
        elif change == ChangeType.PR_OPENED:
            ctx.agents_to_run = ["git_agent", "ast_agent"]
        elif change in [ChangeType.PR_MERGE, ChangeType.NEW_FEATURE, ChangeType.REFACTOR, ChangeType.MIXED]:
            ctx.agents_to_run = ["ast_agent", "git_agent", "env_agent"]
        elif change == ChangeType.BUG_FIX:
            ctx.agents_to_run = ["ast_agent", "git_agent"]
        else:
            ctx.agents_to_run = ["ast_agent", "git_agent", "env_agent"]
        return ctx

    async def _run_secret_scanner(self, ctx):
        try:
            result = await asyncio.to_thread(self.scanner.scan, ctx)
            ctx.scan_result = result
            if result.get("has_secrets"):
                ctx.status = "BLOCKED"
                log.warning(f"[SecretScanner] ⛔ Secrets: {result.get('secrets_found')}")
            else:
                log.info("[SecretScanner] ✅ Clean")
        except Exception as e:
            ctx.errors.append(f"SecretScanner: {e}")
        return ctx

    async def _run_parallel_agents(self, ctx):
        if not ctx.agents_to_run:
            log.info("[Orchestrator] No agents needed for this change type")
            return ctx
        tasks = {}
        if "ast_agent" in ctx.agents_to_run:
            tasks["ast_agent"] = asyncio.to_thread(self.ast_agent.run, ctx)
        if "git_agent" in ctx.agents_to_run:
            tasks["git_agent"] = asyncio.to_thread(self.git_agent.run, ctx)
        if "env_agent" in ctx.agents_to_run:
            tasks["env_agent"] = asyncio.to_thread(self.env_agent.run, ctx)

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                ctx.errors.append(f"{name}: {result}")
                log.error(f"[{name}] ❌ {result}")
            else:
                if name == "ast_agent":   ctx.ast_output = result
                elif name == "git_agent": ctx.git_output = result
                elif name == "env_agent": ctx.env_output = result
                log.info(f"[{name}] ✅ Done")
        return ctx

    async def _run_fusion(self, ctx):
        try:
            ctx.ukg = await asyncio.to_thread(self.fusion.merge, ctx)
            log.info(f"[KnowledgeFusion] ✅ {len(ctx.ukg.get('nodes',[]))} nodes")
        except Exception as e:
            ctx.errors.append(f"KnowledgeFusion: {e}")
            log.error(f"[KnowledgeFusion] ❌ {e}")
        return ctx

    async def _run_doc_generators(self, ctx):
        tasks = {name: asyncio.to_thread(agent.run, ctx) for name, agent in self.doc_agents.items()}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                ctx.errors.append(f"DocAgent[{name}]: {result}")
                log.error(f"[DocAgent:{name}] ❌ {result}")
            else:
                ctx.doc_outputs[name] = result
                log.info(f"[DocAgent:{name}] ✅ Done")
        return ctx

    async def _run_validation(self, ctx):
        try:
            ctx.validation = await asyncio.to_thread(self.validator.validate, ctx)
            log.info(f"[Validator] ✅ Score: {ctx.validation.get('score')}")
        except Exception as e:
            ctx.errors.append(f"Validator: {e}")
            log.error(f"[Validator] ❌ {e}")
        return ctx

    async def _update_cache(self, ctx):
        try:
            conn = self._get_db()
            cur = conn.cursor()
            symbol_table = ctx.ast_output.get("symbol_table", {}) if ctx.ast_output else {}
            cur.execute("""
                MERGE INTO autodoc_cache c
                USING (SELECT :repo_name AS repo_name FROM DUAL) src
                ON (c.repo_name = src.repo_name)
                WHEN MATCHED THEN
                    UPDATE SET symbol_table = :symbol_table, last_commit = :commit_sha, last_processed = SYSTIMESTAMP
                WHEN NOT MATCHED THEN
                    INSERT (repo_name, symbol_table, last_commit, last_processed)
                    VALUES (:repo_name, :symbol_table, :commit_sha, SYSTIMESTAMP)
            """, {"repo_name": ctx.repo_name, "symbol_table": json.dumps(symbol_table), "commit_sha": ctx.commit_sha})
            conn.commit()
            cur.close()
            conn.close()
            log.info(f"[Orchestrator] ✅ Cache updated")
        except Exception as e:
            log.warning(f"[Orchestrator] Cache update failed (non-critical): {e}")

    def _get_db(self):
        return oracledb.connect(
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            dsn=os.getenv("DB_DSN"),
            config_dir=os.getenv("DB_WALLET_DIR"),
            wallet_location=os.getenv("DB_WALLET_DIR"),
            wallet_password=os.getenv("DB_WALLET_PASSWORD")
        )

    def _build_context(self, event: dict) -> PipelineContext:
        changed_files = event.get("changed_files", {})
        if isinstance(changed_files, str):
            try: changed_files = json.loads(changed_files)
            except: changed_files = {}

        commits = event.get("commits", [])
        if isinstance(commits, str):
            try: commits = json.loads(commits)
            except: commits = []

        raw = event.get("raw_payload", "{}")
        if isinstance(raw, str):
            try: raw = json.loads(raw)
            except: raw = {}

        return PipelineContext(
            event_id      = event.get("id"),
            event_type    = event.get("event_type", "push"),
            repo_name     = raw.get("repository", {}).get("full_name", "unknown"),
            repo_url      = raw.get("repository", {}).get("clone_url", ""),
            commit_sha    = raw.get("after", event.get("commit_sha", "")),
            branch        = raw.get("ref", "").replace("refs/heads/", "") or event.get("branch", "main"),
            author        = raw.get("pusher", {}).get("name", event.get("author", "")),
            changed_files = changed_files,
            commits       = commits,
            pr_number     = event.get("pr_number"),
            pr_title      = event.get("pr_title"),
            pr_action     = raw.get("action"),
        )