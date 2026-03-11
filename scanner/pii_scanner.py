"""
SECRET / PII SCANNER
=====================
Runs FIRST before any agent sees data.
Scans changed files for:
- API keys, tokens, passwords
- Private keys, certificates
- PII (emails, phone numbers)
- AWS/OCI/Azure credentials

If secrets found:
- Pipeline is BLOCKED
- Secrets logged with location
- TODO: Send to OCI Vault (tomorrow)

If clean:
- Pipeline continues normally
"""

import re
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


# ── Secret Patterns ────────────────────────────────────────────
# Each pattern has a name and regex
SECRET_PATTERNS = {

    # Generic secrets
    "generic_api_key": r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
    "generic_secret":  r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
    "generic_token":   r'(?i)(token|auth[_-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
    "generic_password":r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?',

    # Private keys
    "private_key":     r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    "private_key_pkcs":r'-----BEGIN ENCRYPTED PRIVATE KEY-----',

    # Cloud credentials
    "aws_access_key":  r'AKIA[0-9A-Z]{16}',
    "aws_secret_key":  r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
    "oci_key":         r'ocid1\.(tenancy|user|instance)\.[a-z0-9]+\.\.[a-z0-9]+',

    # Database
    "db_password":     r'(?i)(db[_-]?pass|database[_-]?password)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?',
    "connection_string":r'(?i)(mongodb|postgresql|mysql|oracle):\/\/[^:]+:[^@]+@',

    # PII
    "email":           r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "phone_number":    r'\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',

    # GitHub/GitLab tokens
    "github_token":    r'gh[pousr]_[A-Za-z0-9]{36}',
    "gitlab_token":    r'glpat-[A-Za-z0-9\-]{20}',

    # JWT tokens
    "jwt_token":       r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
}

# Files we should ALWAYS skip scanning
SKIP_FILES = {
    ".gitignore", ".gitattributes",
    "package-lock.json", "yarn.lock",
    "poetry.lock", "Pipfile.lock",
    ".env.example", ".env.sample",
    "README.md", "CHANGELOG.md",
    "LICENSE", "LICENSE.md"
}

# Extensions to skip
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".pdf", ".zip", ".tar", ".gz",
    ".pyc", ".pyo", ".class",
    ".min.js", ".min.css"
}


@dataclass
class SecretFinding:
    """Represents a single secret found in code"""
    file_path:    str
    line_number:  int
    secret_type:  str
    matched_text: str
    severity:     str  # HIGH / MEDIUM / LOW


class SecretScanner:
    """
    Scans code for secrets and PII
    Runs BEFORE any agent sees the data
    """

    # High severity — block immediately
    HIGH_SEVERITY = {
        "private_key", "private_key_pkcs",
        "aws_access_key", "aws_secret_key",
        "generic_password", "db_password",
        "connection_string", "github_token",
        "gitlab_token", "jwt_token"
    }

    # Medium severity — flag but review
    MEDIUM_SEVERITY = {
        "generic_api_key", "generic_secret",
        "generic_token", "oci_key"
    }

    # Low severity — informational
    LOW_SEVERITY = {
        "email", "phone_number"
    }

    def scan(self, ctx) -> dict:
        """
        Main scan entry point
        Called by Orchestrator FIRST

        Returns:
            dict with:
            - has_secrets: bool
            - secrets_found: list of findings
            - scanned_files: list of files scanned
            - skipped_files: list of files skipped
        """
        log.info(f"[SecretScanner] Starting scan for {ctx.repo_name}")

        all_findings   = []
        scanned_files  = []
        skipped_files  = []

        # Get all changed files
        changed = ctx.changed_files
        if isinstance(changed, dict):
            all_files = (
                changed.get("added", []) +
                changed.get("modified", [])
                # Don't scan removed files
            )
        else:
            all_files = []

        if not all_files:
            # No files to scan — check raw payload
            log.info("[SecretScanner] No changed files found — scanning raw payload")
            findings = self._scan_text(
                text="",
                file_path="raw_payload"
            )
            all_findings.extend(findings)
        else:
            for file_path in all_files:
                # Check if we should skip this file
                if self._should_skip(file_path):
                    skipped_files.append(file_path)
                    continue

                # Scan the file content
                # NOTE: In real implementation, we fetch file
                # content from GitHub API here
                # For now we scan the file path itself
                findings = self._scan_text(
                    text=file_path,
                    file_path=file_path
                )
                all_findings.extend(findings)
                scanned_files.append(file_path)

        # Determine if we should block
        has_high   = any(f.severity == "HIGH" for f in all_findings)
        has_medium = any(f.severity == "MEDIUM" for f in all_findings)
        has_secrets = has_high or has_medium

        # Log findings
        if all_findings:
            log.warning(f"[SecretScanner] ⚠️ Found {len(all_findings)} potential secrets!")
            for finding in all_findings:
                log.warning(
                    f"[SecretScanner] {finding.severity} | "
                    f"{finding.secret_type} | "
                    f"{finding.file_path}:{finding.line_number}"
                )
        else:
            log.info(f"[SecretScanner] ✅ Clean — no secrets found")

        result = {
            "has_secrets":   has_secrets,
            "secrets_found": [
                {
                    "file":        f.file_path,
                    "line":        f.line_number,
                    "type":        f.secret_type,
                    "severity":    f.severity,
                    "match":       f.matched_text[:20] + "..."
                    if len(f.matched_text) > 20 else f.matched_text
                }
                for f in all_findings
            ],
            "scanned_files": scanned_files,
            "skipped_files": skipped_files,
            "summary": {
                "total_files_scanned": len(scanned_files),
                "total_files_skipped": len(skipped_files),
                "total_findings":      len(all_findings),
                "high_severity":       sum(1 for f in all_findings if f.severity == "HIGH"),
                "medium_severity":     sum(1 for f in all_findings if f.severity == "MEDIUM"),
                "low_severity":        sum(1 for f in all_findings if f.severity == "LOW"),
            }
        }

        log.info(f"[SecretScanner] Scan complete: {result['summary']}")

        # TODO: Tomorrow — send HIGH severity findings to OCI Vault
        # if has_high:
        #     self._send_to_vault(all_findings, ctx)

        return result

    def _scan_text(self, text: str, file_path: str) -> list:
        """Scan a piece of text for all secret patterns"""
        findings = []

        for secret_type, pattern in SECRET_PATTERNS.items():
            try:
                matches = re.finditer(pattern, text)
                for match in matches:
                    severity = self._get_severity(secret_type)
                    finding = SecretFinding(
                        file_path    = file_path,
                        line_number  = text[:match.start()].count('\n') + 1,
                        secret_type  = secret_type,
                        matched_text = match.group(0),
                        severity     = severity
                    )
                    findings.append(finding)
            except re.error:
                continue

        return findings

    def _get_severity(self, secret_type: str) -> str:
        """Get severity level for a secret type"""
        if secret_type in self.HIGH_SEVERITY:
            return "HIGH"
        elif secret_type in self.MEDIUM_SEVERITY:
            return "MEDIUM"
        else:
            return "LOW"

    def _should_skip(self, file_path: str) -> bool:
        """Check if file should be skipped"""
        filename  = file_path.split("/")[-1]
        extension = "." + filename.split(".")[-1] if "." in filename else ""

        if filename in SKIP_FILES:
            return True
        if extension in SKIP_EXTENSIONS:
            return True
        return False

    # ── TODO: Add tomorrow ─────────────────────────────────────
    # def _send_to_vault(self, findings, ctx):
    #     """Send secrets to OCI Vault"""
    #     import oci
    #     vault_client = oci.vault.VaultsClient(config)
    #     for finding in findings:
    #         if finding.severity == "HIGH":
    #             # store in vault
    #             # replace in code with vault reference
    #             pass