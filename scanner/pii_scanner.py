"""
SECRET / PII SCANNER - FINAL
==============================
Runs FIRST before any agent sees data.

Security Rules:
- HIGH severity → sent to OCI Vault
- Original value NEVER passed to agents
- Agents only see VAULT:ocid reference
- KEY = file:line (never the secret value!)
"""

import re
import oci
import base64
import logging
import os
import uuid
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

SECRET_PATTERNS = {
    "generic_api_key":  r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
    "generic_secret":   r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
    "generic_token":    r'(?i)(token|auth[_-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
    "generic_password": r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?',
    "private_key":      r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    "private_key_pkcs": r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
    "aws_access_key":   r'AKIA[0-9A-Z]{16}',
    "aws_secret_key":   r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
    "oci_key":          r'ocid1\.(tenancy|user|instance)\.[a-z0-9]+\.\.[a-z0-9]+',
    "db_password":      r'(?i)(db[_-]?pass|database[_-]?password)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?',
    "connection_string":r'(?i)(mongodb|postgresql|mysql|oracle):\/\/[^:]+:[^@]+@',
    "email":            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "phone_number":     r'\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    "github_token":     r'gh[pousr]_[A-Za-z0-9]{36}',
    "gitlab_token":     r'glpat-[A-Za-z0-9\-]{20}',
    "jwt_token":        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
}

SKIP_FILES = {
    ".gitignore", ".gitattributes", "package-lock.json", "yarn.lock",
    "poetry.lock", "Pipfile.lock", ".env.example", ".env.sample",
    "README.md", "CHANGELOG.md", "LICENSE", "LICENSE.md"
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
    ".tar", ".gz", ".pyc", ".pyo", ".class", ".min.js", ".min.css"
}


@dataclass
class SecretFinding:
    file_path:    str
    line_number:  int
    secret_type:  str
    matched_text: str
    severity:     str


class SecretScanner:

    HIGH_SEVERITY = {
        "private_key", "private_key_pkcs", "aws_access_key",
        "aws_secret_key", "generic_password", "db_password",
        "connection_string", "github_token", "gitlab_token", "jwt_token"
    }
    MEDIUM_SEVERITY = {
        "generic_api_key", "generic_secret", "generic_token", "oci_key"
    }
    LOW_SEVERITY = {
        "email", "phone_number"
    }

    def scan(self, ctx) -> dict:
        log.info(f"[SecretScanner] Starting scan for {ctx.repo_name}")

        all_findings  = []
        scanned_files = []
        skipped_files = []

        changed   = ctx.changed_files
        all_files = (
            changed.get("added", []) + changed.get("modified", [])
            if isinstance(changed, dict) else []
        )

        if not all_files:
            log.info("[SecretScanner] No changed files — scanning raw payload")
            all_findings.extend(self._scan_text("", "raw_payload"))
        else:
            for file_path in all_files:
                if self._should_skip(file_path):
                    skipped_files.append(file_path)
                    continue
                all_findings.extend(self._scan_text(file_path, file_path))
                scanned_files.append(file_path)

        has_high    = any(f.severity == "HIGH"   for f in all_findings)
        has_medium  = any(f.severity == "MEDIUM" for f in all_findings)
        has_secrets = has_high or has_medium

        if all_findings:
            log.warning(f"[SecretScanner] ⚠️ Found {len(all_findings)} secrets!")
            for f in all_findings:
                log.warning(f"[SecretScanner] {f.severity} | {f.secret_type} | {f.file_path}:{f.line_number}")
        else:
            log.info("[SecretScanner] ✅ Clean — no secrets found")

        result = {
            "has_secrets":      has_secrets,
            "secrets_found":    [
                {
                    "file":     f.file_path,
                    "line":     f.line_number,
                    "type":     f.secret_type,
                    "severity": f.severity,
                    "redacted": True   # actual value never included!
                }
                for f in all_findings
            ],
            "vault_references": {},
            "scanned_files":    scanned_files,
            "skipped_files":    skipped_files,
            "summary": {
                "total_files_scanned": len(scanned_files),
                "total_files_skipped": len(skipped_files),
                "total_findings":      len(all_findings),
                "high_severity":       sum(1 for f in all_findings if f.severity == "HIGH"),
                "medium_severity":     sum(1 for f in all_findings if f.severity == "MEDIUM"),
                "low_severity":        sum(1 for f in all_findings if f.severity == "LOW"),
            }
        }

        if has_high:
            log.info("[SecretScanner] Sending HIGH severity to OCI Vault")
            result["vault_references"] = self._send_to_vault(all_findings, ctx)

        log.info(f"[SecretScanner] Complete: {result['summary']}")
        return result

    def _scan_text(self, text: str, file_path: str) -> list:
        findings = []
        for secret_type, pattern in SECRET_PATTERNS.items():
            try:
                for match in re.finditer(pattern, text):
                    findings.append(SecretFinding(
                        file_path    = file_path,
                        line_number  = text[:match.start()].count('\n') + 1,
                        secret_type  = secret_type,
                        matched_text = match.group(0),
                        severity     = self._get_severity(secret_type)
                    ))
            except re.error:
                continue
        return findings

    def _get_severity(self, secret_type: str) -> str:
        if secret_type in self.HIGH_SEVERITY:   return "HIGH"
        elif secret_type in self.MEDIUM_SEVERITY: return "MEDIUM"
        else:                                     return "LOW"

    def _should_skip(self, file_path: str) -> bool:
        filename  = file_path.split("/")[-1]
        extension = "." + filename.split(".")[-1] if "." in filename else ""
        return filename in SKIP_FILES or extension in SKIP_EXTENSIONS

    def _send_to_vault(self, findings: list, ctx) -> dict:
        """
        Send HIGH severity secrets to OCI Vault
        KEY   = file:line  (NEVER the secret value!)
        VALUE = vault OCID + metadata
        Original secret cleared from memory after storing
        """
        vault_refs = {}
        try:
            oci_config   = oci.config.from_file()
            vault_client = oci.vault.VaultsClient(oci_config)

            for finding in findings:
                if finding.severity != "HIGH":
                    continue
                try:
                    # Build secret name — no actual value in name!
                    secret_name = "autodoc-" + \
                        ctx.repo_name.replace("/", "-") + "-" + \
                        finding.secret_type + "-" + \
                        str(finding.line_number) + "-" + \
                        uuid.uuid4().hex[:8]
                    secret_name = ''.join(
                        c if c.isalnum() or c == '-' else '-'
                        for c in secret_name
                    )[:255]

                    # Encode value → store in vault
                    secret_value = base64.b64encode(
                        finding.matched_text.encode()
                    ).decode()

                    response = vault_client.create_secret(
                        create_secret_details=oci.vault.models.CreateSecretDetails(
                            compartment_id = os.getenv("OCI_COMPARTMENT_ID"),
                            vault_id       = os.getenv("OCI_VAULT_ID"),
                            key_id         = os.getenv("OCI_VAULT_KEY_ID"),
                            secret_name    = secret_name,
                            secret_content = oci.vault.models.Base64SecretContentDetails(
                                content_type = "BASE64",
                                content      = secret_value
                            )
                        )
                    )

                    vault_ocid   = response.data.id
                    location_key = f"{finding.file_path}:{finding.line_number}"

                    # Store location → OCID (never secret → OCID!)
                    vault_refs[location_key] = {
                        "ocid":        vault_ocid,
                        "secret_type": finding.secret_type,
                        "severity":    finding.severity
                    }

                    # Log OCID only — NEVER log actual secret!
                    log.info(
                        f"[Vault] ✅ {finding.secret_type} @ "
                        f"{finding.file_path}:{finding.line_number} "
                        f"→ {vault_ocid}"
                    )

                    # !! Clear actual value from memory !!
                    finding.matched_text = f"VAULT:{vault_ocid}"

                except Exception as e:
                    log.error(f"[Vault] ❌ Failed: {e}")

        except Exception as e:
            log.error(f"[Vault] ❌ Connection failed: {e}")

        return vault_refs