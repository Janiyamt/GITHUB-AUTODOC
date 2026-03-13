import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner.pii_scanner import SecretScanner
from orchestrator.orchestrator import PipelineContext

# Create fake context
ctx = PipelineContext(
    event_id=1,
    event_type='push',
    repo_name='test/repo',
    repo_url='',
    commit_sha='abc123',
    branch='main',
    author='test',
    changed_files={
        'added': [],
        'modified': [],
        'removed': []
    },
    commits=[]
)

# Fake HIGH severity finding
from scanner.pii_scanner import SecretFinding

findings = [
    SecretFinding(
        file_path    = "api.py",
        line_number  = 5,
        secret_type  = "generic_password",
        matched_text = "password=mysecretpassword123",
        severity     = "HIGH"
    )
]

scanner = SecretScanner()
print("Sending to OCI Vault...")
vault_refs = scanner._send_to_vault(findings, ctx)
print("Vault refs:", vault_refs)