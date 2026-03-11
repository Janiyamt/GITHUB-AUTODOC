import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner.pii_scanner import SecretScanner
from orchestrator.orchestrator import PipelineContext

# Simulate a file with secrets in the text
scanner = SecretScanner()

# Test _scan_text directly with fake secrets
test_code = """
api_key = "sk-1234567890abcdefghijklmnop"
password = "mysecretpassword123"
token = "ghp_abcdefghijklmnopqrstuvwxyz123456"
email = "janiya@company.com"
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1234567890
-----END RSA PRIVATE KEY-----
"""

findings = scanner._scan_text(test_code, "fake_api.py")

print(f"\n{'='*40}")
print(f"Total findings: {len(findings)}")
print(f"{'='*40}")
for f in findings:
    print(f"❌ {f.severity} | {f.secret_type} | line {f.line_number}")
    print(f"   Match: {f.matched_text[:40]}")
print(f"{'='*40}")