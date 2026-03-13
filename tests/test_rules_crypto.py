"""Tests for weak cryptography rules (PF-CRYP-002 .. PF-CRYP-005).

PF-CRYP-001 (MD5) is already tested in test_rules_injection.py.
"""

import pytest

from pathfinder.scanner import Scanner


class TestSha1Usage:
    """PF-CRYP-002: SHA1 hash usage."""

    def test_detects_hashlib_sha1(self, make_file):
        path = make_file(
            "hasher.py",
            """\
            import hashlib
            digest = hashlib.sha1(data).hexdigest()
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-CRYP-002"
        assert findings[0].cwe == 328

    def test_detects_hashlib_new_sha1(self, make_file):
        path = make_file(
            "hasher.py",
            """\
            import hashlib
            h = hashlib.new("sha1")
            h.update(data)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_sha256(self, make_file):
        path = make_file(
            "hasher.py",
            """\
            import hashlib
            digest = hashlib.sha256(data).hexdigest()
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestDesUsage:
    """PF-CRYP-003: DES/3DES usage."""

    def test_detects_des_cipher(self, make_file):
        path = make_file(
            "crypto_util.py",
            """\
            from cryptography.hazmat.primitives.ciphers import algorithms
            cipher_algo = algorithms.DES(key)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-003"])
        findings = scanner.scan_path(path)
        assert len(findings) >= 1
        assert any(f.rule_id == "PF-CRYP-003" for f in findings)

    def test_detects_triple_des(self, make_file):
        path = make_file(
            "crypto_util.py",
            """\
            from cryptography.hazmat.primitives.ciphers import algorithms
            cipher_algo = algorithms.TripleDES(key)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-003"])
        findings = scanner.scan_path(path)
        assert len(findings) >= 1

    def test_detects_des_ede3(self, make_file):
        path = make_file(
            "crypto_util.py",
            """\
            from cryptography.hazmat.primitives.ciphers import algorithms
            algo = algorithms.DES_EDE3(key)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-003"])
        findings = scanner.scan_path(path)
        assert len(findings) >= 1

    def test_safe_aes(self, make_file):
        path = make_file(
            "crypto_util.py",
            """\
            from Crypto.Cipher import AES
            cipher = AES.new(key, AES.MODE_GCM)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestRandomForCrypto:
    """PF-CRYP-004: random module in crypto context."""

    def test_detects_random_for_password(self, make_file):
        path = make_file(
            "auth.py",
            """\
            import random
            import string

            def generate_password(length=16):
                chars = string.ascii_letters + string.digits
                password = ''.join(random.choice(chars) for _ in range(length))
                return password
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-CRYP-004"
        assert findings[0].cwe == 327

    def test_detects_random_for_token(self, make_file):
        path = make_file(
            "tokens.py",
            """\
            import random

            def generate_token():
                token = random.getrandbits(128)
                return hex(token)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_random_no_crypto_context(self, make_file):
        path = make_file(
            "game.py",
            """\
            import random

            def roll_dice():
                return random.randint(1, 6)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_secrets_module(self, make_file):
        path = make_file(
            "auth.py",
            """\
            import secrets

            def generate_password(length=16):
                password = secrets.token_urlsafe(length)
                return password
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestHardcodedEncryptionKey:
    """PF-CRYP-005: Hardcoded encryption key."""

    def test_detects_encryption_key_in_python(self, make_file):
        path = make_file(
            "crypto.py",
            """\
            encryption_key = "ABCDEF1234567890ABCDEF1234567890"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-CRYP-005"
        assert findings[0].severity.name == "CRITICAL"

    def test_detects_aes_key_in_yaml(self, make_file):
        path = make_file(
            "config.yml",
            """\
            aes_key: "0123456789ABCDEF0123456789ABCDEF"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_secret_key_in_config(self, make_file):
        path = make_file(
            "app.conf",
            """\
            secret_key = "VGhpcyBpcyBhIHRlc3Qga2V5IGZvciBwYXRoZmluZGVy"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_ignores_commented_line(self, make_file):
        path = make_file(
            "crypto.py",
            """\
            # encryption_key = "ABCDEF1234567890ABCDEF1234567890"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_no_false_positive_env_var(self, make_file):
        path = make_file(
            "crypto.py",
            """\
            import os
            encryption_key = os.environ["ENCRYPTION_KEY"]
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0
