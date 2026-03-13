"""Tests for async/sync mixing rules (PF-ASYN-001 .. PF-ASYN-005)."""

import pytest

from pathfinder.scanner import Scanner


class TestSyncCallInAsync:
    """PF-ASYN-001: Blocking call inside async def."""

    def test_detects_time_sleep_in_async(self, make_file):
        path = make_file(
            "worker.py",
            """\
            import time
            import asyncio

            async def do_work():
                time.sleep(5)
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-ASYN-001"

    def test_detects_requests_get_in_async(self, make_file):
        path = make_file(
            "fetcher.py",
            """\
            import requests

            async def fetch_data():
                resp = requests.get("http://example.com")
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_subprocess_run_in_async(self, make_file):
        path = make_file(
            "executor.py",
            """\
            import subprocess

            async def run_cmd():
                result = subprocess.run(["ls", "-la"])
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_os_system_in_async(self, make_file):
        path = make_file(
            "executor.py",
            """\
            import os

            async def run_cmd():
                os.system("ls -la")
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_in_sync_function(self, make_file):
        path = make_file(
            "worker.py",
            """\
            import time

            def do_work():
                time.sleep(5)
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_asyncio_sleep(self, make_file):
        path = make_file(
            "worker.py",
            """\
            import asyncio

            async def do_work():
                await asyncio.sleep(5)
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestMissingAwait:
    """PF-ASYN-002: Missing await on coroutine."""

    def test_detects_missing_await(self, make_file):
        path = make_file(
            "service.py",
            """\
            async def fetch_data():
                return "data"

            async def main():
                result = fetch_data()
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-ASYN-002"

    def test_safe_with_await(self, make_file):
        path = make_file(
            "service.py",
            """\
            async def fetch_data():
                return "data"

            async def main():
                result = await fetch_data()
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_no_false_positive_sync_function(self, make_file):
        path = make_file(
            "util.py",
            """\
            def compute():
                return 42

            async def main():
                result = compute()
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestBlockingIOInAsync:
    """PF-ASYN-003: open() in async def."""

    def test_detects_open_in_async(self, make_file):
        path = make_file(
            "reader.py",
            """\
            async def read_config():
                with open("config.json") as f:
                    return f.read()
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-ASYN-003"

    def test_safe_open_in_sync(self, make_file):
        path = make_file(
            "reader.py",
            """\
            def read_config():
                with open("config.json") as f:
                    return f.read()
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestCpuBoundInAsync:
    """PF-ASYN-004: CPU-heavy calls in async def."""

    def test_detects_json_loads_in_async(self, make_file):
        path = make_file(
            "processor.py",
            """\
            import json

            async def process():
                data = json.loads(big_payload)
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-ASYN-004"

    def test_detects_bcrypt_in_async(self, make_file):
        path = make_file(
            "auth.py",
            """\
            import bcrypt

            async def verify_password(pw, hashed):
                return bcrypt.checkpw(pw, hashed)
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_hashlib_pbkdf2_in_async(self, make_file):
        path = make_file(
            "auth.py",
            """\
            import hashlib

            async def derive_key():
                key = hashlib.pbkdf2_hmac("sha256", password, salt, 100000)
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_in_sync(self, make_file):
        path = make_file(
            "processor.py",
            """\
            import json

            def process():
                data = json.loads(big_payload)
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestAsyncioSleepZeroLoop:
    """PF-ASYN-005: asyncio.sleep(0) inside a loop."""

    def test_detects_sleep_zero_in_while(self, make_file):
        path = make_file(
            "poller.py",
            """\
            import asyncio

            async def poll():
                while True:
                    await asyncio.sleep(0)
                    check_status()
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-ASYN-005"

    def test_detects_sleep_zero_in_for(self, make_file):
        path = make_file(
            "batch.py",
            """\
            import asyncio

            async def process_batch(items):
                for item in items:
                    await asyncio.sleep(0)
                    process(item)
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_sleep_positive_in_loop(self, make_file):
        path = make_file(
            "poller.py",
            """\
            import asyncio

            async def poll():
                while True:
                    await asyncio.sleep(1)
                    check_status()
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_sleep_zero_outside_loop(self, make_file):
        path = make_file(
            "yielder.py",
            """\
            import asyncio

            async def do_once():
                await asyncio.sleep(0)
            """,
        )
        scanner = Scanner(selected_rules=["PF-ASYN-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0
