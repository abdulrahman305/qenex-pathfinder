"""Tests for SQL injection (PF-SQLI-*) and command injection (PF-CMDI-*) rules."""

import textwrap

import pytest

from pathfinder.scanner import Scanner


# =========================================================================
# SQL Injection
# =========================================================================


class TestSqliFString:
    """PF-SQLI-001: f-string in SQL execute."""

    def test_detects_fstring_in_execute(self, make_file):
        path = make_file(
            "db.py",
            """\
            user_id = input("ID: ")
            cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            """,
        )
        scanner = Scanner(selected_rules=["PF-SQLI-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].cwe == 89

    def test_safe_parameterized_query(self, make_file):
        path = make_file(
            "db.py",
            """\
            user_id = input("ID: ")
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            """,
        )
        scanner = Scanner(selected_rules=["PF-SQLI-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestSqliFormat:
    """PF-SQLI-002: .format() in SQL execute."""

    def test_detects_format_in_execute(self, make_file):
        path = make_file(
            "db.py",
            """\
            table = "users"
            cursor.execute("SELECT * FROM {}".format(table))
            """,
        )
        scanner = Scanner(selected_rules=["PF-SQLI-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1


class TestSqliConcat:
    """PF-SQLI-003: String concatenation in SQL."""

    def test_detects_concat_in_execute(self, make_file):
        path = make_file(
            "db.py",
            """\
            name = input("Name: ")
            cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
            """,
        )
        scanner = Scanner(selected_rules=["PF-SQLI-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1


class TestSqliSubprocess:
    """PF-SQLI-004: subprocess sqlite3 with interpolation."""

    def test_detects_subprocess_sqlite3(self, make_file):
        path = make_file(
            "migrate.py",
            """\
            import subprocess
            query = input("SQL: ")
            subprocess.run(f"sqlite3 /tmp/db.sqlite '{query}'", shell=True)
            """,
        )
        scanner = Scanner(selected_rules=["PF-SQLI-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1


# =========================================================================
# Command Injection
# =========================================================================


class TestCmdiShellTrue:
    """PF-CMDI-001: shell=True with variable input."""

    def test_detects_shell_true_with_fstring(self, make_file):
        path = make_file(
            "deploy.py",
            """\
            import subprocess
            host = input("Host: ")
            subprocess.run(f"ssh {host} ls", shell=True)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].cwe == 78

    def test_detects_shell_true_with_variable(self, make_file):
        path = make_file(
            "deploy.py",
            """\
            import subprocess
            cmd = get_command()
            subprocess.run(cmd, shell=True)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_subprocess_list_args(self, make_file):
        path = make_file(
            "deploy.py",
            """\
            import subprocess
            host = input("Host: ")
            subprocess.run(["ssh", host, "ls"])
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_shell_true_with_literal(self, make_file):
        path = make_file(
            "deploy.py",
            """\
            import subprocess
            subprocess.run("echo hello", shell=True)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestCmdiOsSystem:
    """PF-CMDI-002: os.system() call."""

    def test_detects_os_system(self, make_file):
        path = make_file(
            "admin.py",
            """\
            import os
            os.system("reboot")
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_no_false_positive_other_system(self, make_file):
        path = make_file(
            "admin.py",
            """\
            platform.system()
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestCmdiOsPopen:
    """PF-CMDI-003: os.popen() call."""

    def test_detects_os_popen(self, make_file):
        path = make_file(
            "admin.py",
            """\
            import os
            output = os.popen("ls -la").read()
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1


class TestCmdiEval:
    """PF-CMDI-004: eval() with user input."""

    def test_detects_eval_with_variable(self, make_file):
        path = make_file(
            "calc.py",
            """\
            user_input = input("Expression: ")
            result = eval(user_input)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_no_false_positive_eval_literal(self, make_file):
        path = make_file(
            "calc.py",
            """\
            result = eval("2 + 2")
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestCmdiExec:
    """PF-CMDI-005: exec() with user input."""

    def test_detects_exec_with_variable(self, make_file):
        path = make_file(
            "plugin.py",
            """\
            code = load_plugin_code()
            exec(code)
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_exec_with_fstring(self, make_file):
        path = make_file(
            "plugin.py",
            """\
            name = input("Class: ")
            exec(f"class {name}: pass")
            """,
        )
        scanner = Scanner(selected_rules=["PF-CMDI-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
