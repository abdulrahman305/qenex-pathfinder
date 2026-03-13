"""Tests for XXE and deserialization rules (PF-XXE-001 .. PF-XXE-005)."""

import pytest

from pathfinder.scanner import Scanner


class TestXxeElementTree:
    """PF-XXE-001: Unsafe xml.etree.ElementTree import."""

    def test_detects_import_elementtree(self, make_file):
        path = make_file(
            "parser.py",
            """\
            import xml.etree.ElementTree as ET
            tree = ET.parse("data.xml")
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-XXE-001"
        assert findings[0].cwe == 611

    def test_detects_from_import_elementtree(self, make_file):
        path = make_file(
            "parser.py",
            """\
            from xml.etree.ElementTree import parse
            tree = parse("data.xml")
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_with_defusedxml(self, make_file):
        path = make_file(
            "parser.py",
            """\
            import defusedxml.ElementTree as ET
            tree = ET.parse("data.xml")
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_with_both_imports(self, make_file):
        path = make_file(
            "parser.py",
            """\
            import defusedxml
            import xml.etree.ElementTree as ET
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestXxeSax:
    """PF-XXE-002: Unsafe xml.sax import."""

    def test_detects_import_sax(self, make_file):
        path = make_file(
            "handler.py",
            """\
            import xml.sax
            parser = xml.sax.make_parser()
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-XXE-002"

    def test_detects_from_import_sax(self, make_file):
        path = make_file(
            "handler.py",
            """\
            from xml.sax.handler import ContentHandler
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_with_defusedxml(self, make_file):
        path = make_file(
            "handler.py",
            """\
            import defusedxml.sax
            parser = defusedxml.sax.make_parser()
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestXxeLxml:
    """PF-XXE-003: Unsafe lxml parser."""

    def test_detects_lxml_parse_without_parser(self, make_file):
        path = make_file(
            "xml_util.py",
            """\
            from lxml import etree
            doc = etree.parse("data.xml")
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-XXE-003"

    def test_detects_lxml_fromstring(self, make_file):
        path = make_file(
            "xml_util.py",
            """\
            from lxml import etree
            doc = etree.fromstring(xml_data)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_lxml_xml(self, make_file):
        path = make_file(
            "xml_util.py",
            """\
            from lxml import etree
            doc = etree.XML(xml_string)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_with_parser_kwarg(self, make_file):
        path = make_file(
            "xml_util.py",
            """\
            from lxml import etree
            safe_parser = etree.XMLParser(resolve_entities=False)
            doc = etree.parse("data.xml", parser=safe_parser)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_with_resolve_entities_kwarg(self, make_file):
        path = make_file(
            "xml_util.py",
            """\
            from lxml import etree
            doc = etree.parse("data.xml", resolve_entities=False)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_no_finding_without_lxml_import(self, make_file):
        path = make_file(
            "xml_util.py",
            """\
            import json
            doc = etree.parse("data.xml")
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestPickleLoads:
    """PF-XXE-004: Unsafe pickle deserialization."""

    def test_detects_pickle_loads(self, make_file):
        path = make_file(
            "cache.py",
            """\
            import pickle
            data = pickle.loads(raw_bytes)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-XXE-004"
        assert findings[0].cwe == 502

    def test_detects_pickle_load(self, make_file):
        path = make_file(
            "cache.py",
            """\
            import pickle
            with open("cache.pkl", "rb") as f:
                data = pickle.load(f)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_cpickle(self, make_file):
        path = make_file(
            "fast_cache.py",
            """\
            import _pickle
            data = _pickle.loads(raw_bytes)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_unpickler(self, make_file):
        path = make_file(
            "deserialize.py",
            """\
            import pickle
            u = pickle.Unpickler(stream)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_no_false_positive_json_loads(self, make_file):
        path = make_file(
            "safe.py",
            """\
            import json
            data = json.loads(raw_string)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestUnsafeYamlLoad:
    """PF-XXE-005: yaml.load() without SafeLoader."""

    def test_detects_yaml_load_no_loader(self, make_file):
        path = make_file(
            "config.py",
            """\
            import yaml
            with open("config.yml") as f:
                data = yaml.load(f)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-XXE-005"
        assert findings[0].cwe == 502

    def test_safe_with_safeloader(self, make_file):
        path = make_file(
            "config.py",
            """\
            import yaml
            with open("config.yml") as f:
                data = yaml.load(f, Loader=yaml.SafeLoader)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_with_csafeloader(self, make_file):
        path = make_file(
            "config.py",
            """\
            import yaml
            data = yaml.load(content, Loader=yaml.CSafeLoader)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_with_fullloader(self, make_file):
        path = make_file(
            "config.py",
            """\
            import yaml
            data = yaml.load(content, Loader=yaml.FullLoader)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_with_baseloader_name(self, make_file):
        path = make_file(
            "config.py",
            """\
            import yaml
            from yaml import BaseLoader
            data = yaml.load(content, Loader=BaseLoader)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_no_false_positive_safe_load(self, make_file):
        path = make_file(
            "config.py",
            """\
            import yaml
            data = yaml.safe_load(content)
            """,
        )
        scanner = Scanner(selected_rules=["PF-XXE-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0
