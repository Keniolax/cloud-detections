"""Credential-free checks on the detection content, run by CI.

They prove the Sigma rules, the generated Wazuh rules, the Athena SQL and the
technique registry all agree, without touching AWS.
"""
import pathlib
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SIGMA = ROOT / "sigma"
ATHENA = ROOT / "athena"
sys.path.insert(0, str(ROOT / "convert"))


def registry():
    return yaml.safe_load((ROOT / "techniques.yaml").read_text())


def test_wazuh_rules_in_sync():
    """The committed Wazuh ruleset matches what the converter produces."""
    r = subprocess.run([sys.executable, "convert/sigma_to_wazuh.py", "--check"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_every_technique_has_its_files():
    for t in registry():
        assert (SIGMA / t["sigma"]).exists(), f"missing sigma {t['sigma']}"
        assert (ATHENA / t["athena"]).exists(), f"missing athena {t['athena']}"


def test_sigma_matches_registry():
    """Each Sigma rule's wazuh id, logsource and event source agree with the registry."""
    for t in registry():
        doc = yaml.safe_load((SIGMA / t["sigma"]).read_text())
        assert doc["wazuh"]["id"] == t["wazuh_id"], t["key"]
        assert doc["logsource"]["product"] == "aws"
        assert doc["logsource"]["service"] == "cloudtrail"
        sel = doc["detection"]["selection"]
        assert sel["eventSource"] == t["event_source"], t["key"]
        # the MITRE id in the tags matches the registry
        tagged = [x.split(".", 1)[1].upper()
                  for x in doc["tags"] if x.startswith("attack.t")]
        assert t["mitre"] in tagged, t["key"]


def test_wazuh_ids_unique():
    ids = [t["wazuh_id"] for t in registry()]
    assert len(ids) == len(set(ids)), "duplicate Wazuh rule id"


def test_athena_sql_names_its_event():
    """Every Athena query filters on the technique's event source and names."""
    for t in registry():
        sql = (ATHENA / t["athena"]).read_text()
        assert t["event_source"] in sql, f"{t['key']}: event source not in SQL"
        for ev in t["event_names"]:
            assert ev in sql, f"{t['key']}: {ev} not in SQL"


def test_converter_handles_all_rules():
    """The converter builds without error and emits one rule per technique."""
    import sigma_to_wazuh
    xml = sigma_to_wazuh.build()
    for t in registry():
        assert f'id="{t["wazuh_id"]}"' in xml, t["key"]
        assert f"<id>{t['mitre']}</id>" in xml, t["key"]
