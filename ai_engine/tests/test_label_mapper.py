"""
Tests for ai_engine.pipelines.label_mapper.
"""

import pytest

from ai_engine.pipelines.label_mapper import ATTACK_TYPES, map_label


@pytest.mark.parametrize(
    "raw_label,expected",
    [
        ("BENIGN", "normal"),
        ("DDoS", "ddos"),
        ("PortScan", "port_scan"),
        ("FTP-Patator", "brute_force"),
        ("SSH-Patator", "brute_force"),
        ("Bot", "botnet"),
        ("Web Attack - XSS", "web_attack"),
        ("Web Attack - Sql Injection", "sql_injection"),
        ("DoS Hulk", "other"),
        ("Heartbleed", "other"),
    ],
)
def test_map_label_known_values(raw_label, expected):
    assert map_label(raw_label) == expected


def test_map_label_unknown_value_falls_back_to_other():
    assert map_label("Some Totally New Attack Type") == "other"


def test_map_label_strips_whitespace():
    assert map_label("  BENIGN  ") == "normal"


def test_every_mapped_value_is_a_valid_attack_type():
    from ai_engine.pipelines.label_mapper import CIC_IDS2017_LABEL_MAP

    for raw, mapped in CIC_IDS2017_LABEL_MAP.items():
        assert mapped in ATTACK_TYPES, f"'{raw}' maps to '{mapped}', which isn't in ATTACK_TYPES"
