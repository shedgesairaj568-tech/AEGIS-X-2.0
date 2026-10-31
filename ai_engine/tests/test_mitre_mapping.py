"""
Tests for ai_engine.inference.mitre_mapping.
"""

from ai_engine.inference.mitre_mapping import get_mitre_mapping
from ai_engine.pipelines.label_mapper import ATTACK_TYPES


def test_normal_has_no_mitre_mapping():
    assert get_mitre_mapping("normal") is None


def test_ddos_maps_to_expected_technique():
    mapping = get_mitre_mapping("ddos")
    assert mapping.technique_id == "T1498"


def test_every_non_normal_attack_type_has_a_mapping():
    for attack_type in ATTACK_TYPES:
        if attack_type == "normal":
            continue
        mapping = get_mitre_mapping(attack_type)
        assert mapping is not None, f"No MITRE mapping defined for '{attack_type}'"
        assert mapping.technique_id.startswith("T")
        assert len(mapping.technique_name) > 0


def test_unknown_attack_type_returns_none():
    assert get_mitre_mapping("not_a_real_attack_type") is None
