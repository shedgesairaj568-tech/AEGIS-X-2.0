"""
MITRE ATT&CK technique mapping.

A static lookup table from AEGIS-X's attack_type categories to a
representative MITRE ATT&CK technique ID/name. This is intentionally a
simple, fast, first-pass mapping — Module 8's Knowledge Agent will later
do real semantic search over the full MITRE ATT&CK corpus stored in
Qdrant (Module 7) to find more precise, context-aware technique matches.
This module exists so alerts have SOME MITRE mapping immediately, without
waiting for that infrastructure.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    technique_name: str


# One representative technique per attack_type. Real attacks often map to
# several techniques; this picks the single most common/canonical one.
ATTACK_TYPE_TO_MITRE: dict[str, MitreTechnique] = {
    "brute_force": MitreTechnique("T1110", "Brute Force"),
    "ddos": MitreTechnique("T1498", "Network Denial of Service"),
    "botnet": MitreTechnique("T1584", "Compromise Infrastructure"),
    "port_scan": MitreTechnique("T1046", "Network Service Discovery"),
    "sql_injection": MitreTechnique("T1190", "Exploit Public-Facing Application"),
    "web_attack": MitreTechnique("T1190", "Exploit Public-Facing Application"),
    "other": MitreTechnique("T1499", "Endpoint Denial of Service"),
    # "normal" deliberately has no mapping — it's not an attack.
}


def get_mitre_mapping(attack_type: str) -> MitreTechnique | None:
    return ATTACK_TYPE_TO_MITRE.get(attack_type)
