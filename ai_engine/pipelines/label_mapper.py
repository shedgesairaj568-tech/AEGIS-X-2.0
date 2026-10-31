"""
Label mapping: CIC-IDS2017's raw attack labels -> AEGIS-X's AttackType.

CIC-IDS2017 uses 15 fine-grained labels (e.g. "DoS Hulk", "FTP-Patator",
"Web Attack - XSS"). Our platform's `attack_type` field on the Alert model
(see backend/app/core/enums.py) uses a smaller, coarser set of categories
that map to what the XGBoost classifier (Module 6) will actually predict.

This mapping is the single source of truth for that translation — it's
imported by both the preprocessing pipeline and, later, the model
training script, so the labels used to train the model always match the
labels the backend API actually accepts.
"""

# Must match app/core/enums.py -> ATTACK_TYPES in the backend, so a
# prediction from this pipeline can be written straight into the
# `attacks` table without a translation step at API time.
ATTACK_TYPES = (
    "normal",
    "brute_force",
    "ddos",
    "botnet",
    "port_scan",
    "sql_injection",
    "web_attack",
    "other",
)

# Raw CIC-IDS2017 label (as it appears in the CSV's "Label" column,
# case-sensitive) -> our coarse AttackType.
CIC_IDS2017_LABEL_MAP: dict[str, str] = {
    "BENIGN": "normal",
    # Denial of service variants. CIC-IDS2017 distinguishes DoS (single
    # source) from DDoS (distributed); we fold single-source DoS into
    # "other" since our enum doesn't have a dedicated single-source DoS
    # bucket, and reserve "ddos" for the true distributed attack.
    "DoS Hulk": "other",
    "DoS GoldenEye": "other",
    "DoS slowloris": "other",
    "DoS Slowhttptest": "other",
    "DDoS": "ddos",
    # Port scanning
    "PortScan": "port_scan",
    # Credential brute forcing
    "FTP-Patator": "brute_force",
    "SSH-Patator": "brute_force",
    # Botnet activity
    "Bot": "botnet",
    # Web application attacks
    "Web Attack \x96 Brute Force": "web_attack",
    "Web Attack \x96 XSS": "web_attack",
    "Web Attack \x96 Sql Injection": "sql_injection",
    # Some dataset releases use a plain hyphen instead of the mojibake
    # en-dash above (encoding varies by how the CSV was re-saved).
    "Web Attack - Brute Force": "web_attack",
    "Web Attack - XSS": "web_attack",
    "Web Attack - Sql Injection": "sql_injection",
    # Rare/severe categories
    "Infiltration": "other",
    "Heartbleed": "other",
}


def map_label(raw_label: str) -> str:
    """
    Map one raw CIC-IDS2017 label to an AEGIS-X AttackType.

    Falls back to "other" for any label not in the table above, rather
    than raising — new/unseen label variants (the dataset has known
    encoding inconsistencies) shouldn't crash the whole pipeline over one
    row's label text.
    """
    cleaned = raw_label.strip()
    return CIC_IDS2017_LABEL_MAP.get(cleaned, "other")
