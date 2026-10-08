MITRE_MAPPINGS = {
    "REMOTE_LOGON": {
        "technique": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement"
    },

    "PRIVILEGED_LOGON": {
        "technique": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access"
    },

    "EXPLICIT_CREDENTIALS": {
        "technique": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access"
    },

    "SUSPICIOUS_PROCESS": {
        "technique": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution"
    },

    "FAILED_LOGON": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },

    "LATERAL_MOVEMENT_CORRELATION": {
        "technique": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement"
    }
}


def get_mitre_mapping(detection_type):

    return MITRE_MAPPINGS.get(
        detection_type,
        {
            "technique": "N/A",
            "name": "Unmapped Detection",
            "tactic": "N/A"
        }
    )


def get_mitre_for_alert(alert):

    return get_mitre_mapping(
        alert.get(
            "detection_type",
            ""
        )
    )