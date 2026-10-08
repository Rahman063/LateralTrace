from flask import Blueprint, render_template

from detection.mitre import MITRE_MAPPINGS


bp = Blueprint(
    "mitre",
    __name__,
    url_prefix="/mitre"
)


@bp.get("/")
def mitre():

    mappings = []

    for detection_type, mapping in MITRE_MAPPINGS.items():

        mappings.append(
            {
                "detection_type": detection_type,
                "technique": mapping["technique"],
                "name": mapping["name"],
                "tactic": mapping["tactic"]
            }
        )

    return render_template(
        "mitre.html",
        mappings=mappings
    )