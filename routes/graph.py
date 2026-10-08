from flask import Blueprint, render_template, request

from investigation.graph import build_attack_graph


bp = Blueprint(
    "graph",
    __name__,
    url_prefix="/graph"
)


@bp.get("/")
def graph():

    account = request.args.get(
        "account",
        ""
    ).strip()

    graph_data = build_attack_graph(
        account=account or None
    )

    return render_template(
        "graph.html",
        graph_data=graph_data,
        account=account
    )