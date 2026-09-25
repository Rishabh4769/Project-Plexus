"""Template registry."""

from . import soc_dark, exec_brief, dossier, pulse, night_dossier

TEMPLATES = {
    soc_dark.TEMPLATE_ID: soc_dark,
    exec_brief.TEMPLATE_ID: exec_brief,
    dossier.TEMPLATE_ID: dossier,
    pulse.TEMPLATE_ID: pulse,
    night_dossier.TEMPLATE_ID: night_dossier,
}


def list_templates():
    return [(t.TEMPLATE_ID, t.TEMPLATE_NAME, t.TEMPLATE_DESC)
            for t in TEMPLATES.values()]


def generate(template_id, data):
    return TEMPLATES[template_id].generate(data)
