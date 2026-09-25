"""
laya_scorer.py — Laya decision-model second opinion for PLEXUS alerts.
======================================================================
Gives an independent, calibrated verdict on flows already flagged by the
primary XGBoost NIDS. Uses the `laya-typed-decisions` checkpoint
(ModernBERT-large, 421M params, 1024-token context, Apache 2.0).

Design notes (rush-hour safe):
- Lazy: the ~1.5GB checkpoint loads on the FIRST flagged flow, never at
  startup. Zero cost when idle.
- Optional: if the `laya` package or weights are missing, every call
  returns None and alerts look exactly as before. Nothing breaks.
- Never raises: safe to call from the sniffer thread. Wrap callers in
  try/except anyway.
- Beta status: Laya is zero-shot on network flows (its training is
  email/triage/guardrail decisions). Treat its verdict as a second
  opinion, not ground truth. Fine-tuning on labeled flows is the
  follow-up that makes it production-grade.

Install:
    .venv/bin/pip install "laya>=0.3.3"
Pre-download weights (so the first alert isn't slow):
    .venv/bin/python -c "import laya; laya.load('convaiinnovations/laya-typed-decisions')"
"""

import logging
import os
import threading

log = logging.getLogger("laya_scorer")

_MODEL_ID = "convaiinnovations/laya-typed-decisions"

# Kill switch: PLEXUS_DISABLE_LAYA=1 disables the second opinion entirely.
# Useful for isolating issues or for demos where only XGBoost should run.
_DISABLE_ENV = os.environ.get("PLEXUS_DISABLE_LAYA", "").strip().lower() in ("1", "true", "yes")

_agent = None
_disabled = False
_lock = threading.Lock()


def _load_agent():
    """Lazy-load the Laya agent; returns None (latched) on any failure."""
    global _agent, _disabled
    if _agent is not None or _disabled:
        return _agent
    if _DISABLE_ENV:
        _disabled = True
        log.info("Laya second opinion disabled via PLEXUS_DISABLE_LAYA.")
        return None
    with _lock:
        if _agent is not None or _disabled:
            return _agent
        try:
            import laya
        except ImportError:
            log.warning(
                "`laya` package not installed — second opinion disabled "
                "(`.venv/bin/pip install 'laya>=0.3.3'`)."
            )
            _disabled = True
            return None
        try:
            log.info(f"Loading Laya checkpoint {_MODEL_ID} (first run downloads weights)...")
            _agent = laya.load(_MODEL_ID)
            log.info("Laya checkpoint loaded.")
        except Exception as exc:
            log.warning(f"Laya load failed ({exc}) — second opinion disabled for this run.")
            _disabled = True
            return None
        return _agent


def _extract_prob(ans):
    """Pull a probability float out of a noul answer (float or dict)."""
    if isinstance(ans, bool):
        return None
    if isinstance(ans, (int, float)):
        return float(ans)
    if isinstance(ans, dict):
        for key in ("noul", "probability", "p_true", "p", "confidence", "score"):
            val = ans.get(key)
            if isinstance(val, bool):
                continue
            if isinstance(val, (int, float)):
                return float(val)
    return None


def _extract_choice(ans):
    """Pull (choice, confidence) out of a choice answer."""
    if isinstance(ans, str):
        return ans, None
    if isinstance(ans, dict):
        choice = ans.get("choice")
        conf = None
        for key in ("confidence", "prob", "probability"):
            val = ans.get(key)
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                conf = float(val)
                break
        if isinstance(choice, str):
            return choice, conf
    return None, None


def second_opinion(flow_key: str, protocol: str, features: dict) -> str | None:
    """
    Ask Laya for an independent verdict on a flagged flow.

    Returns a short human-readable string like:
        "Laya second opinion (beta): attack P=87%, category=brute_force (72%)"
    or None when the model is unavailable or the call fails.
    Never raises.
    """
    agent = _load_agent()
    if agent is None:
        return None
    try:
        stats = {}
        for k, v in (features or {}).items():
            try:
                stats[str(k)] = round(float(v), 3)
            except (TypeError, ValueError):
                continue

        state = {
            "flow": flow_key,
            "protocol": protocol,
            "flow_statistics": stats,
            "note": "Give an independent verdict based only on the flow data above.",
        }
        # Keep it minimal: one noul + one small choice. Laya's own eval
        # warns that score questions and many-option choices are unreliable
        # zero-shot, so we ask only what it does best.
        questions = {
            "is_attack": {
                "type": "noul",
                "instructions": (
                    "Is this network flow part of a cyber attack "
                    "(port scan, flood, brute force, or other malicious activity)?"
                ),
            },
            "attack_category": {
                "type": "choice",
                "instructions": "What best describes this network flow?",
                "criteria": {
                    "port_scan": "probing or scanning many ports on a target",
                    "flood": "overwhelming packet volume or denial of service",
                    "brute_force": "repeated connection or login attempts",
                    "benign": "normal legitimate network traffic",
                },
            },
        }

        res = agent.predict(state, questions)
        answers = res.get("answers", {}) if isinstance(res, dict) else {}

        p_attack = _extract_prob(answers.get("is_attack"))
        category, cat_conf = _extract_choice(answers.get("attack_category"))

        parts = []
        if p_attack is not None:
            parts.append(f"attack P={p_attack:.0%}")
        if category:
            parts.append(
                f"category={category}"
                + (f" ({cat_conf:.0%})" if cat_conf is not None else "")
            )
        if not parts:
            return None
        return "Laya second opinion (beta): " + ", ".join(parts)
    except Exception as exc:
        log.warning(f"Laya predict failed: {exc}")
        return None
