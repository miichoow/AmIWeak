"""The REST API.

The check is a POST with a JSON body so the password never lands in a URL, where
it would be logged by every proxy and access log between here and the client.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from flask import Blueprint, current_app, jsonify, request
from flask.wrappers import Response

from amiweak.algorithms import Algorithm, is_valid_digest, parse_algorithm
from amiweak.app import Evaluator, context, envelope
from amiweak.checks.runner import BatchItem, Verdict
from amiweak.config import BatchConfig

logger = logging.getLogger(__name__)

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def _load_json() -> Any:
    """Parse the request body as JSON, tolerating a body mislabeled as UTF-8.

    JSON is UTF-8 by spec, and Flask's `get_json` decodes it strictly as such.
    Some clients (notably SSPR, which sends `Content-Type: application/json;
    charset=UTF-8` but a Windows-1252 body) put accented text in fields we
    never read -- a policy `ChangeMessage`, a `passwordRules` list. Those bytes
    (a lone \\xe9, \\x92, ...) are invalid UTF-8, so a strict parse 400s a
    request whose `password` is plain ASCII and perfectly usable.

    So: try UTF-8 first -- a well-formed client always wins here -- then fall
    back to cp1252, a superset of Latin-1 that also covers the smart-punctuation
    bytes those clients emit. Returns None when the body is JSON under neither
    decoding, so every caller keeps its existing 400 path unchanged. Content
    type is deliberately ignored: the whole point is that we cannot trust the
    charset a client declares.
    """
    raw = request.get_data()
    if not raw:
        return None
    for encoding in ("utf-8", "cp1252"):
        try:
            return json.loads(raw.decode(encoding))
        except (UnicodeDecodeError, ValueError):
            continue
    return None


#: Which configured message answers which verdict.
MESSAGE_FOR = {
    Verdict.SAFE: "safe",
    Verdict.LEAKED: "leaked",
    Verdict.PRECOMPUTED: "precomputed",
    Verdict.DENYLISTED: "denylisted",
    Verdict.TOO_SHORT: "too_short",
    Verdict.WEAK: "weak",
    Verdict.ERROR: "error",
}


@bp.post("/check")
def check() -> tuple[Response, int]:
    ctx = context(current_app)
    messages = ctx.config.messages

    if ctx.config.policy.rate_limit.enabled:
        client = request.remote_addr or "unknown"
        if not ctx.limiter.allow(client):
            return jsonify(envelope(True, "Too many checks. Try again shortly.")), 429

    payload = _load_json()
    if not isinstance(payload, dict):
        return jsonify(envelope(True, "Send a JSON object with a 'password' field.")), 400

    password = payload.get("password")
    if not isinstance(password, str) or not password:
        return jsonify(envelope(True, "Send a JSON object with a 'password' field.")), 400

    try:
        _require_supported(ctx.runner, Algorithm.SHA1)
        evaluation = ctx.runner.evaluate(password)
    except _Invalid as exc:
        return jsonify(envelope(True, str(exc))), 400
    except Exception:
        # No payload, no password, no exception text in the log line: the
        # traceback goes to the handler, which the redacting filter guards.
        logger.exception("password check failed")
        return jsonify(envelope(True, messages.error)), 500

    message = getattr(messages, MESSAGE_FOR[evaluation.verdict])
    body = envelope(
        error=evaluation.verdict is not Verdict.SAFE,
        message=message,
        verdict=str(evaluation.verdict),
        degraded=evaluation.degraded,
        checks=[result.to_dict() for result in evaluation.results],
    )
    if evaluation.degraded:
        body["degradedMessage"] = messages.degraded
    return jsonify(body), 200


#: Every verdict a batch item can carry, so a summary always has the same keys
#: whether or not that verdict occurred.
SUMMARY_VERDICTS = (
    Verdict.LEAKED,
    Verdict.PRECOMPUTED,
    Verdict.DENYLISTED,
    Verdict.SAFE,
    Verdict.ERROR,
)


class _Invalid(Exception):
    """A request the client got wrong. Carries no client data."""


def _parse_batch(payload: Any, batch_config: BatchConfig) -> tuple[Algorithm, list[BatchItem]]:
    """Validate the request body, or raise _Invalid.

    Nothing a client sent is ever put into the exception message: a label is a
    username and a hash is a credential, and both would end up in a log line.
    """
    if not isinstance(payload, dict):
        raise _Invalid("Send a JSON object.")
    try:
        algorithm = parse_algorithm(payload.get("algorithm"))
    except ValueError:
        raise _Invalid("Field 'algorithm' must be 'sha1' or 'ntlm'.") from None

    raw_items = payload.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise _Invalid("Field 'items' must be a non-empty array.")
    if len(raw_items) > batch_config.max_items:
        raise _Invalid(f"A batch may contain at most {batch_config.max_items} items.")

    items: list[BatchItem] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise _Invalid("Each item must be an object with 'label' and 'hash'.")
        label = raw.get("label")
        if not isinstance(label, str) or not label:
            raise _Invalid("Each item needs a non-empty string 'label'.")
        if len(label) > batch_config.max_label_length:
            raise _Invalid(f"A label may be at most {batch_config.max_label_length} characters.")
        digest = raw.get("hash")
        if not is_valid_digest(digest, algorithm):
            raise _Invalid(f"Each 'hash' must be {algorithm.digest_length} hex characters.")
        items.append(BatchItem(label=label, digest=str(digest).strip().lower()))
    return algorithm, items


def _require_supported(runner: Evaluator, algorithm: Algorithm) -> None:
    """Reject an algorithm no enabled backend can answer for.

    The name is safe to echo: it came out of `parse_algorithm`, so it is a
    member of the fixed Algorithm enum and never attacker-controlled text.
    """
    if not runner.supports(algorithm):
        raise _Invalid(f"Algorithm '{algorithm}' is not enabled.")


@bp.post("/check/batch")
def check_batch() -> tuple[Response, int]:
    ctx = context(current_app)
    if not ctx.config.batch.enabled:
        return jsonify(envelope(True, "Batch checking is disabled.")), 404

    try:
        algorithm, items = _parse_batch(_load_json(), ctx.config.batch)
        _require_supported(ctx.runner, algorithm)
    except _Invalid as exc:
        return jsonify(envelope(True, str(exc))), 400

    if ctx.config.batch.rate_limit.enabled:
        client = request.remote_addr or "unknown"
        # A batch that hits an entirely warm cache still costs real server
        # work (dict lookups, Evaluation construction, JSON serialization),
        # so it must never be free: charge at least 1 token even when
        # prefix_cost reports 0 uncached prefixes.
        cost = max(1, ctx.runner.prefix_cost(items, algorithm))
        if not ctx.batch_limiter.allow(client, cost=cost):
            return jsonify(envelope(True, "Too many checks. Try again shortly.")), 429

    try:
        outcomes = ctx.runner.evaluate_batch(items, algorithm)
    except Exception:
        # No labels, no digests, no exception text: the traceback goes to the
        # handler, which the redacting factory guards.
        logger.exception("batch check failed")
        return jsonify(envelope(True, ctx.config.messages.error)), 500

    ctx.metrics.record_batch(items=len(items))

    summary = {"total": len(outcomes)}
    summary.update({str(v): 0 for v in SUMMARY_VERDICTS})
    results = []
    for outcome in outcomes:
        summary[str(outcome.evaluation.verdict)] += 1
        results.append(
            {
                "label": outcome.label,
                "verdict": str(outcome.evaluation.verdict),
                "degraded": outcome.evaluation.degraded,
                "checks": [r.to_dict() for r in outcome.evaluation.results],
            }
        )

    body = envelope(
        # `error` describes the request, not its contents. A batch containing
        # leaked passwords is a successful batch.
        error=False,
        message=ctx.config.messages.batch_complete.format(
            total=summary["total"], failed=summary[str(Verdict.ERROR)]
        ),
        algorithm=str(algorithm),
        degraded=any(o.evaluation.degraded for o in outcomes),
        summary=summary,
        results=results,
    )
    return jsonify(body), 200


def _parse_hash(payload: Any) -> tuple[Algorithm, str]:
    """Validate the request body, or raise _Invalid.

    Same rule as `_parse_batch`: a digest is a credential, so nothing the client
    sent is ever put into the exception message.
    """
    if not isinstance(payload, dict):
        raise _Invalid("Send a JSON object with a 'hash' field.")
    # SHA-1 is the default because it is the overwhelmingly common case and the
    # one /check already implies. NTLM is asked for explicitly.
    try:
        algorithm = parse_algorithm(payload.get("algorithm", str(Algorithm.SHA1)))
    except ValueError:
        raise _Invalid("Field 'algorithm' must be 'sha1' or 'ntlm'.") from None

    digest = payload.get("hash")
    if not is_valid_digest(digest, algorithm):
        raise _Invalid(f"Field 'hash' must be {algorithm.digest_length} hex characters.")
    return algorithm, str(digest).strip().lower()


@bp.post("/check/hash")
def check_hash() -> tuple[Response, int]:
    """/check with the hashing moved client-side.

    `policy.min_length` is not enforceable here and is not enforced: a digest
    does not carry the length of the password it came from, so Verdict.TOO_SHORT
    is unreachable. Callers who need a length policy apply it before hashing.
    """
    ctx = context(current_app)
    messages = ctx.config.messages

    # Validation precedes the limiter, as on /check/batch: a malformed body must
    # not spend a token that a well-formed request from the same client needs.
    try:
        algorithm, digest = _parse_hash(_load_json())
        _require_supported(ctx.runner, algorithm)
    except _Invalid as exc:
        return jsonify(envelope(True, str(exc))), 400

    if ctx.config.policy.rate_limit.enabled:
        client = request.remote_addr or "unknown"
        # The interactive bucket, shared with /check. This is the same work --
        # one prefix per backend -- so it must not be a second allowance.
        if not ctx.limiter.allow(client):
            return jsonify(envelope(True, "Too many checks. Try again shortly.")), 429

    try:
        evaluation = ctx.runner.evaluate_digest(digest, algorithm)
    except Exception:
        # No digest, no algorithm, no exception text in the log line: the
        # traceback goes to the handler, which the redacting filter guards.
        logger.exception("hash check failed")
        return jsonify(envelope(True, messages.error)), 500

    message = getattr(messages, MESSAGE_FOR[evaluation.verdict])
    body = envelope(
        # `error` follows the verdict, as on /check, not the request as on
        # /check/batch. A single-check caller reads this as "is this password
        # bad?", which is the question /check answers.
        error=evaluation.verdict is not Verdict.SAFE,
        message=message,
        verdict=str(evaluation.verdict),
        algorithm=str(algorithm),
        degraded=evaluation.degraded,
        checks=[result.to_dict() for result in evaluation.results],
    )
    if evaluation.degraded:
        body["degradedMessage"] = messages.degraded
    return jsonify(body), 200


@bp.get("/config")
def client_config() -> Response:
    """The subset of config the page needs: strength settings and copy.

    Deliberately narrow — the page has no business knowing about proxies,
    timeouts, or which backends are wired up.
    """
    ctx = context(current_app)
    return jsonify(
        {
            "strength": {
                "enabled": ctx.config.strength.enabled,
                "min_score": ctx.config.strength.min_score,
                "min_length": ctx.config.policy.min_length,
            },
            "messages": {
                "safe": ctx.config.messages.safe,
                "leaked": ctx.config.messages.leaked,
                "precomputed": ctx.config.messages.precomputed,
                "denylisted": ctx.config.messages.denylisted,
                "weak": ctx.config.messages.weak,
                "too_short": ctx.config.messages.too_short,
                "degraded": ctx.config.messages.degraded,
                "error": ctx.config.messages.error,
            },
        }
    )
