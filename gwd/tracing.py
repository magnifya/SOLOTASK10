"""W3C Trace Context (the ``traceparent`` / ``tracestate`` headers).

The gateway mints one local root context per proxy request: a 32 lowercase
hex trace id and a 16 lowercase hex span id. An inbound ``traceparent`` is
honoured only in the strict ``00`` form --

``00-<32 hex trace-id>-<16 hex parent-id>-<2 hex flags>``

with neither id all zero -- otherwise the request is rejected with ``400``
before authentication, quota, idempotency or any upstream call. Tracing never
takes part in routing, quota or weighting and never changes forwarding,
billing or failover outcomes: a request without a ``traceparent`` keeps its
historical behaviour apart from the correlation headers and audit fields.
"""

from __future__ import annotations

import secrets
from typing import NamedTuple, Optional

TRACEPARENT_HEADER = "traceparent"
TRACESTATE_HEADER = "tracestate"
TRACE_ID_HEADER = "X-Trace-Id"

_HEX = set("0123456789abcdef")


def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and all(ch in _HEX for ch in value)


class TraceContext(NamedTuple):
    """The trace/span identity carried by one gateway request.

    ``span_id`` is the gateway span for this request. On an inbound
    ``traceparent`` the upstream ``parent-id`` is remembered as
    ``parent_span_id``; a locally minted root request has no parent.
    """

    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    flags: str

    @classmethod
    def root(cls) -> "TraceContext":
        """Mint a fresh local root: random ids, ``flags`` ``00``, no parent."""
        return cls(secrets.token_hex(16), secrets.token_hex(8), None, "00")

    @property
    def sampled(self) -> bool:
        """The least significant bit of the two hex flags digits."""
        return (int(self.flags, 16) & 0x01) == 1

    def traceparent(self, parent_span_id: Optional[str] = None) -> str:
        """Render a canonical version-``00`` ``traceparent`` value.

        The parent span defaults to this request's gateway span, which is what
        every upstream attempt (retries and failover included) receives.
        """
        parent = parent_span_id or self.span_id
        return "00-%s-%s-%s" % (self.trace_id, parent, self.flags)

    def outgoing(self, tracestate: Optional[str] = None) -> dict:
        """Headers to attach to an upstream call."""
        headers = {TRACEPARENT_HEADER: self.traceparent()}
        if tracestate:
            headers[TRACESTATE_HEADER] = tracestate
        return headers


def parse_traceparent(value: Optional[str]) -> TraceContext:
    """Parse a strict W3C version-``00`` ``traceparent`` or raise ``ValueError``.

    Accepts exactly four hyphen separated fields: version ``00``, a 32 lowercase
    hex non-zero trace id, a 16 lowercase hex non-zero parent id and two
    lowercase hex flags digits. Anything else -- another version, an all-zero id,
    trailing data, odd casing -- is rejected; the caller answers ``400`` and
    audits the rejection without entering the rest of the pipeline.
    """
    if not value or not isinstance(value, str):
        raise ValueError("invalid traceparent")
    fields = value.split("-")
    if len(fields) != 4 or fields[0] != "00":
        raise ValueError("invalid traceparent")
    _, trace_id, parent_id, flags = fields
    if not _is_hex(trace_id, 32) or set(trace_id) == {"0"}:
        raise ValueError("invalid traceparent")
    if not _is_hex(parent_id, 16) or set(parent_id) == {"0"}:
        raise ValueError("invalid traceparent")
    if not _is_hex(flags, 2):
        raise ValueError("invalid traceparent")
    return TraceContext(trace_id, secrets.token_hex(8), parent_id, flags)
