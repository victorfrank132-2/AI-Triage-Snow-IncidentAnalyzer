"""Strict Splunk SPL policy enforcement before any remote execution."""

from __future__ import annotations

import re

from snow_intelligence.schemas import SplunkQueryPolicy, SplunkQueryRequest

_DISALLOWED_COMMANDS = re.compile(
    r"\|\s*(?:delete|collect|outputlookup|sendemail|script|map|rest|inputlookup)\b",
    re.IGNORECASE,
)
_INDEX_PATTERN = re.compile(r"\bindex\s*=\s*([\w.-]+)", re.IGNORECASE)
_SOURCETYPE_PATTERN = re.compile(r"\bsourcetype\s*=\s*([\w.-]+)", re.IGNORECASE)
_FIELD_PATTERN = re.compile(r"\b([A-Za-z_][\w.]*)\s*=")


class SplunkPolicyViolation(ValueError):
    """Raised when generated SPL exceeds the tenant-approved query policy."""


def validate_splunk_query(request: SplunkQueryRequest, policy: SplunkQueryPolicy) -> None:
    query = request.query.strip()
    if _DISALLOWED_COMMANDS.search(query):
        raise SplunkPolicyViolation("query contains a prohibited SPL command")
    if request.earliest_hours_ago > policy.max_time_range_hours:
        raise SplunkPolicyViolation("query time window exceeds the tenant policy")
    if request.max_rows > policy.max_result_rows:
        raise SplunkPolicyViolation("query result limit exceeds the tenant policy")

    indexes = {match.group(1) for match in _INDEX_PATTERN.finditer(query)}
    sourcetypes = {match.group(1) for match in _SOURCETYPE_PATTERN.finditer(query)}
    fields = {match.group(1) for match in _FIELD_PATTERN.finditer(query)} - {"index", "sourcetype"}
    if not indexes or not indexes.issubset(policy.allowed_indexes):
        raise SplunkPolicyViolation("query uses an unapproved or missing index")
    if sourcetypes and not sourcetypes.issubset(policy.allowed_sourcetypes):
        raise SplunkPolicyViolation("query uses an unapproved sourcetype")
    unknown_fields = fields - policy.allowed_fields
    if unknown_fields:
        raise SplunkPolicyViolation(f"query uses unapproved fields: {sorted(unknown_fields)}")
