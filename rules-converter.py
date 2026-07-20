#!/usr/bin/env python3
"""Convert between xray, routingA, switchy, simple-switchy, and clash formats.

xray format:
    JSON list of rule objects.

routingA format:
    # remarks text
    key(v1,v2)&&key2(v3)->outboundTag

switchy format:
    domain +outboundTag

simple-switchy format (.sorl):
    !domain  # direct
    domain   # proxy (and any non-direct outboundTag)

clash/seperate format (output only):
    An output directory containing one outboundTag.list file per outbound tag.
    Each file is a Mihomo classical rule list without a policy field.
"""

from __future__ import annotations

import argparse
import csv
from datetime import date
import ipaddress
import json
import re
import urllib.request
from pathlib import Path
from typing import Any
from urllib.error import URLError


RULE_CONDITION_KEYS = {"domain", "ip", "protocol"}
PREDICATE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)$")
SWITCHY_LINE_RE = re.compile(r"^(\S+)\s+(\+?\S+)\s*$")
SIMPLE_SWITCHY_LINE_RE = re.compile(r"^(!?)(\S+)\s*$")
RE_INLINE_COMMENT = re.compile(r"[@#]")
RE_PROTOCOL = re.compile(r"^[\w\+\-\.]+://")
RE_LEADING_WILDCARD = re.compile(r"^\*\.")
LOYALSOLDIER_GEOSITE = {
    "gfw",
    "china-list",
    "apple-cn",
    "google-cn",
    "win-spy",
    "win-update",
    "win-extra",
}


def split_predicates(expr: str) -> list[str]:
    # routingA uses && to represent logical AND between predicates.
    if "&&" in expr:
        return [p.strip() for p in expr.split("&&") if p.strip()]
    # Backward compatibility for older files that used single '&'.
    return [p.strip() for p in expr.split("&") if p.strip()]


def split_csv(text: str) -> list[str]:
    if not text.strip():
        return []
    reader = csv.reader([text], skipinitialspace=True)
    values = next(reader)
    return [part.strip() for part in values if part.strip()]


def parse_bool(text: str) -> bool | None:
    lowered = text.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def parse_routing_line(line: str) -> tuple[str, dict[str, Any]]:
    if "->" not in line:
        raise ValueError(f"Invalid rule line (missing '->'): {line}")

    left, outbound_tag = line.split("->", 1)
    left = left.strip()
    outbound_tag = outbound_tag.strip()

    if not outbound_tag:
        raise ValueError(f"Invalid rule line (empty outboundTag): {line}")

    conditions: dict[str, Any] = {}
    for raw_predicate in split_predicates(left):
        match = PREDICATE_RE.match(raw_predicate)
        if not match:
            raise ValueError(f"Invalid predicate syntax: {raw_predicate}")

        key = match.group(1)
        values = split_csv(match.group(2))

        if key == "enabled":
            if len(values) != 1:
                raise ValueError("enabled(...) only accepts one value")
            parsed = parse_bool(values[0])
            conditions[key] = parsed if parsed is not None else values[0]
            continue

        if key in RULE_CONDITION_KEYS:
            conditions[key] = values
        elif len(values) == 1:
            conditions[key] = values[0]
        else:
            conditions[key] = values

    return outbound_tag, conditions


def read_routingA(input_path: Path) -> list[dict[str, Any]]:
    lines = input_path.read_text(encoding="utf-8").splitlines()
    rules: list[dict[str, Any]] = []

    pending_comments: list[str] = []
    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue

        if line.startswith("#"):
            pending_comments.append(line[1:].strip())
            continue

        try:
            outbound_tag, conditions = parse_routing_line(line)
        except ValueError as exc:
            raise ValueError(f"{input_path}:{idx}: {exc}") from exc

        rule: dict[str, Any] = {"outboundTag": outbound_tag}
        rule.update({k: v for k, v in conditions.items() if k != "enabled"})

        enabled = conditions.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError(f"{input_path}:{idx}: enabled must be true/false")
        rule["enabled"] = enabled

        if pending_comments:
            rule["remarks"] = " ".join(pending_comments).strip()
            pending_comments = []

        rules.append(rule)

    return rules


def format_value(value: Any) -> str:
    return str(value)


def format_predicate(key: str, value: Any) -> str:
    if isinstance(value, list):
        if key == "ip":
            values = ",".join(json.dumps(format_value(v), ensure_ascii=False) for v in value)
        else:
            values = ",".join(format_value(v) for v in value)
        return f"{key}({values})"

    if key == "ip":
        return f"{key}({json.dumps(format_value(value), ensure_ascii=False)})"
    return f"{key}({format_value(value)})"


def xray_rule_to_routingA_line(rule: dict[str, Any]) -> tuple[str | None, str]:
    outbound_tag = rule.get("outboundTag")
    if not isinstance(outbound_tag, str) or not outbound_tag:
        raise ValueError("Each rule must include non-empty outboundTag")

    predicates: list[str] = []
    for key, value in rule.items():
        if key in {"outboundTag", "remarks", "enabled"}:
            continue
        predicates.append(format_predicate(key, value))

    enabled = rule.get("enabled", True)
    if enabled is not True:
        predicates.append(f"enabled({str(enabled).lower()})")

    if not predicates:
        predicates.append("all()")

    line = f"{'&&'.join(predicates)}->{outbound_tag}"
    remarks = rule.get("remarks")
    if remarks is not None and not isinstance(remarks, str):
        raise ValueError("remarks must be a string when present")

    return remarks, line


def write_routingA(rules: list[dict[str, Any]], output_path: Path) -> None:
    data = rules
    if not isinstance(data, list):
        raise ValueError("JSON root must be a list")

    out_lines: list[str] = []
    for i, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Rule #{i} must be an object")

        remarks, line = xray_rule_to_routingA_line(item)
        if remarks:
            out_lines.append(f"# {remarks}")
        out_lines.append(line)

    output_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")


def read_xray(input_path: Path) -> list[dict[str, Any]]:
    data = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("JSON root must be a list")

    rules: list[dict[str, Any]] = []
    for i, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Rule #{i} must be an object")
        rules.append(item)
    return rules


def write_xray(rules: list[dict[str, Any]], output_path: Path) -> None:
    output_path.write_text(
        json.dumps(rules, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def normalize_switchy_tag(tag: str) -> str:
    return tag[1:] if tag.startswith("+") else tag


def read_switchy(input_path: Path) -> list[dict[str, Any]]:
    lines = input_path.read_text(encoding="utf-8").splitlines()
    rules: list[dict[str, Any]] = []

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            continue
        if line.startswith("@"):
            continue
        if line.startswith("#"):
            raise ValueError(f"{input_path}:{idx}: switchy does not support comments")

        match = SWITCHY_LINE_RE.match(line)
        if not match:
            raise ValueError(f"{input_path}:{idx}: invalid switchy line: {line}")

        domain = match.group(1)
        outbound_tag = normalize_switchy_tag(match.group(2))
        if not outbound_tag:
            raise ValueError(f"{input_path}:{idx}: empty outboundTag")

        if domain.startswith("geosite:"):
            continue

        rules.append(
            {
                "outboundTag": outbound_tag,
                "domain": [domain],
                "enabled": True,
            }
        )

    return rules


def read_simple_switchy(input_path: Path) -> list[dict[str, Any]]:
    lines = input_path.read_text(encoding="utf-8").splitlines()
    rules: list[dict[str, Any]] = []

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            continue
        if line.startswith(";"):
            continue
        if line.startswith("#"):
            raise ValueError(f"{input_path}:{idx}: simple-switchy does not support comments")

        match = SIMPLE_SWITCHY_LINE_RE.match(line)
        if not match:
            raise ValueError(f"{input_path}:{idx}: invalid simple-switchy line: {line}")

        is_direct = bool(match.group(1))
        domain = match.group(2)
        if not domain:
            raise ValueError(f"{input_path}:{idx}: empty domain")

        outbound_tag = "direct" if is_direct else "proxy"
        rules.append(
            {
                "outboundTag": outbound_tag,
                "domain": [domain],
                "enabled": True,
            }
        )

    return rules


def iter_rule_domains(rule: dict[str, Any]) -> list[str]:
    domains = rule.get("domain")
    if domains is None:
        return []
    if isinstance(domains, str):
        return [domains]
    if isinstance(domains, list):
        return [str(item) for item in domains]
    return []


def normalize_domain_for_switchy(domain: str) -> str:
    # Convert xray domain matcher syntax to switchy wildcard syntax.
    if domain.startswith("domain:"):
        bare = domain[len("domain:") :]
        if not bare:
            return domain
        return bare if bare.startswith("*.") else f"*.{bare}"
    if domain.startswith("full:"):
        bare = domain[len("full:") :]
        return bare if bare else domain
    return domain


def geosite_url(item: str) -> str:
    if item in LOYALSOLDIER_GEOSITE:
        return f"https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/{item}.txt"
    return f"https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/{item}"


def fetch_text(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            return response.read().decode("utf-8", errors="ignore")
    except (URLError, TimeoutError) as exc:
        raise ValueError(f"Failed to fetch geosite data from {url}: {exc}") from exc


def normalize_geosite_domain(raw: str, is_full: bool) -> str | None:
    candidate = RE_PROTOCOL.sub("", raw).split("/")[0].split(":")[0]
    candidate = RE_LEADING_WILDCARD.sub("", candidate).lstrip(".")
    if not candidate:
        return None
    if is_full:
        return candidate
    return candidate if candidate.startswith("*.") else f"*.{candidate}"


def parse_geosite_line(line: str) -> tuple[str, str | None]:
    s = line.strip()
    if not s:
        return "skip", None
    if s.startswith(("#", "//", "!")):
        return "skip", None

    s = RE_INLINE_COMMENT.split(s, 1)[0].rstrip()
    if not s:
        return "skip", None

    lowered = s.lower()
    if lowered.startswith("include:"):
        include_item = s.split(":", 1)[1].strip()
        return "include", include_item or None
    if lowered.startswith("regexp:"):
        return "skip", None
    if lowered.startswith("full:"):
        raw = s.split(":", 1)[1].strip()
        return "domain", normalize_geosite_domain(raw, is_full=True)

    return "domain", normalize_geosite_domain(s, is_full=False)


def expand_geosite_item(item: str, cache: dict[str, list[str]], visiting: set[str]) -> list[str]:
    if item in cache:
        return cache[item]
    if item in visiting:
        return []

    visiting.add(item)
    url = geosite_url(item)
    content = fetch_text(url)

    result: list[str] = []
    seen: set[str] = set()
    for raw_line in content.splitlines():
        action, value = parse_geosite_line(raw_line)
        if action == "include" and value:
            for domain in expand_geosite_item(value, cache, visiting):
                if domain not in seen:
                    seen.add(domain)
                    result.append(domain)
            continue
        if action == "domain" and value and value not in seen:
            seen.add(value)
            result.append(value)

    visiting.remove(item)
    cache[item] = result
    return result


def expand_geosite_domain(domain: str, cache: dict[str, list[str]]) -> list[str]:
    item = domain[len("geosite:") :].strip()
    if not item:
        return []
    return expand_geosite_item(item, cache, set())


def iter_domains_for_switchy_output(
    rule: dict[str, Any],
    geosite_cache: dict[str, list[str]],
) -> list[str]:
    expanded_domains: list[str] = []
    for domain in iter_rule_domains(rule):
        domain = normalize_domain_for_switchy(domain)
        if domain.startswith("geosite:"):
            expanded_domains.extend(expand_geosite_domain(domain, geosite_cache))
            continue
        expanded_domains.append(domain)
    return expanded_domains


def write_switchy(rules: list[dict[str, Any]], output_path: Path) -> None:
    out_lines: list[str] = [
        "[SwitchyOmega Conditions]",
        "@with result",
        "",
    ]
    geosite_cache: dict[str, list[str]] = {}

    for i, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule #{i} must be an object")

        enabled = rule.get("enabled", True)
        if enabled is False:
            continue

        outbound_tag = rule.get("outboundTag")
        if not isinstance(outbound_tag, str) or not outbound_tag:
            raise ValueError(f"Rule #{i} must include non-empty outboundTag")

        # switchy only supports domain rules; ip/protocol/remarks are ignored.
        for domain in iter_domains_for_switchy_output(rule, geosite_cache):
            out_lines.append(f"{domain} +{outbound_tag}")

    output_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")


def write_simple_switchy(rules: list[dict[str, Any]], output_path: Path) -> None:
    today = date.today()
    out_lines: list[str] = [
        "[SwitchyOmega Conditions]",
        "; Require: ZeroOmega >= 2.3.2",
        f"; Date: {today.year}/{today.month}/{today.day}",
        "; Usage: https://github.com/FelisCatus/SwitchyOmega/wiki/RuleListUsage",
        "",
    ]
    geosite_cache: dict[str, list[str]] = {}

    for i, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule #{i} must be an object")

        enabled = rule.get("enabled", True)
        if enabled is False:
            continue

        outbound_tag = rule.get("outboundTag")
        if not isinstance(outbound_tag, str) or not outbound_tag:
            raise ValueError(f"Rule #{i} must include non-empty outboundTag")

        for domain in iter_domains_for_switchy_output(rule, geosite_cache):
            line = f"!{domain}" if outbound_tag == "direct" else domain
            out_lines.append(line)

    output_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")


def validate_outbound_tag_filename(outbound_tag: str, rule_number: int) -> None:
    if (
        outbound_tag in {".", ".."}
        or "/" in outbound_tag
        or "\\" in outbound_tag
        or "\0" in outbound_tag
    ):
        raise ValueError(
            f"Rule #{rule_number} outboundTag cannot be used as a filename: "
            f"{outbound_tag!r}"
        )


CLASH_IGNORED_RULE_KEYS = {
    "outboundTag",
    "remarks",
    "enabled",
    "type",
    "ruleTag",
    "webhook",
}


def value_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, (str, int)):
        return [str(value)]
    return []


def deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def collapse_clash_logic(operator: str, clauses: list[str]) -> str:
    if len(clauses) == 1:
        return clauses[0]
    payloads = ",".join(f"({clause})" for clause in clauses)
    return f"{operator},({payloads})"


def domain_clash_clauses(value: Any) -> list[str]:
    clauses: list[str] = []
    for raw in value_list(value):
        if not raw:
            continue
        if raw.startswith("full:"):
            rule_type, payload = "DOMAIN", raw[len("full:") :]
        elif raw.startswith("domain:"):
            rule_type, payload = "DOMAIN-SUFFIX", raw[len("domain:") :]
        elif raw.startswith(("keyword:", "plain:")):
            prefix = raw.split(":", 1)[0] + ":"
            rule_type, payload = "DOMAIN-KEYWORD", raw[len(prefix) :]
        elif raw.startswith(("regexp:", "regex:")):
            prefix = raw.split(":", 1)[0] + ":"
            rule_type, payload = "DOMAIN-REGEX", raw[len(prefix) :]
        elif raw.startswith("dotless:"):
            keyword = raw[len("dotless:") :]
            rule_type = "DOMAIN-REGEX"
            payload = rf"^[^.]*{re.escape(keyword)}[^.]*$"
        elif raw.startswith("geosite:"):
            rule_type, payload = "GEOSITE", raw[len("geosite:") :]
        elif raw.startswith("ext:") or raw.startswith("!"):
            # Mihomo cannot reference Xray's external geosite files, and Xray
            # does not define a generally compatible inverted domain syntax.
            continue
        else:
            # An unprefixed Xray domain is a substring/keyword match.
            rule_type, payload = "DOMAIN-KEYWORD", raw
        if payload:
            clauses.append(f"{rule_type},{payload}")
    return deduplicate(clauses)


def ip_clash_clause(raw: str, source: bool = False) -> str | None:
    if raw.startswith("ext:"):
        return None
    if raw.startswith("geoip:"):
        payload = raw[len("geoip:") :]
        if not payload:
            return None
        return f"{'SRC-GEOIP' if source else 'GEOIP'},{payload.upper()}"

    candidate = raw
    try:
        address = ipaddress.ip_address(candidate)
        candidate = f"{candidate}/{'32' if address.version == 4 else '128'}"
        version = address.version
    except ValueError:
        try:
            version = ipaddress.ip_network(candidate, strict=False).version
        except ValueError:
            return None

    if source:
        rule_type = "SRC-IP-CIDR"
    else:
        rule_type = "IP-CIDR6" if version == 6 else "IP-CIDR"
    return f"{rule_type},{candidate}"


def ip_clash_clauses(value: Any, source: bool = False) -> list[str]:
    positive: list[str] = []
    negative: list[str] = []
    for raw in value_list(value):
        inverted = raw.startswith("!")
        clause = ip_clash_clause(raw[1:] if inverted else raw, source=source)
        if clause is None:
            continue
        if inverted:
            negative.append(f"NOT,(({clause}))")
        else:
            positive.append(clause)

    # Xray combines all inverse IP entries with AND, then ORs that result with
    # every positive entry.
    clauses = positive
    if negative:
        clauses.append(collapse_clash_logic("AND", negative))
    return deduplicate(clauses)


def simple_clash_clauses(rule_type: str, value: Any) -> list[str]:
    return deduplicate(
        [f"{rule_type},{item}" for item in value_list(value) if item]
    )


def port_clash_clauses(rule_type: str, value: Any) -> list[str]:
    values = value_list(value)
    if not values:
        return []
    # Both formats use '-' for ranges. Mihomo accepts '/' between alternatives,
    # which avoids confusing those commas with the rule field separator.
    payload = "/".join(
        part.strip()
        for item in values
        for part in item.split(",")
        if part.strip()
    )
    return [f"{rule_type},{payload}"] if payload else []


def network_clash_clauses(value: Any) -> list[str]:
    networks = [
        part.strip().lower()
        for item in value_list(value)
        for part in item.split(",")
        if part.strip().lower() in {"tcp", "udp"}
    ]
    return simple_clash_clauses("NETWORK", networks)


def clash_condition_clauses(key: str, value: Any) -> list[str] | None:
    converters = {
        "domain": domain_clash_clauses,
        "ip": ip_clash_clauses,
        "port": lambda item: port_clash_clauses("DST-PORT", item),
        "sourcePort": lambda item: port_clash_clauses("SRC-PORT", item),
        "localPort": lambda item: port_clash_clauses("IN-PORT", item),
        "network": network_clash_clauses,
        "source": lambda item: ip_clash_clauses(item, source=True),
        "sourceIP": lambda item: ip_clash_clauses(item, source=True),
        "user": lambda item: simple_clash_clauses(
            "IN-USER",
            [entry for entry in value_list(item) if not entry.startswith("regexp:")],
        ),
        "inboundTag": lambda item: simple_clash_clauses("IN-NAME", item),
        "process": lambda item: simple_clash_clauses(
            "PROCESS-PATH",
            [
                entry
                for entry in value_list(item)
                if not entry.startswith(("self/", "xray/"))
            ],
        ),
    }
    converter = converters.get(key)
    return converter(value) if converter else None


def xray_rule_to_clash_lines(rule: dict[str, Any]) -> list[str]:
    condition_groups: list[list[str]] = []
    for key, value in rule.items():
        if key in CLASH_IGNORED_RULE_KEYS:
            continue
        clauses = clash_condition_clauses(key, value)
        if clauses is None or not clauses:
            # Dropping an AND condition would broaden the rule, so omit the
            # complete Xray rule when that condition cannot be represented.
            return []
        condition_groups.append(clauses)

    if not condition_groups:
        return []
    if len(condition_groups) == 1:
        return condition_groups[0]

    conditions = [collapse_clash_logic("OR", group) for group in condition_groups]
    return [collapse_clash_logic("AND", conditions)]


def write_seperate(rules: list[dict[str, Any]], output_path: Path) -> None:
    lines_by_tag: dict[str, list[str]] = {}

    for i, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule #{i} must be an object")

        enabled = rule.get("enabled", True)
        if enabled is False:
            continue

        outbound_tag = rule.get("outboundTag")
        if not isinstance(outbound_tag, str) or not outbound_tag:
            raise ValueError(f"Rule #{i} must include non-empty outboundTag")
        validate_outbound_tag_filename(outbound_tag, i)

        lines = xray_rule_to_clash_lines(rule)
        if lines:
            lines_by_tag.setdefault(outbound_tag, []).extend(lines)

    if output_path.exists() and not output_path.is_dir():
        raise ValueError(
            f"clash/seperate output path must be a directory: {output_path}"
        )
    output_path.mkdir(parents=True, exist_ok=True)

    for outbound_tag, lines in lines_by_tag.items():
        list_path = output_path / f"{outbound_tag}.list"
        list_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def detect_text_format(input_path: Path) -> str:
    lines = input_path.read_text(encoding="utf-8").splitlines()
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            return "routingA"
        if "->" in line and "(" in line and ")" in line:
            return "routingA"
        if SWITCHY_LINE_RE.match(line):
            return "switchy"
        raise ValueError(f"Unable to detect text format from line: {line}")
    return "switchy"


def infer_input_format(input_path: Path) -> str:
    ext = input_path.suffix.lower()
    if ext == ".json":
        return "xray"
    if ext == ".sorl":
        return "simple-switchy"
    if ext == ".txt":
        return detect_text_format(input_path)
    raise ValueError(f"Cannot infer input format from extension: {input_path.suffix}")


def infer_output_format(output_path: Path) -> str:
    ext = output_path.suffix.lower()
    if ext == ".json":
        return "xray"
    if ext == ".sorl":
        return "simple-switchy"
    if ext == ".txt":
        name = output_path.name.lower()
        if "switchy" in name:
            return "switchy"
        return "routingA"
    raise ValueError(f"Cannot infer output format from extension: {output_path.suffix}")


def read_rules(input_path: Path, fmt: str) -> list[dict[str, Any]]:
    if fmt == "xray":
        return read_xray(input_path)
    if fmt == "routingA":
        return read_routingA(input_path)
    if fmt == "switchy":
        return read_switchy(input_path)
    if fmt == "simple-switchy":
        return read_simple_switchy(input_path)
    raise ValueError(f"Unsupported input format: {fmt}")


def write_rules(rules: list[dict[str, Any]], output_path: Path, fmt: str) -> None:
    if fmt == "xray":
        write_xray(rules, output_path)
        return
    if fmt == "routingA":
        write_routingA(rules, output_path)
        return
    if fmt == "switchy":
        write_switchy(rules, output_path)
        return
    if fmt == "simple-switchy":
        write_simple_switchy(rules, output_path)
        return
    if fmt in {"clash", "seperate"}:
        write_seperate(rules, output_path)
        return
    raise ValueError(f"Unsupported output format: {fmt}")


def resolve_formats(input_path: Path, output_path: Path, from_format: str, to_format: str) -> tuple[str, str]:
    src = infer_input_format(input_path) if from_format == "auto" else from_format
    dst = infer_output_format(output_path) if to_format == "auto" else to_format
    if src == dst:
        raise ValueError("Input and output formats are the same")
    return src, dst


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Convert between xray, routingA, switchy, simple-switchy, "
            "and clash/seperate formats"
        )
    )
    parser.add_argument("input", help="Input file path")
    parser.add_argument("output", help="Output file path, or directory for clash/seperate")
    parser.add_argument(
        "--from-format",
        choices=["auto", "xray", "routingA", "switchy", "simple-switchy"],
        default="auto",
        help="Input format (default: auto)",
    )
    parser.add_argument(
        "--to-format",
        choices=[
            "auto",
            "xray",
            "routingA",
            "switchy",
            "simple-switchy",
            "clash",
            "seperate",
        ],
        default="auto",
        help=(
            "Output format; clash (also spelled seperate for compatibility) "
            "writes outboundTag.list files to a directory"
        ),
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    try:
        source_fmt, target_fmt = resolve_formats(
            input_path,
            output_path,
            args.from_format,
            args.to_format,
        )
        rules = read_rules(input_path, source_fmt)
        write_rules(rules, output_path, target_fmt)
    except ValueError as exc:
        raise SystemExit(f"Conversion failed: {exc}") from exc


if __name__ == "__main__":
    main()
