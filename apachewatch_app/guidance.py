"""Plain-language investigation guidance derived from a finding's evidence."""

import math


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return f"{value:g}" if math.isfinite(value) else None
    except OverflowError:
        return None


def _action(label, view, source=None, query="", status="all"):
    return {"label": label, "view": view, "source": source, "query": query, "status": status}


def finding_guidance(item):
    evidence = item.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    result = {
        "trigger": item.get("summary") or "A finding was recorded during a monitoring check.",
        "impact": "Review the saved evidence to understand which requests or resources were affected.",
        "steps": [
            "Compare the evidence with the current logs and metrics.",
            "Check any recent application or server changes around the recorded times.",
            "Confirm the current behavior before marking this resolved.",
        ],
        "action": None,
    }
    source = item.get("source")
    if source == "alert":
        _threshold_guidance(result, evidence)
    elif source == "error":
        _error_guidance(result, item, evidence)
    elif source == "security":
        _security_guidance(result, evidence)
    return result


def _threshold_guidance(result, evidence):
    kind = evidence.get("alert_type")
    value, limit = _number(evidence.get("value")), _number(evidence.get("threshold"))
    if kind == "disk_percent":
        if value is not None and limit is not None:
            result["trigger"] = f"Recorded disk usage was {value}%, at or above the {limit}% threshold."
        result.update(
            impact="If the disk fills up, the server may be unable to write logs, uploads, or application data.",
            steps=[
                "Identify which directories or files are growing, including logs, uploads, and backups.",
                "Review log rotation and retention, and plan cleanup or additional capacity.",
                "Confirm disk usage is below the threshold before marking this resolved.",
            ],
            action=_action("Check system resources", "overview"),
        )
    elif kind in {"server_errors_5xx", "client_errors_4xx"}:
        server_errors = kind == "server_errors_5xx"
        label = "server errors" if server_errors else "client errors"
        if value is not None and limit is not None:
            result["trigger"] = f"The recent log sample contains {value} {label}; your threshold is {limit}."
        result.update(
            impact=("Some requests received a server-error response. The application or a service it depends on may be failing."
                    if server_errors else "Visitors may be reaching missing or restricted pages. Automated probes can also increase this count."),
            steps=([
                "Open the failed access requests and note their URLs and timestamps.",
                "Compare those times with Apache and application error logs; review recent deployments and dependency availability.",
                "Retry an affected URL and confirm new requests succeed before marking this resolved.",
            ] if server_errors else [
                "Open the client-error requests and distinguish missing pages (404) from access restrictions (401/403).",
                "Check the requested URLs, site links, and access rules to decide whether these responses were expected.",
                "Verify legitimate requests work; review repeated unwanted probes in Security.",
            ]),
            action=_action("Inspect failed requests" if server_errors else "Inspect client errors", "logs", "access", status="5" if server_errors else "4"),
        )
    elif kind == "requests_per_ip":
        ip = evidence.get("ip")
        if value is not None and limit is not None:
            client = str(ip) if ip else "One client"
            result["trigger"] = f"{client} made {value} requests in the recent log sample; your threshold is {limit}."
        result.update(
            impact="A busy client can consume server capacity. Crawlers, monitoring tools, and shared networks can also produce legitimate high volumes.",
            steps=[
                "Inspect this client's requested paths, response codes, and request timing.",
                "Check whether it is a legitimate visitor, crawler, shared proxy, or trusted monitoring tool.",
                "Review Security if the requests are unwanted, then check fresh traffic before closing the finding.",
            ],
            action=_action("Inspect this client's requests" if ip else "Inspect recent requests", "logs", "access", query=str(ip) if ip else ""),
        )
    elif kind == "bot_percentage":
        if value is not None and limit is not None:
            result["trigger"] = f"Traffic identified as bots reached {value}% of the recent log sample; your threshold is {limit}%."
        result.update(
            impact="Search engines and monitoring tools can produce legitimate bot traffic. Unexpected automated traffic can consume capacity.",
            steps=[
                "Open Analytics to compare bot activity with human traffic.",
                "Review the busiest client IPs and their requested paths, and verify any claimed crawler identity.",
                "Review unwanted activity in Security and check the traffic mix after any changes.",
            ],
            action=_action("Review bot traffic", "analytics"),
        )


def _error_guidance(result, item, evidence):
    count = _number(evidence.get("count")) or _number(item.get("occurrence_count"))
    level = str(evidence.get("level", "")).lower()
    label = "warning" if level in {"warn", "warning"} else "error"
    if count is not None:
        result["trigger"] = f"The same type of {label} appeared {count} times in the recent error-log sample."
    result.update(
        impact="A recurring log message can point to an ongoing request or configuration problem. The full message helps identify the affected component.",
        steps=[
            "Open the error logs and read the full message around the recorded timestamps.",
            "Compare it with matching access requests and recent application or configuration changes.",
            "After addressing the cause, check fresh log entries and new requests before marking this resolved.",
        ],
        action=_action("Inspect error logs", "logs", "error", query=item.get("related_query") or ""),
    )
    message = str(evidence.get("message") or item.get("summary") or "").lower()
    if any(text in message for text in ("permission denied", "client denied by server configuration", "access denied", "ah00035", "search permissions are missing")):
        result.update(
            impact="Access to a request or resource was denied. Check whether the restriction was intended before changing permissions or access rules.",
            steps=[
                "Identify the exact path in the error and whether it should be accessible.",
                "Review the relevant Apache access rules and file read or directory traversal permissions.",
                "Test an allowed request and check fresh logs before marking this resolved.",
            ],
        )
    elif any(text in message for text in ("fatal error", "uncaught exception", "traceback")):
        result.update(
            impact="The message indicates an application error. The application's own logs may contain the exception details needed to investigate.",
            steps=[
                "Read the application's logs at the recorded error times for the full exception details.",
                "Review recent code or configuration changes and the dependencies named in the exception.",
                "Verify the affected request works and check fresh logs before marking this resolved.",
            ],
        )
    elif any(text in message for text in ("proxy", "upstream", "backend", "connection refused", "ah01079", "ah01102", "ah00957")):
        result.update(
            impact="The message points to communication with another application or service. Affected requests may fail while that connection is unavailable.",
            steps=[
                "Read the error to identify the upstream application, address, or connection involved.",
                "Check that the named application is running and reachable from Apache, and compare its logs with the error times.",
                "Retry an affected request and confirm it succeeds with fresh log entries.",
            ],
        )
    elif any(text in message for text in ("timed out", "timeout")):
        result.update(
            impact="A request or connection waited longer than allowed. Affected requests may be slow or fail before completing.",
            steps=[
                "Read the full error to identify which request, connection, or component timed out.",
                "Compare that component's load and logs with the recorded times.",
                "Retry an affected request after addressing the cause and check fresh logs.",
            ],
        )
    elif any(text in message for text in ("file does not exist", "no such file or directory", "file not found", "script not found")):
        result.update(
            impact="A resource named in the message could not be found. Requests depending on it may fail.",
            steps=[
                "Identify the missing file, script, or resource named in the error.",
                "Compare the deployed files with the URL, document-root, or alias mapping that should reach it.",
                "Retry an affected request and confirm it succeeds with fresh log entries.",
            ],
        )


def _security_guidance(result, evidence):
    reasons = evidence.get("reasons")
    if isinstance(reasons, list):
        reasons = [reason for reason in reasons if isinstance(reason, str) and reason]
        if reasons:
            result["trigger"] = "; ".join(reasons[:2]).rstrip(".") + "."
    is_range = evidence.get("target_type") == "range"
    target = evidence.get("target")
    result.update(
        impact=("Several flagged client IPs share this network. A shared range can also contain unrelated legitimate visitors."
                if is_range else "These request patterns can indicate automated probing. Review the evidence to determine whether the traffic is unwanted."),
        steps=([
            "Review each member IP and its flagged paths and response codes.",
            "Check whether the network belongs to a trusted proxy, crawler, or other shared service.",
            "If action is needed, review a narrowly scoped rule in Security and verify fresh traffic after any change.",
        ] if is_range else [
            "Inspect this client's access requests and flagged paths.",
            "Check whether it is a legitimate visitor, crawler, or trusted monitoring tool.",
            "If the requests are unwanted, review a specific rule in Security and verify fresh traffic after any change.",
        ]),
        action=(_action("Review security details", "security") if is_range or not target
                else _action("Inspect this client's requests", "logs", "access", query=str(target))),
    )
