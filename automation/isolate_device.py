#!/usr/bin/env python3
"""Isolate a Defender for Endpoint device when a high-severity detection fires.

!!! ILLUSTRATIVE LAB CODE - NOT WIRED TO A LIVE TENANT !!!

This script shows how a detection-to-isolation step can be automated with the
Microsoft Defender for Endpoint API. It was written for a lab exercise with
synthetic data. Authentication is a stub that reads placeholder environment
variables; nothing here contains or needs real credentials.

Isolation cuts a device off the network (except from Defender itself). It is
disruptive, so the script is deliberately cautious:

  * It only acts on alerts whose severity is "High".
  * It needs a named human approver (--approved-by) before acting.
  * It runs in DRY-RUN mode unless --execute is given.

Note: Defender custom detection rules can isolate a device by themselves
(the rule's "Automated actions" setting), which is what the lab case study in
the README used. This script is the equivalent for pipelines that start
somewhere else, e.g. a Sentinel incident or a SOAR playbook.

Example (dry run, uses the synthetic sample alert):
    python isolate_device.py --alert sample_alert.json --approved-by "analyst.name"
"""

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
API_BASE = "https://api.securitycenter.microsoft.com/api"
API_SCOPE = "https://api.securitycenter.microsoft.com/.default"
REQUIRED_SEVERITY = "High"
MAX_RETRIES = 3

log = logging.getLogger("isolate_device")


class IsolationError(Exception):
    """Raised when isolation cannot be performed. The message is shown to the user."""


def load_alert(path: str) -> dict:
    """Read an alert from a JSON file and check it has the fields we need."""
    try:
        with open(path, encoding="utf-8") as handle:
            alert = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise IsolationError(f"Could not read alert file {path}: {error}") from None

    missing = [key for key in ("id", "title", "severity", "machineId") if not alert.get(key)]
    if missing:
        raise IsolationError(f"Alert is missing required field(s): {', '.join(missing)}")
    return alert


def check_gates(alert: dict, approved_by: str) -> None:
    """Refuse to continue unless the alert is High severity and a person approved it."""
    if alert["severity"] != REQUIRED_SEVERITY:
        raise IsolationError(
            f"Alert severity is {alert['severity']!r}; isolation is only allowed for "
            f"{REQUIRED_SEVERITY!r}. Triage it manually instead."
        )
    if not approved_by.strip():
        raise IsolationError("Isolation needs a named approver (--approved-by).")


def get_token() -> str:
    """Get an app-only access token with the client-credentials flow.

    STUB: reads placeholder environment variables. In a real deployment the app
    registration needs the Machine.Isolate application permission, and the secret
    belongs in a vault (e.g. Azure Key Vault), never in code or the repo.
    """
    tenant = os.environ.get("MDE_TENANT_ID")
    client_id = os.environ.get("MDE_CLIENT_ID")
    secret = os.environ.get("MDE_CLIENT_SECRET")
    if not all((tenant, client_id, secret)):
        raise IsolationError(
            "MDE_TENANT_ID, MDE_CLIENT_ID and MDE_CLIENT_SECRET must be set to run "
            "with --execute. (This lab repo ships without any credentials.)"
        )

    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
        "scope": API_SCOPE,
    }).encode()
    response = _request(TOKEN_URL.format(tenant=tenant), data=body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
    token = response.get("access_token")
    if not token:
        raise IsolationError("Token response did not contain an access_token.")
    return token


def _request(url: str, data: bytes, headers: dict) -> dict:
    """POST to the API, retrying on throttling (429) and server errors (5xx)."""
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=30) as reply:
                text = reply.read().decode() or "{}"
                return json.loads(text)
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:300]
            if error.code == 429 or error.code >= 500:
                wait = int(error.headers.get("Retry-After", 2 ** attempt))
                log.warning("HTTP %s (attempt %s/%s), retrying in %ss",
                            error.code, attempt, MAX_RETRIES, wait)
                time.sleep(wait)
                continue
            if error.code == 401 or error.code == 403:
                raise IsolationError(
                    f"Access denied (HTTP {error.code}). Check the app has Machine.Isolate "
                    f"permission with admin consent. Detail: {detail}") from None
            if error.code == 404:
                raise IsolationError(f"Device not found (HTTP 404). Detail: {detail}") from None
            raise IsolationError(f"API error HTTP {error.code}: {detail}") from None
        except urllib.error.URLError as error:
            raise IsolationError(f"Could not reach {url}: {error.reason}") from None
    raise IsolationError(f"Gave up after {MAX_RETRIES} attempts.")


def isolate(machine_id: str, comment: str, token: str) -> dict:
    """Ask Defender to fully isolate a device. Returns the MachineAction record."""
    url = f"{API_BASE}/machines/{urllib.parse.quote(machine_id)}/isolate"
    body = json.dumps({"Comment": comment, "IsolationType": "Full"}).encode()
    return _request(url, data=body, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--alert", required=True, help="path to the alert JSON")
    parser.add_argument("--approved-by", default="", help="name of the person approving isolation")
    parser.add_argument("--execute", action="store_true",
                        help="really call the API (default is a dry run)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        alert = load_alert(args.alert)
        check_gates(alert, args.approved_by)
        comment = (f"Auto-isolation for alert {alert['id']} ({alert['title']}), "
                   f"approved by {args.approved_by}")

        if not args.execute:
            log.info("DRY RUN: would isolate device %s. %s", alert["machineId"], comment)
            log.info("Re-run with --execute to call the API.")
            return 0

        action = isolate(alert["machineId"], comment, get_token())
        log.info("Isolation requested: action id %s, status %s",
                 action.get("id"), action.get("status"))
        return 0
    except IsolationError as error:
        log.error("%s", error)
        return 1


if __name__ == "__main__":
    sys.exit(main())
