"""
Mist MSP WLAN exporter.

Logs onto the Mist cloud with user credentials (email/password), asks which MSP to
export, finds every Org managed under that MSP, and exports every WLAN with
its security settings to a CSV file.

Credentials are read, in order of precedence, from:
  1. --user / --host command line arguments
  2. a .env file (MIST_USER, MIST_PASSWORD, MIST_HOST) - see .env.example
  3. an interactive prompt (password is not echoed; 2FA code asked if enabled)
"""

import argparse
import csv
import os
import sys
from datetime import datetime

import mistapi

CSV_COLUMNS = [
    "msp_name",
    "org_name",
    "org_id",
    "scope",              # org (template) or site
    "template_name",
    "site_name",
    "wlan_id",
    "ssid",
    "enabled",
    "hidden_ssid",
    "auth_type",          # open / psk / eap / eap192 / wep / psk-tkip ...
    "encryption",         # auth.pairwise (wpa2-ccmp, wpa3, ...)
    "psk",                # masked unless --show-psk
    "multi_psk_only",
    "private_wlan",
    "owe",
    "mac_auth",
    "auth_servers",
    "acct_servers",
    "auth_server_selection",
    "radsec_enabled",
    "fast_roaming",       # roam_mode (NONE / OKC / 11r)
    "disable_11w_pmf",
    "client_isolation",
    "captive_portal",
    "portal_auth",
    "vlan_enabled",
    "vlan_ids",
    "dynamic_vlan",
    "bands",
    "apply_to",
]


# --------------------------------------------------------------------------- #
# Session / discovery
# --------------------------------------------------------------------------- #
def open_session(host: str | None, user: str | None, env_file: str | None):
    """Create a mistapi session logged in with email/password."""
    if env_file and os.path.isfile(env_file):
        session = mistapi.APISession(env_file=env_file, show_cli_notif=False,
                                     console_log_level=30)
    else:
        session = mistapi.APISession(show_cli_notif=False, console_log_level=30)

    if host:
        session.set_cloud(host)
    elif not session.get_cloud():
        session.set_cloud("api.mist.com")

    if user:
        session.set_email(user)

    # mistapi prompts for any missing email/password and for the 2FA code
    session.login()
    if not session.get_authentication_status():
        sys.exit("ERROR: login to Mist failed - check the credentials / host.")
    return session


def get_all(session, response) -> list:
    """Return every item of a (possibly paginated) list response."""
    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code}: {response.data}")
    return mistapi.get_all(session, response)


def select_msp(session, msp_filter: str | None) -> tuple[str, str]:
    """
    Return (msp_id, msp_name) of the MSP to export: the one named by --msp,
    otherwise the one the user picks from a numbered menu.
    """
    privileges = mistapi.api.v1.self.self.getSelf(session).data.get("privileges", [])
    msps = sorted({(p["msp_id"], p.get("name", "")) for p in privileges
                   if p.get("scope") == "msp" and p.get("msp_id")},
                  key=lambda m: m[1].lower())
    if not msps:
        sys.exit("ERROR: this user has no MSP privileges.")

    if msp_filter:
        for msp in msps:
            if msp_filter in msp:
                return msp
        sys.exit(f"ERROR: user has no access to MSP '{msp_filter}'.")

    print("\nMSPs available to this user:")
    for i, (msp_id, msp_name) in enumerate(msps, 1):
        print(f"  {i:>3}. {msp_name}  ({msp_id})")
    while True:
        choice = input(f"Select the MSP to export [1-{len(msps)}, q to quit]: ").strip()
        if choice.lower() == "q":
            sys.exit("Cancelled.")
        if choice.isdigit() and 1 <= int(choice) <= len(msps):
            return msps[int(choice) - 1]
        print("  Invalid choice, try again.")


def list_msp_orgs(session, msp_id: str, msp_name: str) -> list[dict]:
    """Return {"msp_name", "org_id", "org_name"} for every org under the MSP."""
    print(f"\nMSP '{msp_name}' ({msp_id}): listing orgs...")
    resp = mistapi.api.v1.msps.orgs.listMspOrgs(session, msp_id)
    orgs = [{"msp_name": msp_name, "org_id": org["id"], "org_name": org.get("name", "")}
            for org in get_all(session, resp)]
    return sorted(orgs, key=lambda o: o["org_name"].lower())


# --------------------------------------------------------------------------- #
# WLAN extraction
# --------------------------------------------------------------------------- #
def _servers(servers: list | None) -> str:
    return "; ".join(f"{s.get('host', '')}:{s.get('port', '')}" for s in servers or [])


def _yn(value) -> str:
    return "" if value is None else ("yes" if value else "no")


def wlan_to_row(wlan: dict, org: dict, scope: str, template_name: str,
                site_name: str, show_psk: bool) -> dict:
    auth = wlan.get("auth") or {}
    portal = wlan.get("portal") or {}
    psk = auth.get("psk")
    if psk and not show_psk:
        psk = "********"

    vlan_ids = wlan.get("vlan_ids") or wlan.get("vlan_id") or ""
    if isinstance(vlan_ids, list):
        vlan_ids = ",".join(str(v) for v in vlan_ids)

    dyn_vlan = wlan.get("dynamic_vlan") or {}
    bands = wlan.get("bands") or ([wlan["band"]] if wlan.get("band") else [])

    return {
        "msp_name": org["msp_name"],
        "org_name": org["org_name"],
        "org_id": org["org_id"],
        "scope": scope,
        "template_name": template_name,
        "site_name": site_name,
        "wlan_id": wlan.get("id", ""),
        "ssid": wlan.get("ssid", ""),
        "enabled": _yn(wlan.get("enabled")),
        "hidden_ssid": _yn(wlan.get("hide_ssid")),
        "auth_type": auth.get("type", ""),
        "encryption": ",".join(auth.get("pairwise") or []),
        "psk": psk or "",
        "multi_psk_only": _yn(auth.get("multi_psk_only")),
        "private_wlan": _yn(auth.get("private_wlan")),
        "owe": auth.get("owe", ""),
        "mac_auth": _yn(auth.get("enable_mac_auth")),
        "auth_servers": _servers(wlan.get("auth_servers")),
        "acct_servers": _servers(wlan.get("acct_servers")),
        "auth_server_selection": wlan.get("auth_server_selection", ""),
        "radsec_enabled": _yn((wlan.get("radsec") or {}).get("enabled")),
        "fast_roaming": wlan.get("roam_mode", ""),
        "disable_11w_pmf": _yn(wlan.get("disable_11w")),
        "client_isolation": _yn(wlan.get("isolation")),
        "captive_portal": _yn(portal.get("enabled")),
        "portal_auth": portal.get("auth", "") if portal.get("enabled") else "",
        "vlan_enabled": _yn(wlan.get("vlan_enabled")),
        "vlan_ids": vlan_ids,
        "dynamic_vlan": _yn(dyn_vlan.get("enabled")),
        "bands": ",".join(bands),
        "apply_to": wlan.get("apply_to", ""),
    }


def collect_org_wlans(session, org: dict, include_sites: bool, show_psk: bool) -> list[dict]:
    org_id = org["org_id"]
    rows: list[dict] = []

    templates = get_all(session, mistapi.api.v1.orgs.templates.listOrgTemplates(session, org_id))
    tmpl_names = {t["id"]: t.get("name", "") for t in templates}

    sites = get_all(session, mistapi.api.v1.orgs.sites.listOrgSites(session, org_id))
    site_names = {s["id"]: s.get("name", "") for s in sites}

    # Org-level WLANs (defined in WLAN templates)
    org_wlans = get_all(session, mistapi.api.v1.orgs.wlans.listOrgWlans(session, org_id))
    seen = set()
    for wlan in org_wlans:
        seen.add(wlan.get("id"))
        rows.append(wlan_to_row(
            wlan, org, "org",
            tmpl_names.get(wlan.get("template_id"), ""),
            site_names.get(wlan.get("site_id"), ""),
            show_psk))

    # Site-level WLANs (configured directly on a site, not via a template)
    if include_sites:
        for site_id, site_name in site_names.items():
            resp = mistapi.api.v1.sites.wlans.listSiteWlans(session, site_id)
            for wlan in get_all(session, resp):
                if wlan.get("id") in seen:
                    continue
                seen.add(wlan.get("id"))
                rows.append(wlan_to_row(wlan, org, "site", "", site_name, show_psk))

    return rows


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export all Orgs and WLANs (with security settings) from a Mist MSP to CSV.")
    parser.add_argument("--host", help="Mist API host, e.g. api.mist.com, api.eu.mist.com, "
                                       "api.gc1.mist.com (default: MIST_HOST or api.mist.com)")
    parser.add_argument("--user", help="Mist login email (default: MIST_USER or prompt)")
    parser.add_argument("--env-file", default=".env",
                        help="env file with MIST_HOST / MIST_USER / MIST_PASSWORD")
    parser.add_argument("--msp", help="MSP name or id to export (skips the selection prompt)")
    parser.add_argument("-o", "--output",
                        default=f"mist_wlans_{datetime.now():%Y%m%d_%H%M%S}.csv",
                        help="output CSV file")
    parser.add_argument("--no-site-wlans", action="store_true",
                        help="skip site-level WLANs (faster: one fewer call per site)")
    parser.add_argument("--show-psk", action="store_true",
                        help="write PSK passphrases in clear text (masked by default)")
    args = parser.parse_args()

    session = open_session(args.host, args.user, args.env_file)
    try:
        export(session, args)
    finally:
        session.logout()


def export(session, args) -> None:
    msp_id, msp_name = select_msp(session, args.msp)
    orgs = list_msp_orgs(session, msp_id, msp_name)
    print(f"Found {len(orgs)} org(s).")

    all_rows: list[dict] = []
    failed: list[str] = []
    for i, org in enumerate(orgs, 1):
        print(f"[{i}/{len(orgs)}] {org['org_name']} ... ", end="", flush=True)
        try:
            rows = collect_org_wlans(session, org, not args.no_site_wlans, args.show_psk)
        except Exception as exc:  # keep going if one org is not readable
            print(f"FAILED ({exc})")
            failed.append(org["org_name"])
            continue
        if not rows:  # still list the org so every managed org appears in the CSV
            rows = [{**{c: "" for c in CSV_COLUMNS}, "msp_name": org["msp_name"],
                     "org_name": org["org_name"], "org_id": org["org_id"]}]
            print("no WLANs")
        else:
            print(f"{len(rows)} WLAN(s)")
        all_rows.extend(rows)

    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\nWrote {len(all_rows)} row(s) to {os.path.abspath(args.output)}")
    if failed:
        print(f"WARNING: {len(failed)} org(s) could not be read: {', '.join(failed)}")


if __name__ == "__main__":
    main()
