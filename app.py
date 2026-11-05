import os
import re
import threading
import time
import uuid
from urllib.parse import urljoin

import requests
from flask import Flask, jsonify, redirect, render_template, request, url_for
from dotenv import load_dotenv


API_ROOT = "https://api.meraki.com/api/v1"
CLIENT_TIMESPAN_SECONDS = 30 * 24 * 60 * 60
app = Flask(__name__)
# Use the local .env settings even when the process inherits a generic PORT value.
load_dotenv(override=True)
SCANS = {}
SCANS_LOCK = threading.Lock()


class MerakiAPI:
    def __init__(self, api_key):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-Cisco-Meraki-API-Key": api_key,
                "Accept": "application/json",
                "User-Agent": "MerakiNATInventory/1.0",
            }
        )

    def get_all(self, path, params=None):
        url = urljoin(API_ROOT + "/", path.lstrip("/"))
        query = dict(params or {})
        results = []
        while url:
            response = self.session.get(url, params=query, timeout=(10, 60))
            if response.status_code == 429:
                delay = int(response.headers.get("Retry-After", "1"))
                time.sleep(max(1, min(delay, 30)))
                continue
            query = None  # The next-page URL already contains its query string.
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, list):
                results.extend(payload)
            elif isinstance(payload, dict):
                # Most list endpoints return arrays. Keep object responses usable
                # so the caller can report a clear error for unexpected schemas.
                return payload
            else:
                return payload
            link = response.headers.get("Link", "")
            next_link = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = next_link.group(1) if next_link else None
        return results


def get_clients_by_ip(api, network_id):
    clients = api.get_all(
        f"/networks/{network_id}/clients",
        params={"timespan": CLIENT_TIMESPAN_SECONDS, "perPage": 1000},
    )
    if not isinstance(clients, list):
        return {}, "Réponse clients Meraki inattendue."
    by_ip = {}
    for client in clients:
        ip = client.get("ip")
        if ip and (
            ip not in by_ip
            or (client.get("lastSeen") or "") >= (by_ip[ip].get("lastSeen") or "")
        ):
            by_ip[ip] = client
    return by_ip, None


def collect_nat_rules(api, network_id, clients_by_ip):
    rules = []
    errors = []

    def display_value(value, fallback):
        if isinstance(value, (list, tuple)):
            return ", ".join(str(part) for part in value) if value else fallback
        return value or fallback

    def display_allowed_ips(value):
        if not value:
            return ["Toutes les IP"]
        return [value] if isinstance(value, str) else value

    def add_rule(kind, name, public_ip, protocol, public_ports, local_ip,
                 local_ports, allowed_ips, uplink=None):
        client = clients_by_ip.get(local_ip, {}) if local_ip else {}
        rules.append(
            {
                "kind": kind,
                "name": name or "Sans nom",
                "public_ip": public_ip or "—",
                "protocol": protocol or "—",
                "public_ports": display_value(public_ports, "Tous les ports"),
                "destination_ip": local_ip or "—",
                "destination_ports": display_value(local_ports, "Tous les ports"),
                "allowed_ips": display_allowed_ips(allowed_ips),
                "uplink": uplink or "—",
                "os": client.get("os") or "Non identifié par Meraki",
                "client_name": client.get("description") or client.get("dhcpHostname") or "",
            }
        )

    try:
        forwarding = api.get_all(
            f"/networks/{network_id}/appliance/firewall/portForwardingRules"
        )
        for rule in forwarding.get("rules", []) if isinstance(forwarding, dict) else []:
            add_rule(
                "Redirection de ports",
                rule.get("name"),
                rule.get("publicIp"),
                rule.get("protocol"),
                rule.get("publicPort"),
                rule.get("lanIp"),
                rule.get("localPort"),
                rule.get("allowedIps"),
                rule.get("uplink"),
            )
    except requests.RequestException as exc:
        errors.append(f"Redirections de ports : {api_error_message(exc)}")

    try:
        one_to_one = api.get_all(
            f"/networks/{network_id}/appliance/firewall/oneToOneNatRules"
        )
        for rule in one_to_one.get("rules", []) if isinstance(one_to_one, dict) else []:
            for inbound in rule.get("allowedInbound", []):
                ports = inbound.get("destinationPorts") or "Tous les ports"
                add_rule(
                    "NAT 1:1",
                    rule.get("name"),
                    rule.get("publicIp"),
                    inbound.get("protocol"),
                    ports,
                    rule.get("lanIp"),
                    ports,
                    inbound.get("allowedIps"),
                    rule.get("uplink"),
                )
    except requests.RequestException as exc:
        errors.append(f"NAT 1:1 : {api_error_message(exc)}")

    try:
        one_to_many = api.get_all(
            f"/networks/{network_id}/appliance/firewall/oneToManyNatRules"
        )
        for rule in one_to_many.get("rules", []) if isinstance(one_to_many, dict) else []:
            for port_rule in rule.get("portRules", []):
                add_rule(
                    "NAT 1:Many",
                    port_rule.get("name") or rule.get("name"),
                    rule.get("publicIp"),
                    port_rule.get("protocol"),
                    port_rule.get("publicPort"),
                    port_rule.get("localIp") or port_rule.get("lanIp"),
                    port_rule.get("localPort"),
                    port_rule.get("allowedIps"),
                    rule.get("uplink"),
                )
    except requests.RequestException as exc:
        errors.append(f"NAT 1:Many : {api_error_message(exc)}")

    return rules, errors


def api_error_message(exc):
    response = getattr(exc, "response", None)
    if response is not None:
        if response.status_code == 401:
            return (
                "HTTP 401 — Meraki refuse la clé API. Vérifiez que vous avez remplacé le texte exemple par une clé API Dashboard active, "
                "créée depuis le profil de votre utilisateur Meraki, et relancez l’application après l’avoir définie. "
                "Ne préfixez pas la clé par « Bearer »."
            )
        if response.status_code == 403:
            return (
                "HTTP 403 — la clé est reconnue, mais votre utilisateur n’a pas accès à cette ressource. "
                "Vérifiez ses droits de lecture sur l’organisation et les paramètres MX concernés."
            )
        try:
            detail = response.json().get("errors", [response.text])
            if isinstance(detail, list):
                detail = "; ".join(str(item) for item in detail)
            return f"HTTP {response.status_code} — {detail}"
        except (ValueError, AttributeError):
            return f"HTTP {response.status_code} — {response.text[:200]}"
    return str(exc)


def run_inventory(api_key, progress_callback=None):
    api = MerakiAPI(api_key)
    orgs = api.get_all("/organizations", params={"perPage": 1000})
    if not isinstance(orgs, list):
        raise ValueError("La réponse des organisations Meraki est inattendue.")

    inventory = []
    warnings = []
    total_orgs = len(orgs)
    for org_index, org in enumerate(orgs, start=1):
        org_id = org["id"]
        org_name = org.get("name", org_id)
        if progress_callback:
            progress_callback(org_index, total_orgs, org_name)
        try:
            networks = api.get_all(
                f"/organizations/{org_id}/networks", params={"perPage": 1000}
            )
        except requests.RequestException as exc:
            warnings.append(f"{org.get('name', org_id)} : {api_error_message(exc)}")
            continue
        if not isinstance(networks, list):
            warnings.append(f"{org.get('name', org_id)} : liste de réseaux inattendue.")
            continue

        uplink_status_by_device = {}
        if any("appliance" in network.get("productTypes", []) for network in networks):
            try:
                # Meraki exposes appliance uplink statuses at organization scope.
                uplink_statuses = api.get_all(
                    f"/organizations/{org_id}/appliance/uplink/statuses"
                )
                if isinstance(uplink_statuses, list):
                    uplink_status_by_device = {
                        (status.get("networkId"), status.get("serial")): status
                        for status in uplink_statuses
                        if isinstance(status, dict)
                    }
            except requests.RequestException as exc:
                warnings.append(
                    f"{org.get('name', org_id)} — état WAN : {api_error_message(exc)}"
                )

        for network in networks:
            if "appliance" not in network.get("productTypes", []):
                continue
            network_id = network["id"]
            try:
                devices = api.get_all(f"/networks/{network_id}/devices", params={"perPage": 1000})
                mx_devices = [
                    device for device in devices
                    if isinstance(device, dict) and (device.get("model") or "").upper().startswith("MX")
                ] if isinstance(devices, list) else []
            except requests.RequestException as exc:
                warnings.append(
                    f"{network.get('name', network_id)} — appareils : {api_error_message(exc)}"
                )
                continue
            if not mx_devices:
                continue

            for device in mx_devices:
                status = uplink_status_by_device.get(
                    (network_id, device.get("serial")), {}
                )
                uplinks = {}
                for item in status.get("uplinks") or []:
                    if isinstance(item, dict):
                        interface = (item.get("interface") or "").lower()
                        if interface:
                            uplinks[interface] = item
                device["wan_status"] = {
                    "wan1": uplinks.get("wan1", {}),
                    "wan2": uplinks.get("wan2", {}),
                }

            rules, rule_errors = collect_nat_rules(api, network_id, {})
            if rules:
                try:
                    clients_by_ip, client_error = get_clients_by_ip(api, network_id)
                    if client_error:
                        warnings.append(f"{network.get('name', network_id)} — {client_error}")
                except requests.RequestException as exc:
                    clients_by_ip = {}
                    warnings.append(
                        f"{network.get('name', network_id)} — clients : {api_error_message(exc)}"
                    )
                for rule in rules:
                    client = clients_by_ip.get(rule["destination_ip"], {})
                    rule["os"] = client.get("os") or "Non identifié par Meraki"
                    rule["client_name"] = client.get("description") or client.get("dhcpHostname") or ""
            warnings.extend(
                f"{network.get('name', network_id)} — {error}" for error in rule_errors
            )
            inventory.append(
                {
                    "organization": org.get("name", org_id),
                    "network": network.get("name", network_id),
                    "network_id": network_id,
                    "devices": mx_devices,
                    "rules": rules,
                    "warnings": rule_errors,
                }
            )
    return inventory, warnings


def update_scan(scan_id, **changes):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
        if scan is not None:
            scan.update(changes)


def run_scan_in_background(scan_id, api_key):
    def report_progress(current, total, organization):
        update_scan(
            scan_id,
            current=current,
            total=total,
            organization=organization,
            message=f"Organisation {current}/{total} : {organization}",
        )

    try:
        inventory, warnings = run_inventory(api_key, report_progress)
        with SCANS_LOCK:
            total = SCANS.get(scan_id, {}).get("total", 0)
        update_scan(
            scan_id,
            done=True,
            current=total,
            message="Inventaire terminé.",
            inventory=inventory,
            warnings=warnings,
        )
    except requests.RequestException as exc:
        update_scan(scan_id, done=True, error=api_error_message(exc))
    except Exception as exc:
        update_scan(scan_id, done=True, error=f"Erreur pendant l’inventaire : {exc}")


@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    inventory = None
    warnings = []
    scan_status = None
    api_key_configured = bool(os.getenv("MERAKI_DASHBOARD_API_KEY"))

    if request.method == "GET" and request.args.get("scan_id"):
        with SCANS_LOCK:
            scan_status = dict(SCANS.get(request.args["scan_id"], {}))
        if scan_status.get("done"):
            error = scan_status.get("error")
            inventory = scan_status.get("inventory")
            warnings = scan_status.get("warnings", [])

    if request.method == "POST":
        api_key = os.getenv("MERAKI_DASHBOARD_API_KEY", "").strip()
        if not api_key:
            error = "Configurez MERAKI_DASHBOARD_API_KEY avant de lancer l’inventaire."
        else:
            scan_id = uuid.uuid4().hex
            with SCANS_LOCK:
                SCANS[scan_id] = {
                    "done": False,
                    "current": 0,
                    "total": 0,
                    "organization": "",
                    "message": "Connexion à l’API Meraki…",
                }
            threading.Thread(
                target=run_scan_in_background,
                args=(scan_id, api_key),
                daemon=True,
            ).start()
            return redirect(url_for("index", scan_id=scan_id))

    return render_template(
        "index.html",
        error=error,
        inventory=inventory,
        warnings=warnings,
        api_key_configured=api_key_configured,
        scan_status=scan_status,
    )


@app.get("/status/<scan_id>")
def scan_status(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
        if scan is None:
            return jsonify({"error": "Inventaire introuvable. Relancez le scan."}), 404
        status = {
            key: scan.get(key)
            for key in ("done", "current", "total", "organization", "message", "error")
        }
    return jsonify(status)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "8086")), debug=False)
