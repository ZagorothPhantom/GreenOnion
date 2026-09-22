from __future__ import annotations

import socket
import subprocess
import time
from dataclasses import dataclass, asdict
from typing import Any

import requests


USER_AGENT = "TorVPNChecker/1.0"
TIMEOUT = 10

IP_ENDPOINTS = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.co/json",
    "https://ipinfo.io/json",
]

TOR_CHECK_URL = "https://check.torproject.org/api/ip"

# Public DNS resolvers. These are used only as comparison points.
KNOWN_DNS_RESOLVERS = {
    "Google": {"8.8.8.8", "8.8.4.4"},
    "Cloudflare": {"1.1.1.1", "1.0.0.1"},
    "Quad9": {"9.9.9.9", "149.112.112.112"},
    "OpenDNS": {"208.67.222.222", "208.67.220.220"},
}


@dataclass
class CheckResult:
    name: str
    status: str
    summary: str
    details: str
    latency_ms: float | None = None


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def get_public_ip(session: requests.Session) -> CheckResult:
    errors = []

    for endpoint in IP_ENDPOINTS:
        started = time.perf_counter()

        try:
            response = session.get(endpoint, timeout=TIMEOUT)
            response.raise_for_status()
            data = response.json()

            ip = data.get("ip")
            if not ip:
                errors.append(f"{endpoint}: response did not contain an IP")
                continue

            latency = (time.perf_counter() - started) * 1000

            return CheckResult(
                name="Public IP",
                status="PASS",
                summary=f"Public IP: {ip}",
                details=f"Endpoint: {endpoint}\n"
                f"Country: {data.get('country', 'unknown')}\n"
                f"ISP/Organization: {data.get('org', data.get('organization', 'unknown'))}",
                latency_ms=round(latency, 1),
            )

        except Exception as exc:
            errors.append(f"{endpoint}: {exc}")

    return CheckResult(
        name="Public IP",
        status="ERROR",
        summary="Could not determine public IP",
        details="\n".join(errors),
    )


def check_tor(session: requests.Session) -> CheckResult:
    started = time.perf_counter()

    try:
        response = session.get(TOR_CHECK_URL, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()

        is_tor = bool(data.get("IsTor"))
        ip = data.get("IP", "unknown")
        latency = (time.perf_counter() - started) * 1000

        if is_tor:
            return CheckResult(
                name="Tor",
                status="PASS",
                summary="Traffic appears to be using Tor",
                details=f"Tor check IP: {ip}\n"
                "The remote service identifies this connection as a Tor exit.",
                latency_ms=round(latency, 1),
            )

        return CheckResult(
            name="Tor",
            status="WARN",
            summary="Traffic does not appear to be using Tor",
            details=f"Tor check IP: {ip}\n"
            "This does not prove that Tor is unavailable; it may not be configured "
            "as the application's proxy.",
            latency_ms=round(latency, 1),
        )

    except Exception as exc:
        return CheckResult(
            name="Tor",
            status="ERROR",
            summary="Tor status could not be checked",
            details=str(exc),
        )


def get_local_dns_servers() -> list[str]:
    """
    Retrieves DNS servers configured on the local machine.

    This is intentionally best-effort because DNS configuration differs
    between Windows, macOS, Linux, NetworkManager, systemd-resolved,
    VPN clients, and containers.
    """
    servers: list[str] = []

    try:
        if __import__("platform").system() == "Windows":
            output = subprocess.check_output(
                ["ipconfig", "/all"],
                text=True,
                errors="ignore",
                timeout=5,
            )

            for line in output.splitlines():
                if "DNS Servers" in line or line.strip().startswith((" ", "\t")):
                    parts = line.replace(":", " ").split()
                    for part in parts:
                        try:
                            socket.inet_aton(part)
                            if part not in servers:
                                servers.append(part)
                        except OSError:
                            pass

        else:
            resolv_conf = "/etc/resolv.conf"

            try:
                with open(resolv_conf, "r", encoding="utf-8") as file:
                    for line in file:
                        if line.strip().startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2 and parts[1] not in servers:
                                servers.append(parts[1])
            except OSError:
                pass

            # macOS and some Linux systems expose DNS information here.
            try:
                output = subprocess.check_output(
                    ["scutil", "--dns"],
                    text=True,
                    errors="ignore",
                    timeout=5,
                )

                for line in output.splitlines():
                    if "nameserver[" in line and ":" in line:
                        address = line.split(":", 1)[1].strip()
                        if address not in servers:
                            servers.append(address)
            except (OSError, subprocess.SubprocessError):
                pass

    except Exception:
        pass

    return servers


def check_dns() -> CheckResult:
    dns_servers = get_local_dns_servers()

    if not dns_servers:
        return CheckResult(
            name="DNS Leak",
            status="WARN",
            summary="Could not identify local DNS servers",
            details=(
                "The operating system did not expose DNS configuration in a "
                "format supported by this prototype."
            ),
        )

    recognized = []

    for provider, addresses in KNOWN_DNS_RESOLVERS.items():
        matches = set(dns_servers).intersection(addresses)
        if matches:
            recognized.append(f"{provider}: {', '.join(sorted(matches))}")

    if recognized:
        return CheckResult(
            name="DNS Leak",
            status="PASS",
            summary="DNS configuration uses recognized public resolvers",
            details=(
                f"Detected DNS servers: {', '.join(dns_servers)}\n"
                f"Recognized resolvers: {'; '.join(recognized)}\n\n"
                "This is only a local configuration check. It does not prove "
                "that every DNS query is routed through the VPN or Tor."
            ),
        )

    return CheckResult(
        name="DNS Leak",
        status="WARN",
        summary="DNS servers are not recognized",
        details=(
            f"Detected DNS servers: {', '.join(dns_servers)}\n\n"
            "An unrecognized resolver is not automatically a leak. It may be "
            "your VPN provider, router, ISP, corporate network, or a local "
            "DNS proxy."
        ),
    )


def check_tor_vpn(
    public_ip_result: CheckResult,
    tor_result: CheckResult,
) -> CheckResult:
    """
    Heuristic Tor-over-VPN check.

    A common Tor-over-VPN arrangement looks like:
        Computer -> VPN -> Tor -> Internet

    In that arrangement, the Tor check should identify a Tor exit while the
    local ISP/VPN sees a VPN connection. This function cannot independently
    verify the VPN hop.
    """
    tor_active = tor_result.status == "PASS"

    if tor_active:
        return CheckResult(
            name="Tor over VPN",
            status="PASS",
            summary="Tor is active; Tor-over-VPN is plausible",
            details=(
                "The remote Tor check identifies this connection as Tor. "
                "That is consistent with Tor-over-VPN, but this application "
                "cannot prove that a VPN is present before the Tor connection."
            ),
        )

    return CheckResult(
        name="Tor over VPN",
        status="WARN",
        summary="Tor-over-VPN was not confirmed",
        details=(
            "The connection was not identified as a Tor exit. "
            "Tor may be disabled, misconfigured, or not being used by this app."
        ),
    )


def check_vpn_over_tor(
    public_ip_result: CheckResult,
    tor_result: CheckResult,
) -> CheckResult:
    """
    Heuristic VPN-over-Tor check.

    VPN-over-Tor usually looks like:
        Computer -> Tor -> VPN -> Internet

    The final public IP would normally be a VPN exit, not a Tor exit.
    Determining this reliably requires a VPN IP/range database or a known
    VPN endpoint.
    """
    if tor_result.status == "PASS":
        return CheckResult(
            name="VPN over Tor",
            status="WARN",
            summary="VPN-over-Tor cannot be confirmed",
            details=(
                "The final endpoint identifies the connection as a Tor exit. "
                "This generally does not look like VPN-over-Tor, although "
                "the result depends on the VPN provider and its routing."
            ),
        )

    return CheckResult(
        name="VPN over Tor",
        status="WARN",
        summary="VPN-over-Tor requires provider-specific verification",
        details=(
            "The final IP was not identified as a Tor exit. To verify "
            "VPN-over-Tor, compare this IP against your VPN provider's "
            "official exit IP ranges or connect to a known VPN endpoint."
        ),
    )


def run_all_checks() -> dict[str, Any]:
    session = make_session()

    public_ip = get_public_ip(session)
    tor = check_tor(session)
    dns = check_dns()
    tor_over_vpn = check_tor_vpn(public_ip, tor)
    vpn_over_tor = check_vpn_over_tor(public_ip, tor)

    results = [
        public_ip,
        tor,
        tor_over_vpn,
        vpn_over_tor,
        dns,
    ]

    return {
        "results": [asdict(result) for result in results],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
