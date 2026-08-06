import http.client
import ipaddress
import socket
import ssl
import urllib.parse
from urllib.error import HTTPError, URLError

METADATA_SUBNETS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]

BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "broadcasthost"}
BLOCKED_SCHEMES = {"file", "ftp", "gopher", "dict", "ldap", "jar", "tftp", "data"}
INTERNAL_TLDS = (".local", ".internal", ".lan", ".home", ".corp", ".private", ".intranet")


def is_ip_private_or_internal(ip_val):
    """
    Enterprise-grade IP validation using Python's native ipaddress module.
    Blocks RFC1918, loopback, link-local, reserved, multicast, unspecified,
    cloud metadata (169.254.169.254), IPv6 private/local subnets, and unroutable ranges.
    """
    if not ip_val:
        return False

    try:
        if isinstance(ip_val, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip_obj = ip_val
        else:
            ip_clean = str(ip_val).strip()
            ip_obj = ipaddress.ip_address(ip_clean)
    except ValueError:
        return False

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    ):
        return True

    for net in METADATA_SUBNETS:
        if ip_obj in net:
            return True

    return False


def validate_url_ssrf(url_str, retries=1):
    """
    Validate a URL to prevent SSRF vulnerabilities and DNS-rebinding attacks.
    Returns (is_valid: bool, reason: str, pinned_ip: str or None).

    Guarantees:
    1. Scheme must be http or https.
    2. Hostname must not be blocked (localhost, .local, etc.).
    3. Hostname is resolved during validation.
    4. EVERY resolved IP address is validated against restricted internal ranges.
    5. If any resolved IP is internal/private, validation fails immediately.
    6. If resolution succeeds, a validated public IP is pinned and returned.
    7. If resolution fails, validation fails (pinned_ip is None), preventing subsequent network requests.
    """
    if not url_str or not isinstance(url_str, str):
        return False, "URL is missing or invalid.", None

    url_clean = url_str.strip()
    try:
        parsed = urllib.parse.urlparse(url_clean)
    except Exception:
        return False, "Malformed URL format.", None

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Scheme '{scheme}' is prohibited. Only HTTP and HTTPS are permitted.", None

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False, "URL contains no hostname.", None

    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(INTERNAL_TLDS):
        return False, f"Host '{hostname}' is an internal domain.", None

    # Check if hostname is already a literal IP address (IPv4 or IPv6)
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_ip_private_or_internal(ip_obj):
            return False, f"Target IP {hostname} is a restricted internal or private address.", str(ip_obj)
        return True, "Valid public IP target.", str(ip_obj)
    except ValueError:
        pass

    # Resolve domain hostnames via socket getaddrinfo with retry support
    addr_info = None
    last_err = None
    for attempt in range(max(1, retries + 1)):
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if addr_info:
                break
        except socket.gaierror as err:
            last_err = err
        except Exception as err:
            return False, f"DNS resolution error: {err}", None

    if not addr_info:
        return False, f"Unresolvable domain (DNS lookup failed: {last_err or 'No address found'}).", None

    resolved_ips = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_ip_private_or_internal(ip_obj):
                return False, f"Domain '{hostname}' resolves to restricted internal IP {ip_str}.", ip_str
        except ValueError:
            return False, f"Invalid IP resolution '{ip_str}'.", None

    primary_ip = resolved_ips[0] if resolved_ips else None
    if not primary_ip:
        return False, f"Domain '{hostname}' did not produce a valid IP destination.", None

    return True, "Valid public domain target.", primary_ip


def safe_http_get(url_str, timeout=2.5, max_redirects=10):
    """
    Perform a safe HTTP/HTTPS GET request with absolute IP-pinning,
    defeating DNS-rebinding attacks, enforcing TLS certificate verification,
    and recording per-hop redirect telemetry.

    Returns (status_code: int, response_body: str, final_url: str, server_banner: str, content_type: str, pinned_ip: str, redirect_hops: list).
    """
    current_url = url_str
    redirect_count = 0
    redirect_hops = []

    while redirect_count <= max_redirects:
        is_valid, reason, pinned_ip = validate_url_ssrf(current_url)
        if not is_valid or not pinned_ip:
            raise ValueError(f"SSRF Firewall Blocked Target: {reason}")

        parsed = urllib.parse.urlparse(current_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        headers = {
            "User-Agent": "Guardly-Security-Scanner/2.4 (+https://guardly.local)",
            "Host": hostname,
            "Accept": "*/*",
        }

        # IP Pinning: Use pinned_ip directly for the socket connection to eliminate DNS rebinding
        conn = None
        try:
            if scheme == "https":
                ssl_ctx = ssl.create_default_context()
                sock = socket.create_connection((pinned_ip, port), timeout=timeout)
                try:
                    ssl_sock = ssl_ctx.wrap_socket(sock, server_hostname=hostname)
                except (ssl.SSLCertVerificationError, ssl.SSLError, ssl.CertificateError) as cert_err:
                    sock.close()
                    return 0, "", current_url, f"TLS Verification Failed ({cert_err})", "Unknown", pinned_ip, redirect_hops

                conn = http.client.HTTPSConnection(hostname, port=port, timeout=timeout)
                conn.sock = ssl_sock
            else:
                sock = socket.create_connection((pinned_ip, port), timeout=timeout)
                conn = http.client.HTTPConnection(hostname, port=port, timeout=timeout)
                conn.sock = sock

            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            status = response.status
            resp_headers = dict(response.getheaders())
            server_banner = resp_headers.get("server") or resp_headers.get("Server") or "Generic Web Server"
            content_type = resp_headers.get("content-type") or resp_headers.get("Content-Type") or "text/html"

            # Per-hop redirect handling
            if status in (301, 302, 303, 307, 308):
                location = resp_headers.get("location") or resp_headers.get("Location")
                conn.close()
                if not location:
                    return status, "", current_url, server_banner, content_type, pinned_ip, redirect_hops

                redirect_url = urllib.parse.urljoin(current_url, location)
                # Re-validate redirect target URL and IP before following hop!
                is_red_valid, red_reason, red_ip = validate_url_ssrf(redirect_url)
                if not is_red_valid or not red_ip:
                    raise ValueError(f"Blocked SSRF Redirect Target ({red_reason})")

                redirect_hops.append({
                    "hop_number": redirect_count + 1,
                    "status_code": status,
                    "source_url": current_url,
                    "destination_url": redirect_url,
                    "pinned_ip": red_ip,
                })

                current_url = redirect_url
                redirect_count += 1
                continue

            body = response.read(1024 * 512).decode("utf-8", errors="replace")
            conn.close()
            return status, body, current_url, server_banner, content_type, pinned_ip, redirect_hops

        except (socket.timeout, TimeoutError):
            if conn:
                conn.close()
            raise ValueError("Connection Timed Out")
        except Exception as err:
            if conn:
                conn.close()
            if isinstance(err, ValueError):
                raise err
            raise ValueError(f"Connection Failed ({err})")

    raise ValueError("Exceeded Maximum Allowed Redirects (10 Hops Limit)")

