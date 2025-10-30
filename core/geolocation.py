import requests
import socket
from typing import Dict, List, Any, Optional
import time
import re
from datetime import datetime


class GeolocationAnalyzer:
    """Geolocation and IP analysis for onion sites"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

        # Free geolocation APIs (no key required for the first three).
        # ipbase.com typically requires an API key; we keep it last and handle failures gracefully.
        self.geo_apis = [
            "http://ip-api.com/json/",
            "https://ipapi.co/{}/json/",
            "http://ipwhois.app/json/",
            "https://api.ipbase.com/v2/info"
        ]

        # Tor exit node list endpoint (plain text, may include comments and blank lines)
        self.tor_exit_nodes_url = "https://check.torproject.org/torbulkexitlist"
        self.tor_exits: set[str] = set()
        self.last_tor_update = 0.0

        # Simple IPv4 regex to ignore comments/empty lines from the exit list
        self._ipv4_re = re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
        )

    # -------------------- Public API --------------------

    def resolve_onion_to_ip(self, onion_url: str) -> Dict[str, Any]:
        """Attempt to resolve onion site to real IP address (best-effort heuristics)."""
        result: Dict[str, Any] = {
            "onion_url": onion_url,
            "timestamp": datetime.now().isoformat(),
            "resolution_attempts": [],
            "resolved_ips": [],
            "exit_nodes_used": [],
            "geolocation_data": []
        }

        try:
            # Extract domain from URL (sanity check only; .onion won't resolve via DNS)
            domain = self._extract_domain(onion_url)
            if not domain:
                result["error"] = "Invalid onion URL format"
                return result

            # 1) Direct DNS resolution (will fail for .onion — expected)
            try:
                ip_addresses = socket.gethostbyname_ex(domain)[2]
                if ip_addresses:
                    result["resolved_ips"].extend(ip_addresses)
                    result["resolution_attempts"].append({
                        "method": "dns_resolution",
                        "success": True,
                        "ips": ip_addresses
                    })
            except socket.gaierror:
                result["resolution_attempts"].append({
                    "method": "dns_resolution",
                    "success": False,
                    "error": "DNS resolution failed (expected for .onion)"
                })

            # 2) Tor exit node analysis (live fetch, cached 1h)
            exit_nodes = self._analyze_tor_exit_nodes()
            if exit_nodes:
                result["exit_nodes_used"] = exit_nodes
                result["resolution_attempts"].append({
                    "method": "tor_exit_analysis",
                    "success": True,
                    "nodes_found": len(exit_nodes)
                })

            # 3) Header/IP leak checks (placeholder, returns empty list safely)
            leaked_ips = self._check_ip_leaks(onion_url)
            if leaked_ips:
                result["resolved_ips"].extend(leaked_ips)
                result["resolution_attempts"].append({
                    "method": "header_analysis",
                    "success": True,
                    "leaked_ips": leaked_ips
                })

            # Geolocate any IPs we have (resolved + exit node IPs)
            all_ips = list(
                {ip for ip in result["resolved_ips"]}
                | {node.get("ip", "") for node in exit_nodes if isinstance(node, dict)}
            )
            all_ips = [ip for ip in all_ips if self._ipv4_re.match(ip)]

            for ip in all_ips:
                geo_data = self._geolocate_ip(ip)
                if geo_data:
                    result["geolocation_data"].append(geo_data)

        except Exception as e:
            result["error"] = str(e)

        return result

    def generate_location_summary(self, geo_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate and summarize multiple geolocation results."""
        summary = {
            "total_ips_analyzed": len(geo_results),
            "countries_detected": set(),
            "regions_detected": set(),
            "cities_detected": set(),
            "isps_detected": set(),
            "hosting_detected": [],
            "proxy_detected": [],
            "most_likely_location": None,
            "confidence_score": 0
        }

        if not geo_results:
            return summary

        for result in geo_results:
            location = result.get("location_data", {}) or {}
            country = location.get("country", "Unknown")
            region = location.get("region", "Unknown")
            city = location.get("city", "Unknown")
            isp = location.get("isp", "Unknown")

            if country != "Unknown":
                summary["countries_detected"].add(country)
            if region != "Unknown":
                summary["regions_detected"].add(region)
            if city != "Unknown":
                summary["cities_detected"].add(city)
            if isp != "Unknown":
                summary["isps_detected"].add(isp)

            if location.get("hosting"):
                summary["hosting_detected"].append(result.get("ip_address"))
            if location.get("proxy"):
                summary["proxy_detected"].append(result.get("ip_address"))

        # Convert sets to lists for JSON serialization
        summary["countries_detected"] = list(summary["countries_detected"])
        summary["regions_detected"] = list(summary["regions_detected"])
        summary["cities_detected"] = list(summary["cities_detected"])
        summary["isps_detected"] = list(summary["isps_detected"])

        # Simple "most likely" logic based on mode
        if summary["countries_detected"]:
            most_common_country = max(
                set(summary["countries_detected"]),
                key=summary["countries_detected"].count
            )
            summary["most_likely_location"] = {
                "country": most_common_country,
                "confidence": "medium"
            }
            if summary["cities_detected"]:
                most_common_city = max(
                    set(summary["cities_detected"]),
                    key=summary["cities_detected"].count
                )
                summary["most_likely_location"]["city"] = most_common_city

        # Confidence: crude, but avoids division by zero and weird states
        confidence_factors = [
            len(summary["countries_detected"]) > 0,
            len(summary["cities_detected"]) > 0,
            len(geo_results) > 1,
            len(summary["hosting_detected"]) == 0,
            len(summary["proxy_detected"]) == 0
        ]
        summary["confidence_score"] = (sum(confidence_factors) / len(confidence_factors)) * 100

        return summary

    # -------------------- Helpers --------------------

    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract the .onion domain from a URL-like string."""
        try:
            # strip scheme
            if "://" in url:
                url = url.split("://", 1)[1]
            domain = url.split("/", 1)[0]

            # v3 onions are 56 chars + ".onion" (v2 is deprecated but was shorter)
            if domain.endswith(".onion") and len(domain) >= 22:
                return domain
            return None
        except Exception:
            return None

    def _analyze_tor_exit_nodes(self) -> List[Dict[str, Any]]:
        """Fetch and geolocate a small sample of real Tor exit nodes."""
        exit_nodes: List[Dict[str, Any]] = []

        try:
            # Refresh exit list hourly
            if (time.time() - self.last_tor_update) > 3600 or not self.tor_exits:
                self._update_tor_exit_list()

            # Take a small sample (limit to avoid rate limits on geo APIs)
            sample_ips = [ip for ip in self.tor_exits if self._ipv4_re.match(ip)][:5]

            for ip in sample_ips:
                geo = self._geolocate_ip(ip) or {}
                loc = geo.get("location_data", {}) or {}
                exit_nodes.append({
                    "ip": ip,
                    "country": loc.get("country", "Unknown"),
                    "region": loc.get("region", "Unknown"),
                    "city": loc.get("city", "Unknown")
                })

        except Exception as e:
            exit_nodes.append({"error": str(e)})

        return exit_nodes

    def _check_ip_leaks(self, onion_url: str) -> List[str]:
        """
        Placeholder: In a real flow, you would fetch the onion via a Tor-routed session
        and inspect response headers for X-Forwarded-For / X-Real-IP, or HTML for leaks.
        """
        return []

    def _geolocate_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Query multiple providers until one succeeds; return normalized structure."""
        geo_data: Dict[str, Any] = {
            "ip_address": ip_address,
            "timestamp": datetime.now().isoformat(),
            "location_data": {},
            "provider": None,
            "accuracy": "unknown"
        }

        for api_url in self.geo_apis:
            try:
                url = api_url.format(ip_address) if "{}" in api_url else (api_url + ip_address)
                resp = self.session.get(url, timeout=10)

                # ipbase.com often needs an API key -> 401/403; just skip on non-200
                if resp.status_code != 200:
                    time.sleep(0.5)
                    continue

                data = resp.json()

                if "ip-api.com" in api_url:
                    geo_data.update(self._parse_ipapi_response(data))
                elif "ipapi.co" in api_url:
                    geo_data.update(self._parse_ipapi_co_response(data))
                elif "ipwhois.app" in api_url:
                    geo_data.update(self._parse_ipwhois_response(data))
                elif "ipbase.com" in api_url:
                    geo_data.update(self._parse_ipbase_response(data))

                if geo_data["location_data"]:
                    return geo_data

                time.sleep(0.5)  # be gentle with public APIs

            except Exception:
                # Try the next API
                time.sleep(0.25)
                continue

        # If all attempts failed
        return None

    # -------------------- Provider parsers --------------------

    def _parse_ipapi_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # ip-api.com free tier returns a 'status' field ('success'/'fail')
        if data.get("status") != "success":
            return {"provider": "ip-api.com", "location_data": {}, "accuracy": "unknown"}

        return {
            "provider": "ip-api.com",
            "location_data": {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "region_code": data.get("region", "Unknown"),
                "city": data.get("city", "Unknown"),
                "zip_code": data.get("zip", "Unknown"),
                "latitude": data.get("lat", 0),
                "longitude": data.get("lon", 0),
                "timezone": data.get("timezone", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org", "Unknown"),
                "as_number": data.get("as", "Unknown"),
                # present only on pro; guard with defaults:
                "proxy": data.get("proxy", False),
                "hosting": data.get("hosting", False),
            },
            "accuracy": "city" if data.get("city") else "country"
        }

    def _parse_ipapi_co_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # ipapi.co returns error on key 'error'
        if data.get("error"):
            return {"provider": "ipapi.co", "location_data": {}, "accuracy": "unknown"}

        return {
            "provider": "ipapi.co",
            "location_data": {
                "country": data.get("country_name", "Unknown"),
                "country_code": data.get("country_code", "Unknown"),
                "region": data.get("region", "Unknown"),
                "region_code": data.get("region_code", "Unknown"),
                "city": data.get("city", "Unknown"),
                "zip_code": data.get("postal", "Unknown"),
                "latitude": data.get("latitude", 0),
                "longitude": data.get("longitude", 0),
                "timezone": data.get("timezone", "Unknown"),
                "isp": data.get("org", "Unknown"),
                "org": data.get("org", "Unknown"),
                "as_number": data.get("asn", "Unknown"),
                "currency": data.get("currency", "Unknown"),
                "languages": data.get("languages", "Unknown"),
            },
            "accuracy": "city" if data.get("city") else "country"
        }

    def _parse_ipwhois_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # ipwhois.app returns 'success': True/False
        if data.get("success") is False:
            return {"provider": "ipwhois.app", "location_data": {}, "accuracy": "unknown"}

        # timezone can be a string OR an object; normalize to string
        tz_raw = data.get("timezone")
        if isinstance(tz_raw, dict):
            timezone = tz_raw.get("name", "Unknown")
        else:
            timezone = tz_raw or "Unknown"

        return {
            "provider": "ipwhois.app",
            "location_data": {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("country_code", "Unknown"),
                "region": data.get("region", "Unknown"),
                "city": data.get("city", "Unknown"),
                "latitude": data.get("latitude", 0),
                "longitude": data.get("longitude", 0),
                "timezone": timezone,
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org", "Unknown"),
                "as_number": data.get("asn", "Unknown")
            },
            "accuracy": "city" if data.get("city") else "country"
        }

    def _parse_ipbase_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # ipbase.com (usually needs key). Shape: {"data": {"location": {...}, "connection": {...}}}
        dat = data.get("data") or {}
        location = dat.get("location") or {}
        connection = dat.get("connection") or {}

        # If the payload doesn't include expected structure, bail gracefully
        if not (location or connection):
            return {"provider": "ipbase.com", "location_data": {}, "accuracy": "unknown"}

        country_obj = (location.get("country") or {})
        region_obj = (location.get("region") or {})
        city_obj = (location.get("city") or {})
        tz_obj = (location.get("timezone") or {})

        return {
            "provider": "ipbase.com",
            "location_data": {
                "country": country_obj.get("name", "Unknown"),
                "country_code": country_obj.get("alpha2", "Unknown"),
                "region": region_obj.get("name", "Unknown"),
                "city": city_obj.get("name", "Unknown"),
                "zip_code": location.get("zip", "Unknown"),
                "latitude": location.get("latitude", 0),
                "longitude": location.get("longitude", 0),
                "timezone": tz_obj.get("id", "Unknown"),
                "isp": connection.get("organization", "Unknown"),
                "org": connection.get("organization", "Unknown"),
                "as_number": connection.get("asn", "Unknown")
            },
            "accuracy": "city" if city_obj.get("name") else "country"
        }

    def _update_tor_exit_list(self):
        """Update the cached list of Tor exit node IPs."""
        try:
            resp = self.session.get(self.tor_exit_nodes_url, timeout=30)
            if resp.status_code == 200:
                ips: set[str] = set()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if self._ipv4_re.match(line):
                        ips.add(line)
                # only update if we actually parsed something
                if ips:
                    self.tor_exits = ips
                    self.last_tor_update = time.time()
        except Exception:
            # keep existing cache if request fails
            pass
