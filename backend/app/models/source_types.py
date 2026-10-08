from enum import Enum


class TelemetrySourceType(str, Enum):
    WEB = "WEB"
    AUTH = "AUTH"
    FIREWALL = "FIREWALL"
    ZEEK = "ZEEK"
    SYSMON = "SYSMON"  # PLANNED / NOT IMPLEMENTED (Phase 3 restriction)
    THREAT_INTEL = "THREAT_INTEL"
    OTHER = "OTHER"


SOURCE_TYPE_STATUS = {
    TelemetrySourceType.WEB.value: "IMPLEMENTED",
    TelemetrySourceType.AUTH.value: "IMPLEMENTED",
    TelemetrySourceType.FIREWALL.value: "IMPLEMENTED",
    TelemetrySourceType.ZEEK.value: "IMPLEMENTED",
    TelemetrySourceType.SYSMON.value: "PLANNED / NOT IMPLEMENTED",
    TelemetrySourceType.THREAT_INTEL.value: "IMPLEMENTED",
    TelemetrySourceType.OTHER.value: "IMPLEMENTED",
}


def normalize_source_type(raw_type: str | None) -> str:
    """Classifies raw source string into standard TelemetrySourceType."""
    if not raw_type:
        return TelemetrySourceType.OTHER.value
    cleaned = raw_type.strip().upper()
    if cleaned in ("ZEEK", "BRO", "CONN", "DNS", "HTTP"):
        return TelemetrySourceType.ZEEK.value
    if cleaned in ("WEB", "NGINX", "APACHE", "ACCESS", "JUICE_SHOP"):
        return TelemetrySourceType.WEB.value
    if cleaned in ("AUTH", "SSHD", "PAM", "LOGIN", "AUDIT"):
        return TelemetrySourceType.AUTH.value
    if cleaned in ("FIREWALL", "IPTABLES", "UFW", "PFSENSE"):
        return TelemetrySourceType.FIREWALL.value
    if cleaned in ("THREAT_INTEL", "TI", "IOC", "BLACKLIST"):
        return TelemetrySourceType.THREAT_INTEL.value
    if cleaned == "SYSMON":
        return TelemetrySourceType.SYSMON.value
    return TelemetrySourceType.OTHER.value
