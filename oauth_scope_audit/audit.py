"""Core rules. Pure functions, no I/O."""
import datetime
import re

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

BENIGN = {"openid", "profile", "email", "user.read", "offline_access", "https://www.googleapis.com/auth/userinfo.email",
          "https://www.googleapis.com/auth/userinfo.profile"}

HIGH_RISK = [
    re.compile(r"\.readwrite\.all$", re.I),
    re.compile(r"^mail\.(send|readwrite)", re.I),
    re.compile(r"full_access_as_app", re.I),
    re.compile(r"^directory\.(readwrite|accessasuser)", re.I),
    re.compile(r"^rolemanagement\.readwrite", re.I),
    re.compile(r"^application\.readwrite", re.I),
    re.compile(r"^user\.readwrite\.all$", re.I),
    re.compile(r"^https://mail\.google\.com/?$", re.I),
    re.compile(r"/auth/drive$", re.I),
    re.compile(r"/auth/gmail\.(modify|send|compose)$", re.I),
    re.compile(r"/auth/admin\.directory\.(?!.*readonly)", re.I),
    re.compile(r"/auth/cloud-platform$", re.I),
]

BROAD_READ = [
    re.compile(r"\.read\.all$", re.I),
    re.compile(r"^mail\.read", re.I),
    re.compile(r"^files\.read", re.I),
    re.compile(r"/auth/(gmail|drive)\.readonly$", re.I),
    re.compile(r"/auth/admin\.directory\..*readonly$", re.I),
]


def is_high_risk(scope):
    return any(p.search(scope) for p in HIGH_RISK)


def is_broad_read(scope):
    return any(p.search(scope) for p in BROAD_READ)


def is_benign(scope):
    return scope.lower() in BENIGN


def parse_date(value):
    if value in (None, ""):
        return None
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def audit_grant(grant, today):
    """Returns a list of (severity, rule, message) for one grant."""
    out = []
    scopes = [str(s) for s in grant.get("scopes", [])]
    verified = bool(grant.get("publisher_verified"))
    admin = bool(grant.get("admin_consent"))
    risky = [s for s in scopes if is_high_risk(s)]
    meaningful = [s for s in scopes if not is_benign(s)]
    users = grant.get("users")
    who = "{} user{}".format(users, "" if users == 1 else "s") if isinstance(users, int) else "unknown users"

    if risky and not verified and admin:
        out.append(("critical", "OA001", "unverified publisher with admin consent to {} ({})".format(", ".join(risky), who)))
    elif risky:
        out.append(("high", "OA002", "high-risk scope{}: {} ({})".format("s" if len(risky) > 1 else "", ", ".join(risky), who)))
    if risky and not verified and admin:
        pass
    elif not verified and meaningful and not risky:
        out.append(("medium", "OA003", "unverified publisher holds {} ({})".format(", ".join(meaningful), who)))
    last = parse_date(grant.get("last_used"))
    if last is not None and (today - last).days >= 180:
        out.append(("medium", "OA004", "not used for {} days but the grant is still active".format((today - last).days)))
    if any(s.lower() == "offline_access" for s in scopes) and any(is_broad_read(s) for s in scopes) and not risky:
        broad = [s for s in scopes if is_broad_read(s)]
        out.append(("medium", "OA005", "permanent refresh access combined with broad read ({})".format(", ".join(broad))))
    return out


def audit(grants, today):
    """grants: list of dicts. Returns (findings, count) with findings as dicts sorted by severity."""
    if not isinstance(grants, list):
        raise ValueError("expected a JSON list of grants")
    findings = []
    for i, g in enumerate(grants):
        if not isinstance(g, dict):
            raise ValueError("grant #{} is not an object".format(i + 1))
        name = str(g.get("app") or "grant #{}".format(i + 1))
        for sev, rule, msg in audit_grant(g, today):
            findings.append({"severity": sev, "rule": rule, "where": name, "message": msg})
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["where"], f["rule"]))
    unverified = sum(1 for g in grants if not g.get("publisher_verified"))
    findings.append({"severity": "info", "rule": "OA006", "where": "all grants",
                     "message": "{} grants, {} from unverified publishers".format(len(grants), unverified)})
    return findings, len(grants)
