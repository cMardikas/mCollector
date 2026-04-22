"""
mCollector fleet health report generator.

Reads JSON host records from ./uploads/ (as written by mCollector's PowerShell
collector + C receiver) and produces a timestamped HTML dashboard under
./uploads/ (e.g. uploads/koondraport_2026-04-22_17-54-12.html).

Stdlib only.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html import escape as h

__version__ = '1.3.7'

UPLOAD_DIR = 'uploads'
OUTPUT_PREFIX = 'koondraport'

EID_VENDORS = {'ria', 'thales', 'idemia'}
EID_NAME_PATTERNS = (
    'open-eid', 'digidoc', 'web eid', 'esteid',
    'smartcard client', 'idplug', 'ladmlauncher',
)


# ---------------------------------------------------------------------------
# JSON parsing helpers
# ---------------------------------------------------------------------------

def extract(pattern, text):
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1) if m else "-"


def extract_array_block(key, text):
    m = re.search(
        f'"{key}"\\s*:\\s*\\[(.*?)\\]\\s*(?:,\\s*"|\\}})',
        text, re.DOTALL | re.IGNORECASE,
    )
    return m.group(1) if m else ""


def parse_software_block(soft_block):
    items = re.findall(r'\{.*?\}', soft_block, re.DOTALL)
    out = []
    for b in items:
        n = re.search(r'"Name"\s*:\s*"([^"]+)"', b)
        v = re.search(r'"Version"\s*:\s*"([^"]+)"', b)
        ven = re.search(r'"Vendor"\s*:\s*"([^"]+)"', b)
        idate = re.search(r'"InstallDate"\s*:\s*"([^"]+)"', b)
        if not n or n.group(1) == "null":
            continue
        out.append({
            'name': n.group(1),
            'version': v.group(1) if v and v.group(1) != "null" else "-",
            'vendor': ven.group(1) if ven and ven.group(1) != "null" else "-",
            'install_date': idate.group(1) if idate and idate.group(1) != "null" else "",
        })
    return out


def parse_services_block(srv_block):
    items = re.findall(r'\{.*?\}', srv_block, re.DOTALL)
    out = []
    for b in items:
        n = re.search(r'"Name"\s*:\s*"([^"]+)"', b)
        s = re.search(r'"Status"\s*:\s*"([^"]+)"', b)
        if not n or n.group(1) == "null":
            continue
        out.append({'name': n.group(1), 'status': s.group(1) if s else "-"})
    return out


def is_eid_software(name, vendor):
    v = (vendor or '').lower()
    if any(k in v for k in EID_VENDORS):
        return True
    n = (name or '').lower()
    return any(pat in n for pat in EID_NAME_PATTERNS)


def software_key(name):
    return re.sub(r'\s+', ' ', name.strip().lower())


def parse_install_date(d):
    if not d or len(d) != 8 or not d.isdigit():
        return None
    return d[:4], d[4:6], d[6:8]


def install_date_iso(d):
    p = parse_install_date(d)
    return f"{p[0]}-{p[1]}-{p[2]}" if p else ""


def days_since_install(d):
    p = parse_install_date(d)
    if not p:
        return None
    try:
        dt = datetime(int(p[0]), int(p[1]), int(p[2]), tzinfo=timezone.utc)
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days


def version_tuple(v):
    if not v or v == '-':
        return ()
    parts = re.split(r'[^0-9A-Za-z]+', v)
    key = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))
        else:
            key.append((1, p.lower()))
    return tuple(key)


# ---------------------------------------------------------------------------
# Load hosts
# ---------------------------------------------------------------------------

def load_hosts(upload_dir):
    hosts = []
    for filename in sorted(os.listdir(upload_dir)):
        if not filename.endswith('.json'):
            continue
        with open(os.path.join(upload_dir, filename), 'r',
                  encoding='utf-8', errors='ignore') as f:
            content = f.read()
        hosts.append({
            'filename': filename,
            'name': extract(r'"ComputerName"\s*:\s*"([^"]+)"', content),
            'desc': extract(r'"Description"\s*:\s*"([^"]+)"', content),
            'os': extract(r'"OS"\s*:\s*"([^"]+)"', content),
            'os_ver': extract(r'"OS_Version"\s*:\s*"([^"]+)"', content),
            'ip': extract(r'"IPv4Address"\s*:\s*"([^"]+)"', content),
            'user': extract(r'"Current_user"\s*:\s*"([^"]+)"', content),
            'boot': extract(r'"LastBoot"\s*:\s*"([^"]+)"', content),
            'defender': extract(r'"ProductState"\s*:\s*"([^"]+)"', content),
            'responder': extract(r'"Responder"\s*:\s*"([^"]+)"', content),
            'updates_last_install': extract(
                r'"Updates_lastInstallationSuccessDate"\s*:\s*"([^"]+)"', content),
            'bitlocker': bool(re.search(
                r'"Bitlocker-C"\s*:\s*true', content, re.IGNORECASE)),
            'admins': re.findall(r'"([^"]+)"',
                                 extract_array_block("All_local_admins", content)),
            'software': parse_software_block(extract_array_block("Software", content)),
            'services': parse_services_block(
                extract_array_block("Non_standard_win_services", content)),
        })
    return hosts


# ---------------------------------------------------------------------------
# Software comparison + upstream verification
# ---------------------------------------------------------------------------

def build_software_matrix(hosts):
    fleet = {}
    for host in hosts:
        for sw in host['software']:
            key = software_key(sw['name'])
            if key not in fleet:
                fleet[key] = {
                    'key': key,
                    'display_name': sw['name'],
                    'vendor': sw['vendor'],
                    'is_eid': is_eid_software(sw['name'], sw['vendor']),
                    'per_host': {},
                    'versions': set(),
                }
            entry = fleet[key]
            if sw['name'] and (len(sw['name']) < len(entry['display_name'])
                               or entry['display_name'].islower()):
                entry['display_name'] = sw['name']
            if sw['vendor'] and sw['vendor'] != '-' and entry['vendor'] in ('-', ''):
                entry['vendor'] = sw['vendor']
            entry['per_host'][host['name']] = {
                'version': sw['version'],
                'install_date': sw['install_date'],
            }
            entry['versions'].add(sw['version'])

    total = len(hosts)
    for entry in fleet.values():
        entry['host_count'] = len(entry['per_host'])
        non_dash = {v for v in entry['versions'] if v and v != '-'}

        # Latest is simply the max version seen across the fleet.
        try:
            entry['latest_version'] = max(non_dash, key=version_tuple) if non_dash else ''
        except ValueError:
            entry['latest_version'] = ''

        latest = entry['latest_version']
        if entry['host_count'] == 1 and total > 1:
            entry['status'] = 'unique'
            entry['lagging_hosts'] = []
        else:
            lagging = []
            for hn, info in entry['per_host'].items():
                iv = info['version']
                if iv and iv != '-' and latest and version_tuple(iv) < version_tuple(latest):
                    lagging.append(hn)
            entry['lagging_hosts'] = lagging
            entry['status'] = 'drift' if lagging else 'consistent'

    status_order = {'drift': 0, 'unique': 1, 'consistent': 2}
    matrix = sorted(
        fleet.values(),
        key=lambda e: (status_order[e['status']],
                       -len(e.get('lagging_hosts', [])),
                       -e['host_count'],
                       e['display_name'].lower()),
    )
    return matrix


# ---------------------------------------------------------------------------
# Per-host metrics + findings
# ---------------------------------------------------------------------------

def compute_host_metrics(host, matrix):
    name = host['name']
    lagging = []
    unique_sw = []
    for entry in matrix:
        if name not in entry['per_host']:
            continue
        if entry['status'] == 'unique':
            unique_sw.append(entry)
        elif entry['status'] == 'drift' and name in entry.get('lagging_hosts', []):
            lagging.append(entry)

    user_clean = host['user'].split("\\")[-1] if "\\" in host['user'] else host['user']
    is_admin_user = any(a.lower() == user_clean.lower() for a in host['admins'])
    defender_on = host['defender'] == 'On'

    risk_points = 0
    if not host['bitlocker']:  risk_points += 2
    if not defender_on:        risk_points += 3
    if is_admin_user:          risk_points += 2
    if len(lagging) >= 5:      risk_points += 3
    elif len(lagging) >= 2:    risk_points += 1

    if risk_points >= 5:
        health = 'red'
    elif risk_points >= 2:
        health = 'yellow'
    else:
        health = 'green'

    host['metrics'] = {
        'lagging': lagging,
        'unique_sw': unique_sw,
        'is_admin_user': is_admin_user,
        'defender_on': defender_on,
        'health': health,
        'risk_points': risk_points,
    }
    return host


# ---------------------------------------------------------------------------
# Security findings
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'info': 3}
SEVERITY_LABEL = {
    'critical': 'Kriitiline',
    'high': 'Kõrge',
    'medium': 'Keskmine',
    'info': 'Info',
}

UPDATE_STALE_DAYS = 30
UPTIME_STALE_DAYS = 30

# Remote-access / remote-management / tunnel software signatures.
# Patterns are case-insensitive, checked against concatenated "Name | Vendor".
# Ordering matters: specific variants (e.g. UltraVNC) are matched before the
# generic 'vnc' fallback.
REMOTE_ACCESS_PATTERNS = [
    # (label, category, severity, regex)
    # --- Remote Desktop (classical) ---
    ('AnyDesk',                    'Kaugtöölaud', 'medium', r'\banydesk\b'),
    ('TeamViewer',                 'Kaugtöölaud', 'medium', r'\bteamviewer\b'),
    ('Chrome Remote Desktop',      'Kaugtöölaud', 'medium', r'chrome remote desktop'),
    ('Splashtop',                  'Kaugtöölaud', 'medium', r'\bsplashtop\b'),
    ('Parsec',                     'Kaugtöölaud', 'medium', r'\bparsec\b'),
    ('NoMachine',                  'Kaugtöölaud', 'medium', r'\bnomachine\b'),
    ('RustDesk',                   'Kaugtöölaud', 'medium', r'\brustdesk\b'),
    ('Getscreen',                  'Kaugtöölaud', 'medium', r'\bgetscreen\b'),
    ('Iperius Remote',             'Kaugtöölaud', 'medium', r'\biperius remote\b'),
    ('Supremo',                    'Kaugtöölaud', 'medium', r'\bsupremo\b'),
    ('LogMeIn',                    'Kaugtöölaud', 'medium', r'\blogmein\b'),
    ('GoToMyPC / GoToAssist',      'Kaugtöölaud', 'medium', r'\bgoto(mypc|assist)\b'),
    ('RemotePC',                   'Kaugtöölaud', 'medium', r'\bremotepc\b'),
    ('Zoho Assist',                'Kaugtöölaud', 'medium', r'\bzoho assist\b'),
    ('Remote Utilities',           'Kaugtöölaud', 'medium', r'\bremote utilities\b'),
    ('Radmin',                     'Kaugtöölaud', 'medium', r'\bradmin\b'),
    ('DameWare',                   'Kaugtöölaud', 'medium', r'\bdameware\b'),

    # --- VNC family ---
    ('TightVNC',                   'VNC',         'medium', r'\btightvnc\b'),
    ('UltraVNC',                   'VNC',         'medium', r'\bultra[\s\-]?vnc\b'),
    ('RealVNC',                    'VNC',         'medium', r'\breal[\s\-]?vnc\b|vnc (viewer|server|connect)'),
    ('TigerVNC',                   'VNC',         'medium', r'\btiger[\s\-]?vnc\b'),
    ('VNC (generic)',              'VNC',         'medium', r'\bvnc\b'),

    # --- RMM / remote management ---
    ('ConnectWise ScreenConnect',  'RMM',         'medium', r'screenconnect|connectwise control'),
    ('NinjaOne / NinjaRMM',        'RMM',         'medium', r'\bninja(rmm|one)\b'),
    ('Atera',                      'RMM',         'medium', r'\batera\b'),
    ('Kaseya VSA',                 'RMM',         'medium', r'\bkaseya\b'),
    ('Datto RMM',                  'RMM',         'medium', r'datto rmm|\bdatto\b.*\brmm\b'),
    ('N-able / N-central',         'RMM',         'medium', r'n-?able|n-?central|solarwinds msp'),
    ('Syncro',                     'RMM',         'medium', r'\bsyncro\b'),
    ('ManageEngine',               'RMM',         'medium', r'manageengine'),
    ('Action1',                    'RMM',         'medium', r'\baction1\b'),

    # --- Microsoft remote support ---
    ('Quick Assist',               'MS kaugtugi', 'info',   r'quick assist'),
    ('Remote Desktop Connection',  'MS kaugtugi', 'info',   r'\bmstsc\b'),

    # --- SSH / terminal clients ---
    ('PuTTY',                      'SSH/Terminal','info',   r'\bputty\b'),
    ('MobaXterm',                  'SSH/Terminal','info',   r'\bmobaxterm\b'),
    ('mRemoteNG',                  'SSH/Terminal','info',   r'\bmremoteng\b'),
    ('Royal TS',                   'SSH/Terminal','info',   r'\broyal ?ts\b'),
    ('Remote Desktop Manager',     'SSH/Terminal','info',   r'\bremote desktop manager\b'),
    ('WinSCP',                     'SSH/Terminal','info',   r'\bwinscp\b'),
    ('FileZilla',                  'SSH/Terminal','info',   r'\bfilezilla\b'),

    # --- Tunnels / VPN / ZTNA ---
    ('ngrok',                      'Tunnel/VPN',  'medium', r'\bngrok\b'),
    ('Cloudflare Tunnel',          'Tunnel/VPN',  'medium', r'cloudflared|cloudflare tunnel'),
    ('Tailscale',                  'Tunnel/VPN',  'medium', r'\btailscale\b'),
    ('ZeroTier',                   'Tunnel/VPN',  'medium', r'\bzerotier\b'),
    ('LogMeIn Hamachi',            'Tunnel/VPN',  'medium', r'\bhamachi\b'),
    ('WireGuard',                  'Tunnel/VPN',  'info',   r'\bwireguard\b'),
    ('OpenVPN',                    'Tunnel/VPN',  'info',   r'\bopenvpn\b'),
    ('Localtunnel',                'Tunnel/VPN',  'medium', r'\blocaltunnel\b'),
]


def detect_remote_access(host):
    """Scan host software list; return list of {label, category, severity, source}.

    Deduplicates by label (first match wins per host). Order preserved from
    REMOTE_ACCESS_PATTERNS, so specific variants match before generic fallbacks.
    """
    hits = []
    seen_labels = set()
    for sw in host.get('software', []):
        haystack = f"{sw.get('name', '')} | {sw.get('vendor', '')}".lower()
        for label, cat, sev, pattern in REMOTE_ACCESS_PATTERNS:
            if label in seen_labels:
                continue
            if re.search(pattern, haystack, re.IGNORECASE):
                hits.append({
                    'label': label,
                    'category': cat,
                    'severity': sev,
                    'source': sw.get('name', ''),
                })
                seen_labels.add(label)
                break
    return hits


def parse_boot_datetime(s):
    """Parse LastBoot in 'dd.mm.yyyy hh:mm' format; return datetime or None."""
    if not s or s == '-':
        return None
    try:
        return datetime.strptime(s.strip(), '%d.%m.%Y %H:%M').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_update_date(s):
    """Parse Updates_lastInstallationSuccessDate 'dd.mm.yyyy'; return datetime or None."""
    if not s or s == '-':
        return None
    try:
        return datetime.strptime(s.strip()[:10], '%d.%m.%Y').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def compute_security_findings(hosts, matrix):
    """Collect security-relevant observations, grouped by category and severity.

    Each finding has: key, title, severity, icon, hosts (list of dicts with
    'name' and optional 'detail'), summary_count.
    """
    now = datetime.now(timezone.utc)
    findings = []

    # 1. Defender inactive (critical)
    defender_off = [
        {'name': h0['name'], 'detail': f"ProductState: {h0['defender']}"}
        for h0 in hosts if not h0['metrics']['defender_on']
    ]
    if defender_off:
        findings.append({
            'key': 'defender_off',
            'title': 'Defender mitteaktiivne',
            'severity': 'critical',
            'icon': 'shield-slash',
            'hosts': defender_off,
        })

    # 2. BitLocker missing (high)
    bitlocker_off = [
        {'name': h0['name'], 'detail': 'C: draiv krüpteerimata'}
        for h0 in hosts if not h0['bitlocker']
    ]
    if bitlocker_off:
        findings.append({
            'key': 'bitlocker_off',
            'title': 'BitLocker puudub',
            'severity': 'high',
            'icon': 'unlock',
            'hosts': bitlocker_off,
        })

    # 3. Active user is local admin (high)
    admin_users = [
        {'name': h0['name'], 'detail': f"Kasutaja: {h0['user']}"}
        for h0 in hosts if h0['metrics']['is_admin_user']
    ]
    if admin_users:
        findings.append({
            'key': 'admin_user',
            'title': 'Aktiivne kasutaja on lokaalne administraator',
            'severity': 'high',
            'icon': 'person-fill-gear',
            'hosts': admin_users,
        })

    # 4. Non-standard services not OK (medium)
    bad_services = []
    for h0 in hosts:
        failing = [s for s in h0['services'] if s['status'] != 'OK']
        if failing:
            names = ', '.join(s['name'] for s in failing[:3])
            suffix = f" (+{len(failing)-3})" if len(failing) > 3 else ''
            bad_services.append({
                'name': h0['name'],
                'detail': f"{len(failing)} teenust: {names}{suffix}",
            })
    if bad_services:
        findings.append({
            'key': 'bad_services',
            'title': 'Mittestandardsed teenused vigases olekus',
            'severity': 'medium',
            'icon': 'gear-wide-connected',
            'hosts': bad_services,
        })

    # 5. Multiple local admins (medium) — more than one besides built-in Administrator
    many_admins = []
    for h0 in hosts:
        non_builtin = [a for a in h0['admins']
                       if a.lower() not in ('administrator', 'administraator')]
        if len(non_builtin) > 1:
            many_admins.append({
                'name': h0['name'],
                'detail': f"{len(non_builtin)} kasutajat: {', '.join(non_builtin)}",
            })
    if many_admins:
        findings.append({
            'key': 'many_admins',
            'title': 'Mitu lokaalset administraatorit',
            'severity': 'medium',
            'icon': 'people-fill',
            'hosts': many_admins,
        })

    # 6. Windows Update stale > 30 days (medium)
    stale_updates = []
    for h0 in hosts:
        dt = parse_update_date(h0['updates_last_install'])
        if dt is None:
            continue
        days = (now - dt).days
        if days > UPDATE_STALE_DAYS:
            stale_updates.append({
                'name': h0['name'],
                'detail': f"Viimane uuendus: {dt.strftime('%d.%m.%Y')} ({days} p tagasi)",
            })
    if stale_updates:
        findings.append({
            'key': 'stale_updates',
            'title': f'Windows Update vanem kui {UPDATE_STALE_DAYS} päeva',
            'severity': 'medium',
            'icon': 'clock-history',
            'hosts': stale_updates,
        })

    # 7. Uptime > 30 days (info)
    long_uptime = []
    for h0 in hosts:
        dt = parse_boot_datetime(h0['boot'])
        if dt is None:
            continue
        days = (now - dt).days
        if days > UPTIME_STALE_DAYS:
            long_uptime.append({
                'name': h0['name'],
                'detail': f"Viimane alglaadimine: {dt.strftime('%d.%m.%Y')} ({days} p tagasi)",
            })
    if long_uptime:
        findings.append({
            'key': 'long_uptime',
            'title': f'Pikk uptime (>{UPTIME_STALE_DAYS} päeva ilma alglaadimiseta)',
            'severity': 'info',
            'icon': 'hourglass-split',
            'hosts': long_uptime,
        })

    # 8. Version drift summary (info)
    drift_count = sum(1 for e in matrix if e['status'] == 'drift')
    if drift_count:
        affected_hosts = set()
        for e in matrix:
            if e['status'] == 'drift':
                for hn in e.get('lagging_hosts', []):
                    affected_hosts.add(hn)
        findings.append({
            'key': 'version_drift',
            'title': 'Sama tarkvara eri versioonidel',
            'severity': 'info',
            'icon': 'shuffle',
            'hosts': [
                {'name': hn, 'detail': ''}
                for hn in sorted(affected_hosts)
            ],
            'summary_count': drift_count,
            'summary_suffix': 'paketti',
        })

    # 9. Remote-access / remote-management / tunnel software (medium)
    remote_hosts = []
    for h0 in hosts:
        hits = detect_remote_access(h0)
        if hits:
            # Group labels by category for a compact per-host detail line
            by_cat = {}
            for hit in hits:
                by_cat.setdefault(hit['category'], []).append(hit['label'])
            parts = [f"{cat}: {', '.join(labels)}"
                     for cat, labels in by_cat.items()]
            remote_hosts.append({
                'name': h0['name'],
                'detail': ' | '.join(parts),
            })
    if remote_hosts:
        findings.append({
            'key': 'remote_access',
            'title': 'Kauglaua / kaughalduse tarkvara',
            'severity': 'medium',
            'icon': 'display',
            'hosts': remote_hosts,
        })

    findings.sort(key=lambda f: (SEVERITY_ORDER[f['severity']], f['key']))
    return findings


def build_markdown_report(findings, hosts):
    """Build a Markdown-formatted string suitable for pasting into security reports."""
    now_str = datetime.now().strftime('%d.%m.%Y %H:%M')
    lines = [
        f'# Turvaleiud — {now_str} (koondraport v{__version__})',
        '',
        f'Hosts auditis: **{len(hosts)}** — {", ".join(h0["name"] for h0 in hosts)}',
        '',
    ]
    if not findings:
        lines.append('_Leide ei tuvastatud._')
        return '\n'.join(lines)

    for f in findings:
        sev_label = SEVERITY_LABEL[f['severity']]
        count = f.get('summary_count', len(f['hosts']))
        suffix = f.get('summary_suffix', 'masinat')
        lines.append(f"## [{sev_label}] {f['title']} ({count} {suffix})")
        for host_entry in f['hosts']:
            if host_entry.get('detail'):
                lines.append(f"- **{host_entry['name']}** — {host_entry['detail']}")
            else:
                lines.append(f"- **{host_entry['name']}**")
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

HTML_HEAD = """<!DOCTYPE html>
<html lang="et">
<head>
    <meta charset="UTF-8">
    <title>Masinate oleku raport</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap">
    <style>
        :root {
            /* Surfaces */
            --bg: #f6f7f9;
            --surface: #ffffff;
            --surface-2: #f8fafc;
            --surface-3: #eef1f5;
            --border: #e4e7ec;
            --border-strong: #d0d5dd;

            /* Text */
            --text: #0f172a;
            --text-muted: #475569;
            --text-subtle: #64748b;
            --text-faint: #94a3b8;

            /* Semantic */
            --ok: #059669;
            --ok-bg: #ecfdf5;
            --ok-border: #a7f3d0;
            --warn: #d97706;
            --warn-bg: #fffbeb;
            --warn-border: #fde68a;
            --bad: #dc2626;
            --bad-bg: #fef2f2;
            --bad-border: #fecaca;
            --info: #2563eb;
            --info-bg: #eff6ff;
            --info-border: #bfdbfe;

            /* Accent */
            --accent: #4f46e5;
            --accent-weak: #eef2ff;

            /* Radii */
            --r-sm: 6px;
            --r-md: 8px;
            --r-lg: 12px;
            --r-xl: 16px;

            /* Shadows */
            --sh-sm: 0 1px 2px rgba(15,23,42,.04);
            --sh-md: 0 1px 3px rgba(15,23,42,.06), 0 1px 2px rgba(15,23,42,.04);
            --sh-lg: 0 10px 30px rgba(15, 23, 42, .08);
        }
        html { -webkit-text-size-adjust: 100%; }
        body {
            background: var(--bg);
            color: var(--text);
            font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
            font-size: 14px;
            line-height: 1.5;
            font-feature-settings: "cv02", "cv03", "cv04", "cv11";
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        code, .tabular, .mono {
            font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
            font-variant-numeric: tabular-nums;
        }
        .num { font-variant-numeric: tabular-nums; }

        /* ================ HERO ================ */
        .hero {
            position: relative; overflow: hidden;
            background:
              radial-gradient(1200px 400px at 85% -10%, rgba(79,70,229,.22), transparent 60%),
              radial-gradient(900px 300px at 10% 110%, rgba(14,165,233,.14), transparent 60%),
              linear-gradient(135deg, #0b1220, #111a2e 60%, #0f172a);
            color: #f1f5f9;
            border-radius: var(--r-xl);
            padding: 1.75rem 2rem 1.5rem;
            margin-bottom: 1.25rem;
            box-shadow: var(--sh-lg);
        }
        .hero::after {
            content: ""; position: absolute; inset: 0;
            background-image:
              linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px),
              linear-gradient(90deg, rgba(255,255,255,.03) 1px, transparent 1px);
            background-size: 32px 32px;
            mask-image: linear-gradient(180deg, rgba(0,0,0,.8), transparent 70%);
            pointer-events: none;
        }
        .hero > * { position: relative; z-index: 1; }
        .hero-eyebrow {
            color: #a5b4fc; font-size: .72rem; font-weight: 600;
            text-transform: uppercase; letter-spacing: .12em; margin-bottom: .35rem;
        }
        .hero h1 {
            margin: 0 0 .4rem 0;
            font-weight: 700; font-size: 1.85rem;
            letter-spacing: -.02em;
        }
        .hero .sub { color: #cbd5e1; font-size: .97rem; line-height: 1.55; max-width: 760px; }
        .hero .sub strong { color: #fff; font-weight: 600; }
        .hero .meta {
            color: #94a3b8; font-size: .78rem; line-height: 1.55;
            text-align: right;
        }
        .hero .meta code {
            background: rgba(255,255,255,.07); color: #cbd5e1;
            border: 1px solid rgba(255,255,255,.08);
        }
        .hero-stats {
            display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: .75rem; margin-top: 1.25rem;
        }
        .hero-stat {
            background: rgba(255,255,255,.04);
            border: 1px solid rgba(255,255,255,.08);
            border-radius: var(--r-md);
            padding: .8rem .95rem;
            backdrop-filter: blur(6px);
        }
        .hero-stat .stat-label {
            color: #94a3b8; font-size: .72rem; font-weight: 500;
            text-transform: uppercase; letter-spacing: .08em;
        }
        .hero-stat .stat-value {
            margin-top: .25rem;
            font-size: 1.6rem; font-weight: 700; letter-spacing: -.02em;
            color: #f8fafc; font-variant-numeric: tabular-nums;
            display: flex; align-items: baseline; gap: .4rem;
        }
        .hero-stat .stat-suffix { font-size: .8rem; color: #94a3b8; font-weight: 500; }
        .hero-stat.is-bad  .stat-value { color: #fecaca; }
        .hero-stat.is-warn .stat-value { color: #fcd34d; }
        .hero-stat.is-ok   .stat-value { color: #a7f3d0; }
        @media (max-width: 900px) { .hero-stats { grid-template-columns: repeat(2, 1fr); } }

        /* ================ SECTIONS ================ */
        .section-card {
            background: var(--surface); border-radius: var(--r-lg);
            box-shadow: var(--sh-md);
            padding: 1.25rem 1.4rem; margin-bottom: 1.25rem;
            border: 1px solid var(--border);
        }
        .section-head {
            display: flex; align-items: center; justify-content: space-between;
            gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap;
        }
        .section-head h5 {
            margin: 0; font-weight: 600; color: var(--text);
            display: flex; align-items: center; gap: .55rem;
            font-size: 1.02rem; letter-spacing: -.005em;
        }
        .section-head h5 i { color: var(--text-subtle); font-size: 1.05rem; }
        .section-head .sub { color: var(--text-subtle); font-size: .82rem; }

        /* ================ CHIPS / BADGES ================ */
        .chip {
            display: inline-flex; align-items: center; gap: .25rem;
            padding: .12rem .5rem; border-radius: 999px;
            font-size: .7rem; font-weight: 600; margin-left: .25rem;
            white-space: nowrap; line-height: 1.5;
            border: 1px solid transparent;
            font-variant-numeric: tabular-nums;
        }
        .chip-danger { background: var(--bad-bg);  color: #991b1b; border-color: var(--bad-border); }
        .chip-warn   { background: var(--warn-bg); color: #92400e; border-color: var(--warn-border); }
        .chip-info   { background: var(--info-bg); color: #1e40af; border-color: var(--info-border); }
        .chip-muted  { background: var(--surface-3); color: var(--text-muted); border-color: var(--border); }
        .chip-ok     { background: var(--ok-bg);   color: #065f46; border-color: var(--ok-border); }

        /* ================ SECURITY FINDINGS ================ */
        .sec-findings .section-head {
            display: flex; justify-content: space-between; align-items: flex-start;
            gap: 1rem; flex-wrap: wrap;
        }
        .sf-head-right {
            display: flex; align-items: center; gap: .75rem; flex-wrap: wrap;
        }
        .sf-summary { display: flex; gap: .4rem; flex-wrap: wrap; }
        .sf-pill {
            display: inline-flex; align-items: center;
            padding: .2rem .6rem; border-radius: 999px;
            font-size: .72rem; font-weight: 600; letter-spacing: .01em;
            border: 1px solid transparent;
            font-variant-numeric: tabular-nums;
            white-space: nowrap;
        }
        .sf-pill-critical { background: #fee2e2; color: #991b1b; border-color: #fecaca; }
        .sf-pill-high     { background: var(--bad-bg); color: #991b1b; border-color: var(--bad-border); }
        .sf-pill-medium   { background: var(--warn-bg); color: #92400e; border-color: var(--warn-border); }
        .sf-pill-info     { background: var(--info-bg); color: #1e40af; border-color: var(--info-border); }

        /* --- CVE / vulnerability table --- */
        .sec-vulns .table-responsive { padding: .25rem 1rem 1rem; }
        .cve-table { font-size: .82rem; }
        .cve-table thead th {
            background: var(--bg); color: var(--text-muted);
            font-size: .7rem; font-weight: 600; text-transform: uppercase;
            letter-spacing: .04em; border-bottom: 1px solid var(--border);
            padding: .55rem .6rem;
        }
        .cve-table tbody td {
            padding: .55rem .6rem; vertical-align: top;
            border-bottom: 1px solid var(--border);
        }
        .cve-table .mono { font-family: 'JetBrains Mono', monospace; font-size: .78rem; }
        .cve-cpe { font-family: 'JetBrains Mono', monospace; font-size: .7rem; color: var(--text-muted); }
        .cve-sev-badge {
            display: inline-block; min-width: 2.4rem; text-align: center;
            padding: .25rem .55rem; border-radius: var(--r-sm);
            font-weight: 700; font-variant-numeric: tabular-nums;
            font-size: .85rem;
        }
        .cve-sev-critical { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .cve-sev-high     { background: var(--bad-bg); color: #991b1b; border: 1px solid var(--bad-border); }
        .cve-sev-medium   { background: var(--warn-bg); color: #92400e; border: 1px solid var(--warn-border); }
        .cve-sev-low      { background: var(--info-bg); color: #1e40af; border: 1px solid var(--info-border); }
        .cve-sev-none     { background: var(--bg); color: var(--text-muted); border: 1px solid var(--border); }
        .cve-item {
            display: flex; gap: .5rem; align-items: flex-start;
            padding: .2rem 0;
            border-bottom: 1px dashed var(--border);
        }
        .cve-item:last-child { border-bottom: none; }
        .cve-id {
            font-family: 'JetBrains Mono', monospace; font-size: .72rem;
            font-weight: 600; text-decoration: none; white-space: nowrap;
            color: var(--accent);
        }
        .cve-id:hover { text-decoration: underline; }
        .cve-score {
            font-size: .7rem; font-weight: 600;
            padding: .1rem .35rem; border-radius: 4px;
            white-space: nowrap;
        }
        .cve-desc { font-size: .72rem; color: var(--text-muted); line-height: 1.3; }
        .cve-more { margin-top: .35rem; }
        .cve-more summary {
            font-size: .7rem; color: var(--accent); cursor: pointer;
            font-weight: 600; list-style: none;
        }
        .cve-more summary::before { content: "▸ "; }
        .cve-more[open] summary::before { content: "▾ "; }
        .cve-more-list { margin-top: .35rem; font-size: .7rem; line-height: 1.6; }
        .cve-more-list a { font-family: 'JetBrains Mono', monospace; color: var(--accent); }

        .btn-copy-findings {
            --bs-btn-color: var(--text);
            --bs-btn-bg: var(--surface);
            --bs-btn-border-color: var(--border);
            --bs-btn-hover-bg: var(--accent);
            --bs-btn-hover-color: #fff;
            --bs-btn-hover-border-color: var(--accent);
            font-size: .78rem; font-weight: 600;
            display: inline-flex; align-items: center; gap: .4rem;
            border-radius: var(--r-sm);
            padding: .38rem .75rem;
            box-shadow: var(--sh-sm);
        }
        .btn-copy-findings.is-copied {
            --bs-btn-bg: var(--ok-bg);
            --bs-btn-border-color: var(--ok-border);
            --bs-btn-color: #065f46;
        }

        .sf-grid {
            display: grid; gap: .75rem;
            grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
            padding: 1rem 1.25rem 1.25rem;
        }
        .sf-card {
            background: var(--surface); border: 1px solid var(--border);
            border-radius: var(--r-md); overflow: hidden;
            display: flex; flex-direction: column;
            box-shadow: var(--sh-sm);
        }
        .sf-card.sf-critical { border-top: 3px solid #dc2626; }
        .sf-card.sf-high     { border-top: 3px solid var(--bad); }
        .sf-card.sf-medium   { border-top: 3px solid var(--warn); }
        .sf-card.sf-info     { border-top: 3px solid var(--info); }

        .sf-card-head {
            display: flex; align-items: center; gap: .7rem;
            padding: .8rem 1rem;
            border-bottom: 1px solid var(--border);
            background: var(--surface-2);
        }
        .sf-icon {
            width: 34px; height: 34px; border-radius: 8px;
            display: inline-flex; align-items: center; justify-content: center;
            font-size: 1rem; flex-shrink: 0;
        }
        .sf-critical .sf-icon { background: #fee2e2; color: #dc2626; }
        .sf-high     .sf-icon { background: var(--bad-bg);  color: var(--bad); }
        .sf-medium   .sf-icon { background: var(--warn-bg); color: var(--warn); }
        .sf-info     .sf-icon { background: var(--info-bg); color: var(--info); }

        .sf-title-wrap { flex: 1; min-width: 0; }
        .sf-sev-label {
            display: block;
            font-size: .64rem; font-weight: 700; letter-spacing: .08em;
            text-transform: uppercase; color: var(--text-subtle);
            margin-bottom: .1rem;
        }
        .sf-title {
            font-size: .92rem; font-weight: 600; color: var(--text);
            line-height: 1.3; letter-spacing: -.005em;
        }
        .sf-count {
            margin-left: auto; flex-shrink: 0;
            font-size: .72rem; font-weight: 600;
            color: var(--text-muted); background: var(--surface-3);
            padding: .2rem .55rem; border-radius: 999px;
            font-variant-numeric: tabular-nums;
        }

        .sf-hosts {
            list-style: none; margin: 0; padding: .5rem 1rem .9rem;
        }
        .sf-hosts li {
            padding: .45rem 0; border-bottom: 1px solid var(--border);
        }
        .sf-hosts li:last-child { border-bottom: none; }
        .sf-host-name {
            font-family: "JetBrains Mono", monospace;
            font-size: .82rem; font-weight: 600; color: var(--text);
        }
        .sf-host-detail {
            font-size: .76rem; color: var(--text-subtle);
            margin-top: .15rem; line-height: 1.4;
        }
        .sf-empty {
            padding: 1.5rem; display: flex; align-items: center; gap: .6rem;
            color: var(--text-subtle); font-size: .9rem;
        }
        .sf-empty i { color: var(--ok); font-size: 1.1rem; }

        /* ================ HEALTH / RISK ICONS ================ */
        .health-dot {
            display: inline-block; width: 9px; height: 9px;
            border-radius: 50%; margin-right: .55rem;
            vertical-align: middle; flex-shrink: 0;
        }
        .health-green  { background: var(--ok);   box-shadow: 0 0 0 3px rgba(5,150,105,.15); }
        .health-yellow { background: var(--warn); box-shadow: 0 0 0 3px rgba(217,119,6,.18); }
        .health-red    { background: var(--bad);  box-shadow: 0 0 0 3px rgba(220,38,38,.18); }

        .risk-icons { display: inline-flex; gap: .3rem; align-items: center; }
        .risk-icons .ri {
            width: 26px; height: 26px; border-radius: 6px;
            display: inline-flex; align-items: center; justify-content: center;
            font-size: .92rem;
            border: 1px solid var(--border);
            background: var(--surface);
        }
        .risk-icons .ri.on   { color: var(--ok);   background: var(--ok-bg);   border-color: var(--ok-border); }
        .risk-icons .ri.off  { color: var(--bad);  background: var(--bad-bg);  border-color: var(--bad-border); }
        .risk-icons .ri.warn { color: var(--warn); background: var(--warn-bg); border-color: var(--warn-border); }

        /* ================ HOST TABLE ================ */
        #hostTable { margin-bottom: 0; }
        #hostTable thead th {
            background: var(--surface-2); color: var(--text-muted);
            border: none; border-bottom: 1px solid var(--border);
            font-weight: 600; font-size: .72rem; letter-spacing: .06em;
            text-transform: uppercase; padding: .7rem .75rem;
        }
        #hostTable tbody tr { cursor: default; }
        #hostTable tbody tr:hover { background: var(--surface-2) !important; }
        #hostTable tbody td {
            vertical-align: middle; padding: .85rem .75rem;
            border-top: 1px solid var(--border); border-bottom: none;
            font-size: .88rem;
        }
        #hostTable .host-name {
            font-weight: 600; font-size: .94rem; color: var(--text);
            letter-spacing: -.005em;
        }
        #hostTable .meta-line {
            color: var(--text-subtle); font-size: .78rem; margin-top: .15rem;
        }
        #hostTable .meta-line.mono { font-family: "JetBrains Mono", monospace; font-size: .74rem; }
        /* DataTables controls polish */
        .dataTables_wrapper .dataTables_length select,
        .dataTables_wrapper .dataTables_filter input {
            border: 1px solid var(--border); border-radius: var(--r-sm);
            padding: .25rem .5rem; font-size: .85rem;
        }
        .dataTables_wrapper .dataTables_info { color: var(--text-subtle); font-size: .8rem; }
        .dataTables_wrapper .paginate_button { font-size: .85rem; }

        /* ================ MATRIX ================ */
        .matrix-controls {
            background: var(--surface-2); padding: .8rem 1rem;
            border: 1px solid var(--border); border-bottom: 0;
            border-radius: var(--r-md) var(--r-md) 0 0;
            display: flex; flex-wrap: wrap; align-items: center; gap: .85rem;
        }
        .matrix-controls .search-wrap {
            position: relative; min-width: 240px; flex: 1 1 260px;
        }
        .matrix-controls .search-wrap i {
            position: absolute; top: 50%; left: .7rem; transform: translateY(-50%);
            color: var(--text-faint); font-size: .9rem; pointer-events: none;
        }
        .matrix-controls input[type="text"] {
            padding-left: 2rem; border: 1px solid var(--border);
            background: var(--surface); border-radius: var(--r-sm);
            font-size: .86rem; height: 34px;
        }
        .matrix-controls input[type="text"]:focus {
            border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-weak);
        }
        .filter-pills {
            display: inline-flex; gap: .3rem;
            padding: 3px; background: var(--surface-3); border-radius: var(--r-sm);
        }
        .filter-pills .form-check {
            margin: 0; padding: 0;
        }
        .filter-pills input[type="checkbox"] {
            position: absolute; opacity: 0; pointer-events: none;
        }
        .filter-pills label {
            display: inline-flex; align-items: center; gap: .3rem;
            padding: .3rem .65rem; border-radius: 5px;
            font-size: .78rem; font-weight: 500; color: var(--text-muted);
            cursor: pointer; user-select: none;
            border: 1px solid transparent;
        }
        .filter-pills label:hover { color: var(--text); }
        .filter-pills input[type="checkbox"]:checked + label {
            background: var(--surface); color: var(--text);
            border-color: var(--border); box-shadow: var(--sh-sm);
            font-weight: 600;
        }
        .filter-pills label i { font-size: .85rem; color: var(--text-subtle); }
        .filter-pills input[type="checkbox"]:checked + label i { color: var(--accent); }
        .visible-count {
            margin-left: auto; font-size: .78rem; color: var(--text-subtle);
            font-variant-numeric: tabular-nums;
        }
        .visible-count strong { color: var(--text); font-weight: 600; }

        .matrix-wrap {
            overflow-x: auto; position: relative;
            border: 1px solid var(--border); border-radius: 0 0 var(--r-md) var(--r-md);
        }
        table.matrix { font-size: .82rem; margin: 0; background: var(--surface); width: 100%; }
        table.matrix thead th {
            background: var(--surface-2) !important; color: var(--text-muted) !important;
            border: none !important; border-bottom: 1px solid var(--border) !important;
            padding: .65rem .6rem;
            font-weight: 600; font-size: .7rem;
            letter-spacing: .06em; text-transform: uppercase;
        }
        table.matrix th.sw-name-col, table.matrix td.sw-name {
            position: sticky; left: 0; z-index: 2;
            background: var(--surface); min-width: 300px; text-align: left;
            border-right: 1px solid var(--border);
            padding: .6rem .9rem;
        }
        table.matrix thead th.sw-name-col { background: var(--surface-2) !important; }
        table.matrix th.host-col {
            white-space: nowrap; text-align: center; min-width: 130px;
            font-family: "JetBrains Mono", monospace; font-weight: 500;
        }
        table.matrix td {
            text-align: center; white-space: nowrap; padding: .55rem .6rem;
            font-variant-numeric: tabular-nums;
            border-bottom: 1px solid var(--border);
        }
        table.matrix tbody tr:last-child td { border-bottom: none; }
        table.matrix td.missing { color: var(--text-faint); background: var(--surface-2); }
        table.matrix td.match   { background: #f0fdf4; color: #166534; font-weight: 500; }
        table.matrix td.drift   { background: #fffbeb; color: #92400e; font-weight: 600; }
        table.matrix td.unique  { background: #fef2f2; color: #991b1b; font-weight: 500; }
        table.matrix td.drift.is-latest {
            background: #ecfdf5; color: #065f46;
            position: relative;
        }
        table.matrix td.drift.is-latest::after {
            content: ""; position: absolute; top: 5px; right: 5px;
            width: 6px; height: 6px; background: var(--ok); border-radius: 50%;
            box-shadow: 0 0 0 2px #ecfdf5;
        }
        table.matrix tbody tr:hover td { filter: brightness(.98); }
        table.matrix tbody tr:hover td.sw-name { background: var(--surface-2); }
        table.matrix td.cell-clickable { cursor: pointer; }
        table.matrix td.host-count {
            color: var(--text-subtle); font-weight: 500; font-size: .76rem;
        }
        .sw-name .sw-title { font-weight: 600; color: var(--text); font-size: .88rem; }
        .sw-name .sw-vendor { color: var(--text-subtle); font-size: .75rem; margin-top: .1rem; }
        .sw-name .sw-latest {
            font-size: .74rem; color: var(--text-subtle); margin-top: .35rem;
            display: flex; align-items: center; gap: .3rem; flex-wrap: wrap;
        }
        .sw-name .sw-latest code { font-size: .72rem; }
        .row-drift      td.sw-name { border-left: 3px solid var(--warn); }
        .row-unique     td.sw-name { border-left: 3px solid var(--bad); }
        .row-consistent td.sw-name { border-left: 3px solid var(--ok); }

        .matrix-legend {
            display: flex; flex-wrap: wrap; gap: .4rem; align-items: center;
            margin-top: .75rem; font-size: .76rem; color: var(--text-subtle);
        }
        .matrix-legend .legend-label { font-weight: 500; margin-right: .3rem; }
        .legend-chip {
            display: inline-flex; align-items: center; gap: .3rem;
            padding: .2rem .55rem; border-radius: 5px;
            font-weight: 500; font-size: .72rem;
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--text-muted);
        }
        .legend-chip .sw-dot {
            display: inline-block; width: 8px; height: 8px; border-radius: 50%;
        }
        .legend-chip.lc-match  { background: #f0fdf4; border-color: #bbf7d0; color: #166534; }
        .legend-chip.lc-latest { background: #ecfdf5; border-color: #a7f3d0; color: #065f46; }
        .legend-chip.lc-drift  { background: #fffbeb; border-color: #fde68a; color: #92400e; }
        .legend-chip.lc-unique { background: #fef2f2; border-color: #fecaca; color: #991b1b; }

        .matrix-hint {
            margin-top: .5rem; font-size: .76rem; color: var(--text-faint);
            display: flex; align-items: center; gap: .35rem;
        }
        .matrix-hint i { color: var(--text-subtle); }

        /* ================ MODAL ================ */
        .modal-content { border: none; border-radius: var(--r-lg); overflow: hidden; }
        .modal-header {
            background: linear-gradient(135deg, #0b1220, #1e293b) !important;
            border: none; color: #f1f5f9;
        }
        .modal-header .btn-close { filter: invert(1) brightness(1.5); }
        .modal-meta {
            background: var(--surface-2); border-radius: var(--r-md);
            padding: .85rem 1rem; margin-bottom: 1.1rem;
            border: 1px solid var(--border);
        }
        .modal-meta .label {
            color: var(--text-subtle); font-size: .7rem; font-weight: 600;
            text-transform: uppercase; letter-spacing: .06em;
        }
        .modal-meta .value { font-weight: 500; font-size: .9rem; color: var(--text); }
        .modal h6 {
            display: flex; align-items: center; gap: .45rem;
            font-weight: 600; color: var(--text); font-size: .88rem;
            text-transform: uppercase; letter-spacing: .04em; margin-bottom: .6rem;
        }
        .modal h6 i { color: var(--text-subtle); font-size: .95rem; }
        .modal .list-unstyled li {
            padding: .35rem 0; border-bottom: 1px dashed var(--border);
            font-size: .85rem;
        }
        .modal .list-unstyled li:last-child { border-bottom: none; }

        code {
            background: var(--surface-3); padding: .08rem .34rem;
            border-radius: 4px; font-size: .82em; color: var(--text);
            border: 1px solid var(--border);
        }

        .btn-outline-primary {
            --bs-btn-color: var(--accent);
            --bs-btn-border-color: var(--border);
            --bs-btn-hover-bg: var(--accent-weak);
            --bs-btn-hover-border-color: #c7d2fe;
            --bs-btn-hover-color: var(--accent);
            --bs-btn-focus-shadow-rgb: 79, 70, 229;
            font-size: .82rem; font-weight: 500;
            border-radius: var(--r-sm);
        }
    </style>
</head>
<body class="p-4">
    <div class="container-fluid" style="max-width: 1600px;">
"""

HTML_FOOTER_TAIL = """
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
    <script>
        $(document).ready(function() {
            $('#hostTable').DataTable({
                "language": { "url": "//cdn.datatables.net/plug-ins/1.13.4/i18n/et.json" },
                "pageLength": 25,
                "order": [[ 0, 'asc' ]],
                "columnDefs": [{ orderable: false, targets: [3, 4, 5] }]
            });

            function applyMatrixFilters() {
                const onlyDiff = $('#filterOnlyDiff').is(':checked');
                const hideEid  = $('#filterHideEid').is(':checked');
                const search   = ($('#matrixSearch').val() || '').toLowerCase();
                let visible = 0;
                $('#matrixTable tbody tr').each(function() {
                    const $r = $(this);
                    const isEid  = $r.data('eid') === true || $r.data('eid') === 'True';
                    const status = $r.data('status');
                    const swName = ($r.data('swname') || '').toLowerCase();
                    let show = true;
                    if (onlyDiff && status === 'consistent') show = false;
                    if (hideEid && isEid) show = false;
                    if (search && swName.indexOf(search) === -1) show = false;
                    $r.toggle(show);
                    if (show) visible++;
                });
                $('#matrixVisibleCount').text(visible);
            }
            $('#filterOnlyDiff, #filterHideEid').on('change', applyMatrixFilters);
            $('#matrixSearch').on('input', applyMatrixFilters);
            applyMatrixFilters();

            $('#copyFindingsBtn').on('click', function() {
                var md = window.__FINDINGS_MD__ || '';
                var $btn = $('#copyFindingsBtn');
                var $label = $btn.find('.btn-copy-label');
                var $icon = $btn.find('i');
                function flashSuccess() {
                    $btn.addClass('is-copied');
                    $icon.removeClass('bi-clipboard').addClass('bi-check-lg');
                    $label.text('Kopeeritud');
                    setTimeout(function() {
                        $btn.removeClass('is-copied');
                        $icon.removeClass('bi-check-lg').addClass('bi-clipboard');
                        $label.text('Kopeeri Markdown');
                    }, 2000);
                }
                function fallbackCopy() {
                    var ta = document.createElement('textarea');
                    ta.value = md;
                    ta.style.position = 'fixed';
                    ta.style.opacity = '0';
                    document.body.appendChild(ta);
                    ta.select();
                    try { document.execCommand('copy'); flashSuccess(); }
                    catch (e) { console.error(e); }
                    document.body.removeChild(ta);
                }
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(md).then(flashSuccess, fallbackCopy);
                } else {
                    fallbackCopy();
                }
            });

            $('#matrixTable').on('click', 'td.cell-clickable', function() {
                var safe = $(this).data('host');
                var el = document.getElementById('modal-' + safe);
                if (el) bootstrap.Modal.getOrCreateInstance(el).show();
            });
        });
    </script>
</body>
</html>
"""


def safe_id(name):
    return re.sub(r'[^a-zA-Z0-9]', '', name) or 'host'


def render_hero(hosts, matrix):
    generated = datetime.now().strftime("%d.%m.%Y %H:%M")
    total = len(hosts)
    bitlocker_off = sum(1 for h0 in hosts if not h0['bitlocker'])
    admin_users = sum(1 for h0 in hosts if h0['metrics']['is_admin_user'])
    drift_total = sum(1 for e in matrix if e['status'] == 'drift')

    def stat(label, value, suffix='', tone=''):
        tone_cls = f' {tone}' if tone else ''
        suffix_html = f'<span class="stat-suffix">{h(suffix)}</span>' if suffix else ''
        return (
            f'<div class="hero-stat{tone_cls}">'
            f'  <div class="stat-label">{h(label)}</div>'
            f'  <div class="stat-value">{value}{suffix_html}</div>'
            f'</div>'
        )

    stats = [
        stat('Masinad', total, tone='is-ok'),
        stat('BitLocker puudub', bitlocker_off, suffix=f'/ {total}',
             tone='is-bad' if bitlocker_off else 'is-ok'),
        stat('Administraatori õigustes kasutajad', admin_users,
             tone='is-bad' if admin_users else 'is-ok'),
        stat('Sama tarkvara, eri versioon', drift_total, suffix='paketti',
             tone='is-warn' if drift_total else 'is-ok'),
    ]

    return f"""
        <div class="hero">
            <div class="d-flex justify-content-between align-items-start flex-wrap gap-3">
                <div style="max-width: 1000px;">
                    <div class="hero-eyebrow">mCollector · Tarkvara ülevaade</div>
                    <h1>Masinate koondraport</h1>
                </div>
                <div class="meta">
                    Koostatud: <strong style="color:#e2e8f0;">{generated}</strong> · <span style="color:#94a3b8;">v{__version__}</span><br>
                    Kaust: <code>{h(UPLOAD_DIR)}/</code>
                </div>
            </div>
            <div class="hero-stats">
                {''.join(stats)}
            </div>
        </div>
    """


def render_security_findings(findings, hosts, matrix):
    markdown = build_markdown_report(findings, hosts)
    md_json = json.dumps(markdown)

    if not findings:
        return f"""
        <div class="section-card sec-findings">
            <div class="section-head">
                <h5><i class="bi bi-shield-check"></i> Turvaleiud</h5>
                <div class="sub">Leide ei tuvastatud</div>
            </div>
            <div class="sf-empty">
                <i class="bi bi-check-circle-fill"></i>
                Fleet on hetkel ilma tähelepanu vajavate leidudeta.
            </div>
        </div>
        """

    critical = sum(1 for f in findings if f['severity'] == 'critical')
    high = sum(1 for f in findings if f['severity'] == 'high')
    medium = sum(1 for f in findings if f['severity'] == 'medium')
    info = sum(1 for f in findings if f['severity'] == 'info')

    summary_chips = []
    if critical:
        summary_chips.append(f"<span class='sf-pill sf-pill-critical'>{critical} kriitiline</span>")
    if high:
        summary_chips.append(f"<span class='sf-pill sf-pill-high'>{high} kõrge</span>")
    if medium:
        summary_chips.append(f"<span class='sf-pill sf-pill-medium'>{medium} keskmine</span>")
    if info:
        summary_chips.append(f"<span class='sf-pill sf-pill-info'>{info} info</span>")

    cards = []
    for f in findings:
        sev = f['severity']
        host_items = []
        for host_entry in f['hosts']:
            detail_html = (
                f"<div class='sf-host-detail'>{h(host_entry['detail'])}</div>"
                if host_entry.get('detail') else ''
            )
            host_items.append(
                f"<li><div class='sf-host-name'>{h(host_entry['name'])}</div>{detail_html}</li>"
            )
        count = f.get('summary_count', len(f['hosts']))
        suffix = f.get('summary_suffix', 'masinat')
        cards.append(f"""
            <div class="sf-card sf-{sev}">
                <div class="sf-card-head">
                    <span class="sf-icon"><i class="bi bi-{f['icon']}"></i></span>
                    <div class="sf-title-wrap">
                        <span class="sf-sev-label">{SEVERITY_LABEL[sev]}</span>
                        <div class="sf-title">{h(f['title'])}</div>
                    </div>
                    <span class="sf-count">{count} {h(suffix)}</span>
                </div>
                <ul class="sf-hosts">{''.join(host_items)}</ul>
            </div>
        """)

    return f"""
        <div class="section-card sec-findings">
            <div class="section-head">
                <h5><i class="bi bi-shield-exclamation"></i> Turvaleiud</h5>
                <div class="sf-head-right">
                    <div class="sf-summary">{''.join(summary_chips)}</div>
                    <button type="button" id="copyFindingsBtn" class="btn btn-sm btn-copy-findings">
                        <i class="bi bi-clipboard"></i>
                        <span class="btn-copy-label">Kopeeri Markdown</span>
                    </button>
                </div>
            </div>
            <div class="sf-grid">{''.join(cards)}</div>
            <textarea id="findingsMarkdown" style="display:none;"></textarea>
            <script>window.__FINDINGS_MD__ = {md_json};</script>
        </div>
    """


def render_host_table(hosts, safe_ids):
    rows = []
    for host in hosts:
        m = host['metrics']
        health_cls = f"health-{m['health']}"
        health_label = {'green': 'Korras', 'yellow': 'Tähele panna',
                        'red': 'Vajab tähelepanu'}[m['health']]

        icons = []
        if m['defender_on']:
            icons.append('<span class="ri on" title="Defender aktiivne"><i class="bi bi-shield-check"></i></span>')
        else:
            icons.append('<span class="ri off" title="Defender MITTE aktiivne"><i class="bi bi-shield-slash"></i></span>')
        if host['bitlocker']:
            icons.append('<span class="ri on" title="BitLocker aktiivne"><i class="bi bi-lock-fill"></i></span>')
        else:
            icons.append('<span class="ri warn" title="BitLocker puudub"><i class="bi bi-unlock"></i></span>')
        if m['is_admin_user']:
            icons.append('<span class="ri off" title="Aktiivne kasutaja on lokaalne admin"><i class="bi bi-person-fill-gear"></i></span>')

        # Tarkvaraolek column
        chips = []
        if m['lagging']:
            chips.append(f"<span class='chip chip-warn'>{len(m['lagging'])} vananenud</span>")
        if m['unique_sw']:
            chips.append(f"<span class='chip chip-muted'>{len(m['unique_sw'])} ainult siin</span>")
        if not chips:
            chips.append("<span class='chip chip-ok'>Korras</span>")

        user_role_chip = (
            "<span class='chip chip-danger'>Lokaalne admin</span>"
            if m['is_admin_user'] else
            "<span class='chip chip-muted'>Tavakasutaja</span>"
        )

        updates_date = host['updates_last_install'][:10] if host['updates_last_install'] != '-' else '–'

        rows.append(f"""
            <tr data-host="{safe_ids[host['name']]}">
                <td>
                    <div class="d-flex align-items-center">
                      <span class="health-dot {health_cls}" title="{health_label}"></span>
                      <div>
                        <div class="host-name">{h(host['name'])}</div>
                        <div class="meta-line">{h(host['desc'])}</div>
                        <div class="meta-line">Boot: {h(host['boot'])}</div>
                      </div>
                    </div>
                </td>
                <td>
                    <div>{h(host['os'])}</div>
                    <div class="meta-line mono">{h(host['ip'])}</div>
                    <div class="meta-line">Uuendatud: {h(updates_date)}</div>
                </td>
                <td>
                    <div class="host-name" style="font-size:.88rem;">{h(host['user'])}</div>
                    <div class="mt-1">{user_role_chip}</div>
                </td>
                <td><div class="risk-icons">{"".join(icons)}</div></td>
                <td>{" ".join(chips)}</td>
                <td class="text-end">
                    <button type="button" class="btn btn-sm btn-outline-primary"
                            data-bs-toggle="modal" data-bs-target="#modal-{safe_ids[host['name']]}">
                        Ava detailid <i class="bi bi-arrow-right"></i>
                    </button>
                </td>
            </tr>
        """)

    return f"""
        <div class="section-card">
            <div class="section-head">
                <h5><i class="bi bi-pc-display-horizontal"></i> Masinad</h5>
                <div class="sub">{len(hosts)} arvutit ülevaates</div>
            </div>
            <table id="hostTable" class="table align-middle">
                <thead>
                    <tr>
                        <th>Seisund · Arvuti</th>
                        <th>OS · võrk</th>
                        <th>Kasutaja</th>
                        <th>Turvaolek</th>
                        <th>Tarkvaraolek</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>{"".join(rows)}</tbody>
            </table>
        </div>
    """


def render_matrix(matrix, hosts, safe_ids):
    host_names = [host['name'] for host in hosts]
    header_cells = "".join(
        f'<th class="host-col">{h(n)}</th>' for n in host_names
    )

    body_rows = []
    for entry in matrix:
        cells = []
        for hn in host_names:
            info = entry['per_host'].get(hn)
            if not info:
                cells.append('<td class="missing">–</td>')
                continue
            ver = info['version']
            idate = info['install_date']
            title = ''
            if idate and len(idate) == 8:
                title = f' title="Paigaldatud: {idate[:4]}-{idate[4:6]}-{idate[6:8]}"'
            if entry['status'] == 'unique':
                cls = 'unique'
            elif entry['status'] == 'drift':
                cls = 'drift'
                if ver == entry.get('latest_version'):
                    cls += ' is-latest'
            else:
                cls = 'match'
            cells.append(
                f'<td class="{cls} cell-clickable" data-host="{safe_ids[hn]}"{title}>{h(ver)}</td>'
            )

        vendor = entry['vendor'] if entry['vendor'] and entry['vendor'] != '-' else ''
        vendor_html = f'<div class="sw-vendor">{h(vendor)}</div>' if vendor else ''
        is_eid = 'true' if entry['is_eid'] else 'false'

        latest = entry.get('latest_version', '')
        latest_info = ''
        if latest:
            latest_info = (
                f'<div class="sw-latest">Uusim <code>{h(latest)}</code></div>'
            )

        body_rows.append(
            f'<tr class="row-{entry["status"]}" data-status="{entry["status"]}" '
            f'data-eid="{is_eid}" data-swname="{h(entry["display_name"])}">'
            f'<td class="sw-name">'
            f'  <div class="sw-title">{h(entry["display_name"])}</div>'
            f'  {vendor_html}{latest_info}'
            f'</td>'
            + "".join(cells)
            + f'<td class="host-count num">{entry["host_count"]}<span style="opacity:.5">/{len(hosts)}</span></td>'
            + '</tr>'
        )

    legend = (
        '<span class="legend-label">Legend:</span>'
        '<span class="legend-chip lc-latest"><span class="sw-dot" style="background:var(--ok)"></span>Uusim versioon</span>'
        '<span class="legend-chip lc-match">Ühtne fleetis</span>'
        '<span class="legend-chip lc-drift">Vananenud</span>'
        '<span class="legend-chip lc-unique">Ainult ühel masinal</span>'
    )

    return f"""
        <div class="section-card">
            <div class="section-head">
                <h5><i class="bi bi-grid-3x3"></i> Tarkvara versioonivõrdlus</h5>
                <div class="sub">{len(matrix)} unikaalset paketti üle {len(hosts)} masina</div>
            </div>
            <div class="matrix-controls">
                <div class="search-wrap">
                    <i class="bi bi-search"></i>
                    <input id="matrixSearch" type="text" class="form-control"
                           placeholder="Otsi tarkvara nime järgi…">
                </div>
                <div class="filter-pills" role="group">
                    <div class="form-check">
                        <input type="checkbox" id="filterOnlyDiff" checked>
                        <label for="filterOnlyDiff"><i class="bi bi-funnel-fill"></i>Ainult erinevused</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" id="filterHideEid" checked>
                        <label for="filterHideEid"><i class="bi bi-eye-slash"></i>Peida eID</label>
                    </div>
                </div>
                <div class="visible-count">
                    Nähtav <strong id="matrixVisibleCount">–</strong> / {len(matrix)}
                </div>
            </div>
            <div class="matrix-wrap">
                <table id="matrixTable" class="table matrix mb-0">
                    <thead>
                        <tr>
                            <th class="sw-name-col">Tarkvara · uusim versioon</th>
                            {header_cells}
                            <th>Hosti kate</th>
                        </tr>
                    </thead>
                    <tbody>{"".join(body_rows)}</tbody>
                </table>
            </div>
            <div class="matrix-legend">{legend}</div>
            <div class="matrix-hint">
                <i class="bi bi-lightbulb"></i> Vihje: kliki lahtril, et avada selle masina detailvaade.
            </div>
        </div>
    """


def render_modals(hosts, matrix, safe_ids):
    modals = []
    for host in hosts:
        m = host['metrics']
        safe = safe_ids[host['name']]
        admins_str = ", ".join(host['admins']) if host['admins'] else "Puudub info"

        sw_sorted = sorted(
            host['software'],
            key=lambda s: s['install_date'] or '00000000',
            reverse=True,
        )
        soft_html = ""
        for sw in sw_sorted:
            ver_badge = (
                f"<span class='chip chip-muted'>{h(sw['version'])}</span>"
                if sw['version'] and sw['version'] != '-' else ""
            )
            iso = install_date_iso(sw['install_date'])
            date_html = f"<span class='badge-install'>{iso}</span>" if iso else ""
            soft_html += f"<li>{h(sw['name'])} {ver_badge}{date_html}</li>"
        if not soft_html:
            soft_html = "<li class='text-muted'>Info puudub</li>"

        srv_html = ""
        for srv in host['services']:
            stat_color = "text-success" if srv['status'] == "OK" else "text-danger"
            srv_html += (
                f"<li>{h(srv['name'])} — "
                f"<strong class='{stat_color}'>{h(srv['status'])}</strong></li>"
            )
        if not srv_html:
            srv_html = "<li class='text-muted'>Info puudub</li>"

        # Lagging updates — single list, fleet-max comparison
        lagging = m['lagging']
        lag_html = ""
        if lagging:
            for entry in lagging:
                my_ver = entry['per_host'][host['name']]['version']
                latest = entry.get('latest_version', '?')
                lag_html += (
                    f"<li><strong>{h(entry['display_name'])}</strong><br>"
                    f"<span class='small'>siin <code>{h(my_ver)}</code>, fleet-uusim "
                    f"<code class='text-success'>{h(latest)}</code></span></li>"
                )
        else:
            lag_html = "<li class='text-muted'>Kõik paketid on ajakohased</li>"

        uniq_html = ""
        for entry in m['unique_sw']:
            info = entry['per_host'][host['name']]
            ver = info['version'] if info['version'] != '-' else ''
            ver_badge = f" <span class='chip chip-muted'>{h(ver)}</span>" if ver else ""
            uniq_html += f"<li>{h(entry['display_name'])}{ver_badge}</li>"
        if not uniq_html:
            uniq_html = "<li class='text-muted'>Pole unikaalset tarkvara</li>"

        health_cls = f"health-{m['health']}"
        health_label = {'green': 'Seis korras', 'yellow': 'Tasub üle vaadata',
                        'red': 'Vajab tähelepanu'}[m['health']]

        modals.append(f"""
            <div class="modal fade" id="modal-{safe}" tabindex="-1" aria-hidden="true">
              <div class="modal-dialog modal-xl modal-dialog-scrollable">
                <div class="modal-content">
                  <div class="modal-header text-white">
                    <h5 class="modal-title">
                        <span class="health-dot {health_cls}"></span>
                        {h(host['name'])} <span class="text-white-50">· {health_label}</span>
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                  </div>
                  <div class="modal-body">
                    <div class="modal-meta">
                        <div class="row g-3">
                            <div class="col-sm-6 col-md-3">
                                <div class="label">OS</div>
                                <div class="value">{h(host['os'])}</div>
                                <div class="small text-muted">{h(host['os_ver'])}</div>
                            </div>
                            <div class="col-sm-6 col-md-3">
                                <div class="label">Võrk</div>
                                <div class="value">{h(host['ip'])}</div>
                            </div>
                            <div class="col-sm-6 col-md-3">
                                <div class="label">Kasutaja</div>
                                <div class="value">{h(host['user'])}</div>
                            </div>
                            <div class="col-sm-6 col-md-3">
                                <div class="label">Viimane alglaadimine</div>
                                <div class="value">{h(host['boot'])}</div>
                            </div>
                        </div>
                    </div>
                    <div class="row g-3">
                       <div class="col-md-6">
                          <h6><i class="bi bi-arrow-down-circle"></i> Uuendustes maha jäänud</h6>
                          <ul class="list-unstyled small">{lag_html}</ul>
                          <h6 class="mt-3"><i class="bi bi-star"></i> Ainult sellel masinal</h6>
                          <ul class="list-unstyled small">{uniq_html}</ul>
                          <h6 class="mt-3"><i class="bi bi-people"></i> Lokaalsed administraatorid</h6>
                          <p class="small">{h(admins_str)}</p>
                       </div>
                       <div class="col-md-3">
                          <h6><i class="bi bi-gear"></i> Mittestandardsed teenused</h6>
                          <ul class="list-unstyled small">{srv_html}</ul>
                       </div>
                       <div class="col-md-3">
                          <h6><i class="bi bi-box-seam"></i> Paigaldatud tarkvara</h6>
                          <div class="small text-muted mb-1">Uusimad esimesena</div>
                          <ul class="list-unstyled small">{soft_html}</ul>
                       </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
        """)
    return "\n".join(modals)


# ---------------------------------------------------------------------------
# CVE / NVD integration
# ---------------------------------------------------------------------------

# Map from normalised software name prefix -> (CPE vendor, CPE product).
# Focused on widely-deployed desktop software that historically has CVEs.
# Everything not in this table is skipped — Windows Update components,
# vendor-specific engineering apps (ArcGIS, Bentley, Autodesk), and small
# utilities rarely have useful CPE matches and just add noise.
CVE_PRODUCT_MAP = [
    # (regex on display_name (case-insensitive), cpe_vendor, cpe_product)
    (r'^google chrome\b',                        'google',       'chrome'),
    (r'^mozilla firefox\b',                      'mozilla',      'firefox'),
    (r'^firefox\b',                              'mozilla',      'firefox'),
    (r'^microsoft edge\b',                       'microsoft',    'edge_chromium'),
    (r'^adobe acrobat(?! reader)',               'adobe',        'acrobat'),
    (r'^adobe acrobat reader\b',                 'adobe',        'acrobat_reader'),
    (r'^adobe reader\b',                         'adobe',        'acrobat_reader'),
    (r'^adobe air\b',                            'adobe',        'air'),
    (r'^foxit pdf reader\b',                     'foxit',        'pdf_reader'),
    (r'^foxit reader\b',                         'foxit',        'reader'),
    (r'^7-?zip\b',                               '7-zip',        '7-zip'),
    (r'^winrar\b',                               'rarlab',       'winrar'),
    (r'^notepad\+\+\b',                          'notepad-plus-plus', 'notepad\\+\\+'),
    (r'^putty\b',                                'putty',        'putty'),
    (r'^filezilla\b',                            'filezilla-project', 'filezilla'),
    (r'^winscp\b',                               'winscp',       'winscp'),
    (r'^openvpn\b',                              'openvpn',      'openvpn'),
    (r'^forticlient\b',                          'fortinet',     'forticlient'),
    (r'^vlc(\s+media\s+player)?\b',              'videolan',     'vlc_media_player'),
    (r'^zoom\b',                                 'zoom',         'meetings'),
    (r'^microsoft teams\b',                      'microsoft',    'teams'),
    (r'^slack\b',                                'slack',        'slack'),
    (r'^skype\b',                                'microsoft',    'skype'),
    (r'^git(\s+for\s+windows)?\b',               'git-scm',      'git'),
    (r'^node(\.js)?\b',                          'nodejs',       'node.js'),
    (r'^python\s+\d',                            'python',       'python'),
    (r'^wireshark\b',                            'wireshark',    'wireshark'),
    (r'^libreoffice\b',                          'libreoffice',  'libreoffice'),
    (r'^openoffice\b',                           'apache',       'openoffice'),
    (r'^dropbox\b',                              'dropbox',      'dropbox'),
    (r'^teamviewer\b',                           'teamviewer',   'teamviewer'),
    (r'^anydesk\b',                              'anydesk',      'anydesk'),
    (r'^vmware\s+(workstation|player)\b',        'vmware',       'workstation'),
    (r'^virtualbox\b',                           'oracle',       'vm_virtualbox'),
    (r'^docker\s+desktop\b',                     'docker',       'desktop'),
    (r'^digidoc4\s+client\b',                    'ria',          'digidoc4_client'),
    (r'^openjdk\b|^adoptopenjdk\b',              'oracle',       'jdk'),
    (r'^(oracle\s+)?java(\s+\d+)?\b',            'oracle',       'jre'),
]

# Cache on disk so subsequent runs don't re-query identical (product, version).
CVE_CACHE_FILE = os.path.join(UPLOAD_DIR, '.cve_cache.json')
CVE_CACHE_TTL_SEC = 24 * 3600
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_USER_AGENT = f'koondraport/{__version__}'


def _load_cve_cache():
    if not os.path.exists(CVE_CACHE_FILE):
        return {}
    try:
        with open(CVE_CACHE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def _save_cve_cache(cache):
    try:
        os.makedirs(os.path.dirname(CVE_CACHE_FILE) or '.', exist_ok=True)
        tmp = CVE_CACHE_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CVE_CACHE_FILE)
    except Exception as e:
        print(f"  [CVE cache save failed: {e}]", file=sys.stderr)


def _clean_version_for_cpe(version):
    """NVD wants semver-ish '1.2.3.4' style. Strip trailing whitespace
    and anything after first space (e.g. '11.0.8.10 LTS' -> '11.0.8.10')."""
    if not version or version == '-':
        return None
    v = str(version).strip().split()[0]
    # Keep only digits, dots, dashes — strip arch tags etc.
    v = re.sub(r'[^0-9A-Za-z.\-]', '', v)
    return v or None


def map_to_cpe(display_name, version):
    """Return (vendor, product, version) suitable for a CPE 2.3 string,
    or None if the software is not in our whitelist."""
    if not display_name:
        return None
    name_lc = display_name.lower()
    v = _clean_version_for_cpe(version)
    if not v:
        return None
    for pattern, vendor, product in CVE_PRODUCT_MAP:
        if re.search(pattern, name_lc):
            return (vendor, product, v)
    return None


def _nvd_request(params, api_key, attempt=1):
    qs = urllib.parse.urlencode(params)
    url = f'{NVD_API_URL}?{qs}'
    headers = {'User-Agent': NVD_USER_AGENT}
    if api_key:
        headers['apiKey'] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        # 403/429 => backoff and retry once
        if e.code in (403, 429, 503) and attempt <= 2:
            time.sleep(6)
            return _nvd_request(params, api_key, attempt + 1)
        raise


def _extract_cvss(cve):
    metrics = cve.get('metrics', {}) or {}
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        arr = metrics.get(key) or []
        if arr:
            d = arr[0].get('cvssData', {}) or {}
            score = d.get('baseScore')
            sev = d.get('baseSeverity') or arr[0].get('baseSeverity')
            vector = d.get('vectorString', '')
            return score, sev, vector, key
    return None, None, '', ''


def query_cves_for_cpe(vendor, product, version, api_key, cache):
    """Return list of CVE dicts for a given (vendor, product, version).
    Uses disk cache keyed on vendor:product:version."""
    cache_key = f'{vendor}:{product}:{version}'
    now = int(time.time())
    entry = cache.get(cache_key)
    if entry and entry.get('ts', 0) + CVE_CACHE_TTL_SEC > now:
        return entry.get('cves', [])

    cpe = f'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'
    params = {'virtualMatchString': cpe, 'resultsPerPage': 100}
    try:
        data = _nvd_request(params, api_key)
    except Exception as e:
        print(f"  [NVD query failed for {vendor} {product} {version}: {e}]", file=sys.stderr)
        return []

    cves = []
    for item in data.get('vulnerabilities', []) or []:
        c = item.get('cve', {}) or {}
        cid = c.get('id')
        if not cid:
            continue
        score, sev, vector, metric_ver = _extract_cvss(c)
        desc_en = next(
            (d.get('value', '') for d in c.get('descriptions', []) or []
             if d.get('lang') == 'en'),
            ''
        )
        cves.append({
            'id': cid,
            'score': score,
            'severity': (sev or '').lower(),
            'vector': vector,
            'metric': metric_ver,
            'description': desc_en.strip(),
            'url': f'https://nvd.nist.gov/vuln/detail/{cid}',
            'published': c.get('published', ''),
        })

    # Sort highest CVSS first
    cves.sort(key=lambda x: (x['score'] is None, -(x['score'] or 0.0)))
    cache[cache_key] = {'ts': now, 'cves': cves}
    return cves


def scan_fleet_for_cves(hosts, matrix, api_key):
    """Scan all host+software combinations against NVD.

    Returns:
        cve_findings: list of per-package dicts
            {name, vendor, product, version, cves: [...], hosts: [names]}
        host_cve_index: {host_name: [{package, version, cve, score, severity}]}
    """
    cache = _load_cve_cache()
    # (vendor, product, version) -> list of hosts running it
    triples = {}
    for entry in matrix:
        for host_name, info in entry['per_host'].items():
            mapping = map_to_cpe(entry['display_name'], info.get('version'))
            if not mapping:
                continue
            triples.setdefault(mapping, {
                'display_name': entry['display_name'],
                'hosts': [],
            })
            triples[mapping]['hosts'].append(host_name)

    if not triples:
        print("  [CVE scan: no packages matched whitelist]")
        return [], {}

    print(f"  [CVE scan: {len(triples)} unique package+version against NVD]")
    # Rate-limit: with key 50 req / 30s; without 5 req / 30s.
    # Sleep 0.7s between calls with key, 6.5s without.
    delay = 0.7 if api_key else 6.5

    cve_findings = []
    host_cve_index = {}
    for i, ((vendor, product, version), meta) in enumerate(sorted(triples.items())):
        if i > 0:
            time.sleep(delay)
        cves = query_cves_for_cpe(vendor, product, version, api_key, cache)
        if not cves:
            continue
        worst = cves[0]
        entry = {
            'display_name': meta['display_name'],
            'vendor': vendor,
            'product': product,
            'version': version,
            'hosts': sorted(set(meta['hosts'])),
            'cves': cves,
            'cve_count': len(cves),
            'worst_score': worst['score'],
            'worst_severity': worst['severity'],
            'worst_id': worst['id'],
        }
        cve_findings.append(entry)
        for host_name in entry['hosts']:
            host_cve_index.setdefault(host_name, []).append({
                'package': meta['display_name'],
                'version': version,
                'cve_count': len(cves),
                'worst_score': worst['score'],
                'worst_severity': worst['severity'],
                'worst_id': worst['id'],
            })

    _save_cve_cache(cache)

    # Sort packages by worst CVSS descending
    cve_findings.sort(key=lambda x: -(x['worst_score'] or 0.0))
    return cve_findings, host_cve_index


_CVE_SEVERITY_TO_FINDING = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'info',
    'none': 'info',
    '': 'info',
}


def build_vulnerable_software_finding(cve_findings, host_cve_index):
    """Collapse per-package findings into a single Turvaleiud entry."""
    if not cve_findings:
        return None
    # Finding severity = highest per-host severity we saw
    worst_sev_rank = 3  # info
    for entry in cve_findings:
        sev = _CVE_SEVERITY_TO_FINDING.get(entry['worst_severity'], 'info')
        rank = SEVERITY_ORDER.get(sev, 3)
        if rank < worst_sev_rank:
            worst_sev_rank = rank
    rank_to_sev = {v: k for k, v in SEVERITY_ORDER.items()}
    finding_sev = rank_to_sev[worst_sev_rank]

    hosts_list = []
    for host_name in sorted(host_cve_index.keys()):
        pkgs = host_cve_index[host_name]
        pkgs.sort(key=lambda p: -(p['worst_score'] or 0.0))
        top = pkgs[:3]
        detail_parts = [
            f"{p['package']} {p['version']} (CVSS {p['worst_score']}, {p['cve_count']} CVE)"
            for p in top
        ]
        if len(pkgs) > 3:
            detail_parts.append(f"+{len(pkgs)-3} veel")
        hosts_list.append({
            'name': host_name,
            'detail': ' | '.join(detail_parts),
        })

    total_cves = sum(e['cve_count'] for e in cve_findings)
    return {
        'key': 'vulnerable_software',
        'title': 'Teadaolevad haavatavused (CVE)',
        'severity': finding_sev,
        'icon': 'shield-exclamation',
        'hosts': hosts_list,
        'summary_count': total_cves,
        'summary_suffix': 'CVE-d',
    }


def render_vulnerability_section(cve_findings):
    """Dedicated section with a sortable table of vulnerable packages."""
    if not cve_findings:
        return ''

    rows = []
    for entry in cve_findings:
        hosts_html = ', '.join(h(hn) for hn in entry['hosts'])
        # Top-3 CVEs inline, rest collapsible
        top = entry['cves'][:3]
        rest = entry['cves'][3:]
        top_html = []
        for c in top:
            sc = f"{c['score']}" if c['score'] is not None else '—'
            sev = c['severity'].upper() if c['severity'] else ''
            sev_class = c['severity'] or 'none'
            top_html.append(
                f'<div class="cve-item">'
                f'<a href="{h(c["url"])}" target="_blank" rel="noopener" class="cve-id">{h(c["id"])}</a>'
                f'<span class="cve-score cve-sev-{h(sev_class)}">{h(sc)} {h(sev)}</span>'
                f'<span class="cve-desc">{h(c["description"][:160])}'
                + ('…' if len(c['description']) > 160 else '')
                + '</span></div>'
            )
        rest_html = ''
        if rest:
            rest_ids = ', '.join(
                f'<a href="{h(c["url"])}" target="_blank" rel="noopener">{h(c["id"])}</a>'
                for c in rest
            )
            rest_html = (
                f'<details class="cve-more"><summary>+{len(rest)} veel</summary>'
                f'<div class="cve-more-list">{rest_ids}</div></details>'
            )
        worst_sev = entry['worst_severity'] or 'none'
        worst_score = f"{entry['worst_score']}" if entry['worst_score'] is not None else '—'
        rows.append(
            f'<tr>'
            f'<td><span class="cve-sev-badge cve-sev-{h(worst_sev)}">{h(worst_score)}</span></td>'
            f'<td><strong>{h(entry["display_name"])}</strong><br>'
            f'<span class="cve-cpe">{h(entry["vendor"])}:{h(entry["product"])}</span></td>'
            f'<td class="mono">{h(entry["version"])}</td>'
            f'<td>{hosts_html}</td>'
            f'<td>{entry["cve_count"]}</td>'
            f'<td>{"".join(top_html)}{rest_html}</td>'
            f'</tr>'
        )

    total_pkgs = len(cve_findings)
    total_cves = sum(e['cve_count'] for e in cve_findings)
    hosts_affected = len(set(hn for e in cve_findings for hn in e['hosts']))

    return f"""
    <div class="section-card sec-vulns">
        <div class="section-head">
            <h5><i class="bi bi-shield-exclamation"></i> Teadaolevad haavatavused (NVD CVE)</h5>
            <div class="sub">{total_pkgs} haavatavat paketti · {total_cves} CVE · {hosts_affected} hosti</div>
        </div>
        <div class="table-responsive">
            <table class="table cve-table">
                <thead>
                    <tr>
                        <th>Max CVSS</th>
                        <th>Tarkvara</th>
                        <th>Versioon</th>
                        <th>Hostid</th>
                        <th>CVE-d</th>
                        <th>Näited (top 3)</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not os.path.exists(UPLOAD_DIR):
        print(f"Viga: Kausta '{UPLOAD_DIR}' ei leitud.")
        return

    hosts = load_hosts(UPLOAD_DIR)
    if not hosts:
        print("Ei leitud ühtegi JSON-faili kaustast 'uploads/'.")
        return

    matrix = build_software_matrix(hosts)
    for host in hosts:
        compute_host_metrics(host, matrix)

    safe_ids = {host['name']: safe_id(host['name']) for host in hosts}
    findings = compute_security_findings(hosts, matrix)

    # --- CVE / NVD scan ---
    api_key = os.environ.get('NVD_API_KEY', '').strip() or None
    if api_key:
        print("  [NVD API key detected — using authenticated rate-limit]")
    else:
        print("  [No NVD_API_KEY env var — using public (slower) rate-limit]")
    cve_findings, host_cve_index = scan_fleet_for_cves(hosts, matrix, api_key)
    vuln_finding = build_vulnerable_software_finding(cve_findings, host_cve_index)
    if vuln_finding:
        findings.append(vuln_finding)
        findings.sort(key=lambda f: (SEVERITY_ORDER[f['severity']], f['key']))

    drift_count = sum(1 for e in matrix if e['status'] == 'drift')
    unique_count = sum(1 for e in matrix if e['status'] == 'unique')

    html_out = (
        HTML_HEAD
        + render_hero(hosts, matrix)
        + render_security_findings(findings, hosts, matrix)
        + render_vulnerability_section(cve_findings)
        + render_host_table(hosts, safe_ids)
        + render_matrix(matrix, hosts, safe_ids)
        + render_modals(hosts, matrix, safe_ids)
        + HTML_FOOTER_TAIL
    )

    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    output_file = os.path.join(UPLOAD_DIR, f'{OUTPUT_PREFIX}_{timestamp}.html')

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_out)

    print(f"Edukalt valmis! Loodi fail: {output_file} (koondraport v{__version__})")
    print(f"  Masinaid:                 {len(hosts)}")
    print(f"  Tarkvara kokku:           {len(matrix)}")
    print(f"  Vananenud paketid:        {drift_count}")
    print(f"  Unikaalsed paigaldused:   {unique_count}")
    if cve_findings:
        total_cves = sum(e['cve_count'] for e in cve_findings)
        print(f"  Haavatavaid pakette:      {len(cve_findings)} ({total_cves} CVE)")


if __name__ == '__main__':
    main()
