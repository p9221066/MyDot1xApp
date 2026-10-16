# Mist MSP WLAN Exporter

Exports every WLAN, with its security settings, from all Orgs managed under a
Juniper Mist MSP to a single CSV file.

The script logs on to the Mist cloud with your user credentials, asks which MSP
to export, walks every Org under it (org-level, template and site-level WLANs),
and writes one row per WLAN. Orgs with no WLANs still get a row, so every
managed Org shows up in the output.

## Requirements

- Python 3.10+
- A Mist account with access to the MSP

```
pip install -r requirements.txt
```

## Credentials

Credentials are read, in order of precedence, from:

1. `--user` / `--host` command-line arguments
2. a `.env` file (copy `.env.example` to `.env` and fill it in)
3. an interactive prompt (the password is not echoed; a 2FA code is asked for if enabled)

Never commit your real `.env`. It is listed in `.gitignore`.

## Usage

```
python mist_wlan_export.py
```

| Option | Description |
| --- | --- |
| `--host` | Mist API host, e.g. `api.mist.com`, `api.eu.mist.com`, `api.gc1.mist.com` (default: `MIST_HOST` or `api.mist.com`) |
| `--user` | Mist login email (default: `MIST_USER` or prompt) |
| `--env-file` | env file to read (default: `.env`) |
| `--msp` | MSP name or id to export, skipping the selection prompt |
| `-o`, `--output` | output CSV file (default: `mist_wlans_<timestamp>.csv`) |
| `--no-site-wlans` | skip site-level WLANs (faster: one fewer API call per site) |
| `--show-psk` | write PSK passphrases in clear text (masked by default) |

## Output

The CSV is UTF-8 with a BOM so it opens cleanly in Excel. Columns include MSP,
Org and site names, scope (org / template / site), SSID, auth type, encryption,
PSK (masked unless `--show-psk`), MAC auth, RADIUS auth/accounting servers,
RadSec, fast roaming, PMF, client isolation, captive portal, VLAN settings,
bands and apply-to scope.

If an Org can't be read, the script skips it, keeps going, and lists the
failed Orgs at the end.

> The export contains customer network details. Treat the CSV as sensitive.
> `*.csv` is listed in `.gitignore` so exports are not committed by accident.
