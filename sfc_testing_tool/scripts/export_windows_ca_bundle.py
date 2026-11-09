r"""Create config/ca_bundle.pem from the Windows certificate store.

Run once:
    set PYTHONPATH=src            (cmd)     |  $env:PYTHONPATH = "src"   (PowerShell)
    python scripts/export_windows_ca_bundle.py
Then set  "verify_tls": "config/ca_bundle.pem"  in config/settings.json.
The bundle contains only PUBLIC certificates (no private keys).
"""
import os

from sfc_tool.infrastructure.tls import export_windows_ca_bundle

if __name__ == "__main__":
    os.makedirs("config", exist_ok=True)
    out = os.path.join("config", "ca_bundle.pem")
    print("Wrote %d certificates to %s" % (export_windows_ca_bundle(out), out))
