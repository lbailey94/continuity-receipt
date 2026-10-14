#!/usr/bin/env bash
# Run as root on the VPS against a reviewed upload directory. No broad provision.
set -euo pipefail
payload=${1:?reviewed upload directory required}
baseline=f3daa358f055ae1ac4667629c2a73ecd6df694684ad778c0a2a8410ccd72c134
candidate=10f36afc7afa3571d44bd355ba82af77787a543f6d7cd50294bdbd1afc5d19b0
wheel_hash=9b0be02327759b3f95519967f4257ce37a3ee44468359a88f84480d28c5935ee
[[ $(id -u) == 0 ]]
[[ $(sha256sum /opt/whitemagic-api/receipt-api.py | cut -d' ' -f1) == "$baseline" ]]
[[ $(sha256sum "$payload/receipt-api.py" | cut -d' ' -f1) == "$candidate" ]]
[[ $(sha256sum "$payload/continuity_receipt-0.5.0-py3-none-any.whl" | cut -d' ' -f1) == "$wheel_hash" ]]
install -d -m 700 /root/continuity-rollouts
backup=$(mktemp -d /root/continuity-rollouts/20260930.XXXXXXXX)
cp -a /opt/whitemagic-api/receipt-api.py "$backup/receipt-api.py"
cp -a /etc/systemd/system/receipt-api.service "$backup/receipt-api.service"
cp -a /opt/whitemagic-api/venv "$backup/venv"
systemctl stop receipt-api.service
rollback() {
  trap - ERR
  systemctl stop receipt-api.service || true
  cp -a "$backup/receipt-api.py" /opt/whitemagic-api/receipt-api.py
  cp -a "$backup/receipt-api.service" /etc/systemd/system/receipt-api.service
  mv /opt/whitemagic-api/venv "$backup/failed-candidate-venv"
  cp -a "$backup/venv" /opt/whitemagic-api/venv
  systemctl daemon-reload
  systemctl start receipt-api.service
  echo "ROLLED_BACK backup=$backup" >&2
}
trap rollback ERR
# Storage snapshot stays protected; rollback of this code-only delta preserves
# current live state rather than discarding concurrent gateway usage/key changes.
cp -a /var/lib/whitemagic-hosted-api "$backup/state"
/opt/whitemagic-api/venv/bin/python -m pip install --no-index --no-deps "$payload/continuity_receipt-0.5.0-py3-none-any.whl"
/opt/whitemagic-api/venv/bin/python - "$payload/expected-modules.json" <<'PY'
import hashlib,json,pathlib,sys,continuity_receipt
assert continuity_receipt.__version__ == '0.5.0'
root=pathlib.Path(continuity_receipt.__file__).parent
expected=json.loads(pathlib.Path(sys.argv[1]).read_bytes())
actual={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in root.glob('*.py')}
assert actual == expected, 'installed Python module hashes differ from reviewed wheel'
print('Published 0.5.0 module hashes verified')
PY
install -o whitemagic -g whitemagic -m 644 "$payload/receipt-api.py" /opt/whitemagic-api/receipt-api.py
install -o root -g root -m 644 "$payload/receipt-api.service" /etc/systemd/system/receipt-api.service
systemctl daemon-reload
systemctl start receipt-api.service
/opt/whitemagic-api/venv/bin/python - <<'PY'
import json,time,urllib.request
for attempt in range(50):
    try:
        result=json.load(urllib.request.urlopen('http://127.0.0.1:18791/info',timeout=2))
        assert result['verifier_version']=='0.5.0', result.get('verifier_version')
        break
    except OSError:
        time.sleep(.1)
else:
    raise RuntimeError('API did not become ready')
print('API readiness and version verified')
PY
if [[ -f "$backup/state/verify_signing.key" ]]; then
  cmp -s "$backup/state/verify_signing.key" /var/lib/whitemagic-hosted-api/verify_signing.key
fi
systemctl is-active --quiet receipt-api.service
trap - ERR
echo "DEPLOYED backup=$backup source=$candidate"
