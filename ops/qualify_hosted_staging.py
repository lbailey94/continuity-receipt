#!/usr/bin/env python3
"""Exercise a disposable loopback API; never import production state or keys.

Run with the intended wheel on PYTHONPATH. This is an HTTP protocol matrix,
not authentication, payment, tenant isolation or independent adoption proof.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--vectors', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--url', help='Optional already-running loopback staging API')
    parser.add_argument('--state', type=Path, help='State directory of the external staging API')
    parser.add_argument('--skip-state-check', action='store_true', help='Explicitly omit empty-state assertion for an existing production instance')
    args = parser.parse_args()
    import continuity_receipt
    assert continuity_receipt.__version__ == args.version
    checks = []
    with tempfile.TemporaryDirectory(prefix='cr-api-staging-state-') as state:
        os.environ['WM_RECEIPT_API_STATE'] = state
        spec = importlib.util.spec_from_file_location('staged_receipt_api', args.source)
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        server = api.ThreadingHTTPServer(('127.0.0.1', 0), api.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = args.url or f'http://127.0.0.1:{server.server_address[1]}'
        if args.url:
            assert args.url.startswith('http://127.0.0.1:') and (args.state is not None or args.skip_state_check)
        def post(raw, path='/verify'):
            req = urllib.request.Request(base + path, data=raw, headers={'Content-Type':'application/json'})
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as error:
                return error.code, json.loads(error.read())
        try:
            for manifest in ['manifest.json', 'manifest-0.5.json', 'manifest-0.6.json']:
                entries = json.loads((args.vectors / manifest).read_bytes())['vectors']
                for entry in entries:
                    path = '/verify?require_anchor=1' if entry.get('require_anchor') else '/verify'
                    status, result = post((args.vectors / entry['file']).read_bytes(), path)
                    assert status == 200, (entry['file'], status, result)
                    assert result['verdict'] == entry['expected_verdict'], (entry['file'], result)
                    code = entry.get('expected_code')
                    if code:
                        assert code in [e['code'] for e in result['errors']], (entry['file'], code, result)
                    checks.append(entry['file'])
            valid = (args.vectors / '17_agreement_bound.json').read_bytes()
            for name, raw in [
                ('duplicate', b'{"receipts":[],"receipts":[]}'),
                ('escaped-duplicate', b'{"spec":1,"\\u0073pec":2}'),
                ('bom', b'\xef\xbb\xbf'+valid),
                ('utf16', valid.decode().encode('utf-16')),
                ('bad-utf8', b'{"a":"\xff"}'),
                ('nan', b'{"a":NaN}'),
                ('infinity', b'{"a":Infinity}'),
                ('parser-depth', b'['*1800+b'0'+b']'*1800),
            ]:
                status, result = post(raw)
                assert status == 400, (name, status, result)
                checks.append(name)
            for name, value in [('array-root', []), ('core-depth', {'spec':'continuity-receipt/0.4','receipts':[]})]:
                if name == 'core-depth':
                    nested = 0
                    for _ in range(70): nested = {'x':nested}
                    value['extra'] = nested
                status, result = post(json.dumps(value).encode())
                assert status in (200,400) and (status == 400 or result['verdict']=='UNTRUSTED'), (name,status,result)
                if name == 'core-depth': assert 'nesting_too_deep' in [e['code'] for e in result['errors']]
                checks.append(name)
            from urllib.parse import urlparse
            with socket.create_connection(('127.0.0.1', urlparse(base).port), timeout=10) as conn:
                conn.sendall(f'POST /verify HTTP/1.1\r\nHost: localhost\r\nContent-Length: {api.MAX_BODY+1}\r\nConnection: close\r\n\r\n'.encode())
                assert b' 413 ' in conn.recv(4096)
                checks.append('oversize-header')
            if not args.skip_state_check:
                assert not list((args.state or Path(state)).rglob('*')), 'stateless verification wrote state'
                checks.append('no-state-writes')
            print(json.dumps({'version':continuity_receipt.__version__,'source_sha256':hashlib.sha256(args.source.read_bytes()).hexdigest(),'checks_passed':len(checks),'checks':checks},sort_keys=True))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)


if __name__ == '__main__':
    main()
