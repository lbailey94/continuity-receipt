#!/usr/bin/env python3
"""Bounded authenticated public /verify smoke using a temporary evaluation key.

Run as the gateway state owner. Does not print any credential, buy anything,
request receipt/cache persistence, or rewrite other key entries. Gateway
usage/audit records are normal retained operational effects of these calls.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import tempfile
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-store', type=Path, required=True)
    parser.add_argument('--vectors', type=Path, required=True)
    parser.add_argument('--url', default='https://api.whitemagic.dev/verify')
    args = parser.parse_args()
    assert args.url == 'https://api.whitemagic.dev/verify', 'qualification destination is fixed'
    token = 'wm_' + secrets.token_hex(24)
    label = 'qualification-' + secrets.token_hex(8)
    store = args.key_store
    assert store.name == 'keys.json' and store.is_file()
    def update(add):
        with (store.parent / 'keys.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            document = json.loads(store.read_bytes())
            if add:
                document['keys'].append({'token':token, 'name':label, 'daily_cap':32, 'plan':'operator-qualification'})
            else:
                document['keys'] = [k for k in document['keys'] if k.get('token') != token]
            with tempfile.NamedTemporaryFile(dir=store.parent, prefix='qualification-keys-', delete=False) as output:
                temporary = Path(output.name)
                try:
                    output.write((json.dumps(document,indent=2)+'\n').encode())
                    output.flush()
                    os.fsync(output.fileno())
                    os.chmod(temporary, 0o600)
                    os.replace(temporary,store)
                finally:
                    temporary.unlink(missing_ok=True)
    def post(raw, credential=token):
        headers = {'Content-Type':'application/json','User-Agent':'continuity-receipt-operator-qualification/1'}
        if credential is not None: headers['Authorization'] = 'Bearer '+credential
        req = urllib.request.Request(args.url, data=raw, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())
    results = []
    update(True)
    try:
        for filename in ['17_agreement_bound.json','23_agreement_binding_carried.json','24_authority_grant.json']:
            raw = (args.vectors/filename).read_bytes()
            status,result = post(raw)
            assert status == 200 and result.get('verdict') == 'TRUSTED', (filename,status,result.get('verdict'))
            results.append({'case':filename,'http':status,'verdict':result['verdict']})
        valid = (args.vectors/'17_agreement_bound.json').read_bytes()
        nested = 0
        for _ in range(70): nested = {'x':nested}
        for name,raw in [
            ('duplicate',b'{"receipts":[],"receipts":[]}'),
            ('escaped-duplicate',b'{"spec":1,"\\u0073pec":2}'),
            ('bom',b'\xef\xbb\xbf'+valid),
            ('utf16',valid.decode().encode('utf-16')),
            ('bad-utf8',b'{"a":"\xff"}'),
            ('parser-depth',b'['*1800+b'0'+b']'*1800),
            ('core-depth',json.dumps({'spec':'continuity-receipt/0.4','receipts':[],'extra':nested}).encode()),
            ('oversize',b' '*(1048576+1)),
        ]:
            status,result = post(raw)
            assert status in (400,413) or (status==200 and result.get('verdict')=='UNTRUSTED'), (name,status)
            results.append({'case':name,'http':status,'verdict':result.get('verdict')})
        for name,credential,expected in [('no-auth',None,402),('invalid-auth','invalid-qualification-key',401)]:
            status,result = post(valid,credential)
            assert status == expected, (name,status)
            results.append({'case':name,'http':status})
    finally:
        update(False)
    assert not any(k.get('token')==token for k in json.loads(store.read_bytes())['keys'])
    print(json.dumps({'checks_passed':len(results),'results':results,'temporary_key_removed':True,'payment_attempted':False},sort_keys=True))


if __name__ == '__main__':
    main()
