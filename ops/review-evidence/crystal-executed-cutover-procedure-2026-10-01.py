import pathlib, subprocess, hashlib, json, os, pwd, base64, secrets, tarfile, time, shutil, importlib.util, sys
here=pathlib.Path(__file__).parent
release=here.parent
state=pathlib.Path('/var/lib/whitemagic-hosted-api')
plan_path=pathlib.Path('/root/continuity-rollouts/crystal-review-qjI5Ho5P/legacy-dry-run.json')
def digest(p): return hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
def run(*args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
baselines={
 '/etc/whitemagic-hosted/authd.py':'cba03d0f26abdbf90e1d24df3a469bfc1ec14d9bae56b480f73dba982e2a458d',
 '/opt/whitemagic-api/receipt-api.py':'10f36afc7afa3571d44bd355ba82af77787a543f6d7cd50294bdbd1afc5d19b0',
 '/etc/caddy/Caddyfile':'c7a8401a5fdae11722daadd413b35e0e01a4533b921874a5c9b7c889bb20872b',
 '/etc/systemd/system/receipt-api.service':'c54cc984cd42f0682a6ab70e8153491b208b368a9dda96b0142dcb5e86f2c735',
 '/etc/systemd/system/whitemagic-api-gateway.service':'b3498f5fcf0d9be5bbfc479add2b66fc764111681582c5972768a5a8cac5d67d'}
assert not (release/'consistent-backup.tar').exists(), 'already executed; manual review required'
for p,h in baselines.items(): assert digest(pathlib.Path(p))==h, 'baseline drift'
assert digest(plan_path)=='de5f53492f552672db0c3225c305ff67c8fcd4e610a681c12ca6c72e9ab5081c'
plan=json.loads(plan_path.read_text())
assert len(plan['entries'])==1
entry=plan['entries'][0]
expected='f638468a80c55d2c68054b0576a497c2d90b9ad9d216c0e313aabd3752a822ae'
assert entry['source_sha256']==expected
pins={'authd.py':'26c683a99d1e7df8c8ac13c0e6f1e048a93063a5369f19db194951cd0530bad0','receipt-api.py':'aeb3f3e4834db13e497ada7f04c26fe11df977ec02da6041c02e2233551ac173','crystal_client.py':'ff73110168f2ef197190ff5b57d0ad1f08b860438f738112a4e97964515a503d'}
for name,h in pins.items(): assert digest(here/'src'/name)==h
assert digest(here/'quarantine_legacy.py')=='27dc3a5d3d6a2685b1c4f4c3da3258a05a76426c8cd8e7cccad49264d2529df2'
user=pwd.getpwnam('whitemagic')
run('caddy','validate','--config',str(here/'Caddyfile'),'--adapter','caddyfile')
run('systemctl','stop','whitemagic-api-gateway','receipt-api','whitemagic-keyd')
try:
    source=pathlib.Path(plan['source_root'])/entry['source']
    assert digest(source)==expected, 'envelope drift; abort'
    registry_hash=digest(state/'keys.json')
    # Stopped writers ensure the complete SQLite/state snapshot is consistent.
    with tarfile.open(release/'consistent-backup.tar','w',format=tarfile.PAX_FORMAT) as archive:
        archive.add(state,arcname=str(state).lstrip('/'))
        for p in baselines: archive.add(p,arcname=p.lstrip('/'))
    os.chmod(release/'consistent-backup.tar',0o600)
    with tarfile.open(release/'consistent-backup.tar') as archive:
        assert hashlib.sha256(archive.extractfile(str(source).lstrip('/')).read()).hexdigest()==expected
    os.chmod(state,0o700)
    keyring=state/'crystal_assertion.keys.json'
    assert not keyring.exists(), 'unexpected keyring; abort rather than overwrite'
    keys={'new-20261001':base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')}
    legacy=state/'crystal_assertion.secret'
    if legacy.exists():
        secret=legacy.read_bytes(); assert len(secret)>=32
        keys['legacy']=base64.urlsafe_b64encode(secret).decode().rstrip('=')
    fd=os.open(keyring,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump({'active_kid':'new-20261001','keys':keys},f); f.flush(); os.fsync(f.fileno())
    os.chown(keyring,user.pw_uid,user.pw_gid)
    spec=importlib.util.spec_from_file_location('quarantine_api',here/'src/receipt-api.py')
    api=importlib.util.module_from_spec(spec);sys.modules[spec.name]=api;spec.loader.exec_module(api)
    result=api.apply_legacy_crystal_quarantine_plan(plan)
    (release/'quarantine-applied.json').write_text(json.dumps(result,indent=2)+'\n')
    os.chmod(release/'quarantine-applied.json',0o600)
    quarantined=pathlib.Path(plan['quarantine_root'])/entry['source']
    assert digest(quarantined)==expected and not source.exists()
    assert pathlib.Path(plan['quarantine_root']).stat().st_uid==0
    assert subprocess.run(['runuser','-u','whitemagic','--','test','-r',str(quarantined)],stdout=subprocess.DEVNULL).returncode!=0
    for src,dst in [('src/authd.py','/etc/whitemagic-hosted/authd.py'),('src/receipt-api.py','/opt/whitemagic-api/receipt-api.py'),('whitemagic-api-gateway.service','/etc/systemd/system/whitemagic-api-gateway.service'),('Caddyfile','/etc/caddy/Caddyfile')]:
        run('install','-o','root','-g','root','-m','644',str(here/src),dst)
    run('install','-o','root','-g','root','-m','644',str(here/'whitemagic-hosted-api.tmpfiles.conf'),'/etc/tmpfiles.d/whitemagic-hosted-api.conf')
    run('systemctl','daemon-reload')
    run('systemctl','start','receipt-api');run('systemctl','start','whitemagic-api-gateway');run('systemctl','start','whitemagic-keyd')
    run('systemctl','reload','caddy')
    time.sleep(2)
    run('systemctl','is-active','receipt-api','whitemagic-api-gateway','whitemagic-keyd','caddy')
    assert digest(state/'keys.json')==registry_hash, 'unexpected registry modification'
    summary={'status':'cutover-services-active','backup':str(release/'consistent-backup.tar'),'backup_sha256':digest(release/'consistent-backup.tar'),'quarantined_envelopes':1,'envelope_sha256':expected,'plaintext_inspected':False,'registry_unchanged':True,'service_account_quarantine_read_denied':True,'source_sha256':pins}
    (release/'cutover-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary))
except BaseException:
    # Keep both public Crystal routes closed if any cutover step fails.
    shutil.copy2(here/'Caddyfile',here/'deny-Caddyfile')
    text=(here/'deny-Caddyfile').read_text()
    for route in ('/crystals','/crystals/*'):
        old='handle '+route+' {\n\t\treverse_proxy 127.0.0.1:18792\n\t}'
        assert old in text
        text=text.replace(old,'handle '+route+' {\n\t\trespond 503\n\t}')
    (here/'deny-Caddyfile').write_text(text)
    run('caddy','validate','--config',str(here/'deny-Caddyfile'),'--adapter','caddyfile')
    run('install','-o','root','-g','root','-m','644',str(here/'deny-Caddyfile'),'/etc/caddy/Caddyfile')
    run('systemctl','reload','caddy')
    run('systemctl','start','whitemagic-keyd')
    raise
