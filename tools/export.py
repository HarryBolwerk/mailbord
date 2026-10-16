#!/usr/bin/env python3
"""Export the Mailbord into encrypted files for the offline app.

Usage:
  python3 -I tools/export.py --dump DUMP_DIR --assets ASSET_DIR --key KEY_FILE [--repo REPO_DIR]

DUMP_DIR   folder with cards/*.json and mails/*.json as written by ArtifactData (out_dir),
           each file {"id":..., "data": {...}} or the bare document body.
ASSET_DIR  folder with attachment files named by their asset id (any extension).
KEY_FILE   file with the 32-byte data key, base64 encoded (from the board's secret/offlinekey doc).
REPO_DIR   repo root (default: parent of this script's folder).

Writes (all encrypted with AES-256-GCM, format: 12-byte IV || ciphertext+tag):
  data/index.bin          cards + mail metadata (gist, subject, from, date, attachment list)
  data/m/<hash>.bin       one mail body each, named by content hash (immutable)
  data/a/<hash>.bin       one attachment each, named by content hash (immutable)
  data/keys.json          the data key wrapped (RSA-OAEP-256) for every device in tools/devices.json
Removes data/m and data/a files that are no longer referenced.
"""
import argparse, base64, hashlib, hmac, json, os, sys, time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_docs(folder):
    out = {}
    if not folder.is_dir():
        return out
    for f in sorted(folder.glob('*.json')):
        raw = json.loads(f.read_text())
        doc_id = raw.get('id', f.stem) if isinstance(raw, dict) else f.stem
        body = raw.get('data', raw) if isinstance(raw, dict) and 'data' in raw else raw
        out[doc_id] = body
    return out


def enc(key, plain: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + AESGCM(key).encrypt(iv, plain, None)


def write_if_new(path: Path, key, plain: bytes):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(enc(key, plain))


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:24]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dump', required=True)
    ap.add_argument('--assets', required=True)
    ap.add_argument('--key', required=True)
    ap.add_argument('--repo', default=str(Path(__file__).resolve().parent.parent))
    a = ap.parse_args()

    repo = Path(a.repo)
    key = base64.b64decode(Path(a.key).read_text().strip())
    assert len(key) == 32, 'data key must be 32 bytes'
    dump, assets = Path(a.dump), Path(a.assets)
    data = repo / 'data'
    (data / 'm').mkdir(parents=True, exist_ok=True)
    (data / 'a').mkdir(parents=True, exist_ok=True)

    cards = load_docs(dump / 'cards')
    mails = load_docs(dump / 'mails')
    asset_files = {p.stem: p for p in assets.iterdir() if p.is_file()} if assets.is_dir() else {}

    used_m, used_a, missing = set(), set(), []
    out_cards = []
    for cid, c in cards.items():
        if not isinstance(c, dict):
            continue
        out_mails = []
        for m in c.get('mails') or []:
            mid = m.get('id')
            full = mails.get(mid) or {}
            entry = {k: m.get(k) for k in ('id', 'gist', 'subject', 'from', 'date') if m.get(k) is not None}
            if full.get('to'):
                entry['to'] = full['to']
            if full.get('from'):
                entry['fromFull'] = full['from']
            body = (full.get('body') or '').encode('utf-8')
            if body:
                name = h(body)
                write_if_new(data / 'm' / f'{name}.bin', key, body)
                used_m.add(name)
                entry['body'] = name
            atts = []
            for att in full.get('attachments') or []:
                aid = att.get('assetId') or (att.get('url') or '').rsplit('/', 1)[-1]
                src = asset_files.get(aid)
                if not src:
                    missing.append(f"{mid}:{att.get('name')}")
                    continue
                blob = src.read_bytes()
                name = h(blob)
                write_if_new(data / 'a' / f'{name}.bin', key, blob)
                used_a.add(name)
                atts.append({'name': att.get('name') or src.name, 'type': att.get('type') or '', 'file': name, 'size': len(blob)})
            if atts:
                entry['attachments'] = atts
            out_mails.append(entry)
        card = {k: c.get(k) for k in ('title', 'summary', 'status', 'ref', 'done', 'updated', 'tags') if c.get(k) is not None}
        card['id'] = cid
        card['mails'] = out_mails
        out_cards.append(card)

    # only rewrite the index when its content changed (keeps git history small)
    content = json.dumps(out_cards, ensure_ascii=False, sort_keys=True).encode('utf-8')
    tag = hmac.new(key, content, hashlib.sha256).hexdigest()[:32]
    tag_file = data / 'index.tag'
    index_changed = not (tag_file.exists() and tag_file.read_text().strip() == tag and (data / 'index.bin').exists())
    if index_changed:
        index = {'generated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'cards': out_cards}
        (data / 'index.bin').write_bytes(enc(key, json.dumps(index, ensure_ascii=False).encode('utf-8')))
        tag_file.write_text(tag + '\n')

    for sub, used in (('m', used_m), ('a', used_a)):
        for f in (data / sub).glob('*.bin'):
            if f.stem not in used:
                f.unlink()

    devices_file = repo / 'tools' / 'devices.json'
    devices = json.loads(devices_file.read_text()) if devices_file.exists() else []
    keys_file = data / 'keys.json'
    old = {}
    if keys_file.exists():
        try:
            old = {d['id']: d for d in json.loads(keys_file.read_text()).get('devices', [])}
        except Exception:
            old = {}
    key_id = hmac.new(key, b'key-id', hashlib.sha256).hexdigest()[:16]
    wrapped = []
    for d in devices:
        prev = old.get(d['id'])
        if prev and prev.get('keyId') == key_id:
            wrapped.append(prev)
            continue
        pub = serialization.load_der_public_key(base64.b64decode(d['publicKey']))
        ct = pub.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        wrapped.append({'id': d['id'], 'name': d.get('name', ''), 'keyId': key_id, 'wrapped': base64.b64encode(ct).decode()})
    new_keys = json.dumps({'devices': wrapped}, indent=1) + '\n'
    if not keys_file.exists() or keys_file.read_text() != new_keys:
        keys_file.write_text(new_keys)

    print(json.dumps({'index_changed': index_changed, 'cards': len(out_cards), 'mails': sum(len(c['mails']) for c in out_cards),
                      'bodies': len(used_m), 'attachments': len(used_a), 'devices': len(wrapped),
                      'missing_attachments': missing}))


if __name__ == '__main__':
    main()
