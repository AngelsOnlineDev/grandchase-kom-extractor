"""Grand Chase .kom extractor — Algorithm 0 + Algorithm 2.

Unpacks files from "KOG GC TEAM MASSFILE V.1.0" archives.

    Algo 0  (plain zlib)        — fully supported
    Algo 2  (Blowfish + zlib)   — fully supported (SHA-256-derived key)
    Algo 3  (Blowfish, post-inflate, with extra pre-inflate transform) — NOT YET

Requires: Python 3.10+ and pycryptodome (`pip install pycryptodome`).

USAGE
    # single archive
    python extract_kom.py "Texture/ui5.kom"

    # whole install tree
    python extract_kom.py --all "C:/Program Files (x86)/Steam/steamapps/common/GrandChase" --out ./extracted

ALGO 2 DETAILS
    seed_idx = map[permute(MappedID, file_size)]            # from komdatalist.xml
    sum      = sum(SEED_TABLE[seed_idx]) mod 2**64          # 5 qwords per row
    key      = SHA256(str(sum).encode()).digest()           # 32 bytes
    plaintext = zlib.inflate(Blowfish_ECB.decrypt(compressed, key))

    We don't have komdatalist.xml, so the seed index is brute-forced per unique
    (MappedID, file_size). First hit for a new combination takes ~100ms; cached
    for every subsequent file in the session.

OUTPUT LAYOUT
    extracted/
      <archive_stem>/
        _index.xml        - the decrypted file index
        _skipped.txt      - algo-3 entries (not decrypted)
        <files...>        - algo-0 and algo-2 entries
"""
import argparse, struct, zlib, re, hashlib, sys, time
from pathlib import Path
from Crypto.Cipher import Blowfish

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from gc_keytable import MAPPED_HEADER_KEYS as XML_KEYS
from gc_bf_seeds import SEED_TABLE

HEADER_SIZE = 0x4C
FILE_RE = re.compile(
    rb'<File\s+Name="([^"]*)"\s+Size="(\d+)"\s+CompressedSize="(\d+)"\s+'
    rb'Checksum="([^"]*)"\s+FileTime="([^"]*)"\s+Algorithm="(\d+)"'
    rb'(?:\s+MappedID="([^"]*)")?\s*/>'
)

_seed_cache: dict[tuple[str, int], int] = {}


def xml_decrypt(enc: bytes, seed: int) -> bytes:
    """XOR-decrypt the KOM XML index using three rotating keys seeded by xml_size."""
    start = (12 * (seed % 200) + 12) // 4
    keys3 = [XML_KEYS[start + i] for i in range(3)]
    out = bytearray(len(enc))
    kidx = 0
    full = len(enc) - (len(enc) % 4)
    for i in range(0, full, 4):
        dw = struct.unpack_from("<I", enc, i)[0]
        struct.pack_into("<I", out, i, dw ^ keys3[kidx])
        kidx = (kidx + 1) % 3
    if full < len(enc):
        out[full:] = enc[full:]
    return bytes(out)


def parse_index(xml: bytes) -> list[dict]:
    entries = []
    for m in FILE_RE.finditer(xml):
        entries.append({
            "name":       m.group(1).decode("utf-8", "replace"),
            "size":       int(m.group(2)),
            "compressed": int(m.group(3)),
            "checksum":   m.group(4).decode("utf-8", "replace"),
            "filetime":   m.group(5).decode("utf-8", "replace"),
            "algorithm":  int(m.group(6)),
            "mapped_id":  (m.group(7) or b"").decode("utf-8", "replace"),
        })
    return entries


def _try_algo2_seed(enc: bytes, expected_size: int, seed_idx: int) -> bytes | None:
    """Blowfish-ECB decrypt with key=SHA256(str(sum_of_5_qwords)) then zlib-inflate."""
    s = SEED_TABLE[seed_idx]
    if s == 0:
        return None
    key = hashlib.sha256(str(s).encode("ascii")).digest()
    bf = Blowfish.new(key, Blowfish.MODE_ECB)
    aligned = len(enc) - (len(enc) % 8)
    if aligned == 0:
        return None
    dec = bf.decrypt(enc[:aligned]) + enc[aligned:]
    for wbits in (15, -15):
        try:
            out = zlib.decompress(dec, wbits)
            if len(out) == expected_size:
                return out
        except zlib.error:
            pass
    return None


def decrypt_algo2(entry: dict, enc: bytes) -> bytes | None:
    """Return plaintext for an Algorithm-2 entry, or None on failure."""
    cache_key = (entry["mapped_id"], entry["size"])
    if cache_key in _seed_cache:
        seed = _seed_cache[cache_key]
        out = _try_algo2_seed(enc, entry["size"], seed)
        if out is not None:
            return out
    for seed in range(1, len(SEED_TABLE)):
        out = _try_algo2_seed(enc, entry["size"], seed)
        if out is not None:
            _seed_cache[cache_key] = seed
            return out
    return None


def inflate(b: bytes) -> bytes | None:
    for wbits in (15, -15):
        try:
            return zlib.decompress(b, wbits)
        except zlib.error:
            pass
    return None


def load_kom(path: Path):
    data = path.read_bytes()
    if not data[:26] == b"KOG GC TEAM MASSFILE V.1.0":
        return None, None
    xml_size = struct.unpack_from("<I", data, 0x48)[0]
    xml = xml_decrypt(data[HEADER_SIZE:HEADER_SIZE + xml_size], xml_size)
    entries = parse_index(xml)
    # restore per-entry file offset
    cursor = HEADER_SIZE + xml_size
    for e in entries:
        e["offset"] = cursor
        cursor += e["compressed"]
    return data, xml, entries


def extract(kom_path: Path, out_root: Path, quiet: bool = False):
    ret = load_kom(kom_path)
    if ret is None or ret[0] is None:
        print(f"skip {kom_path.name}: not a V.1.0 kom")
        return 0, 0, 0
    data, xml, entries = ret

    out_dir = out_root / kom_path.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "_index.xml").write_bytes(xml.rstrip(b"\x00"))

    n_ok = {0: 0, 2: 0}
    n_fail = 0
    skipped = []
    t0 = time.time()
    last = t0

    for i, e in enumerate(entries):
        blob = data[e["offset"]:e["offset"] + e["compressed"]]
        name = e["name"].replace("\\", "/").lstrip("/")

        try:
            algo = e["algorithm"]
            if algo == 0:
                raw = inflate(blob)
                if raw is None or len(raw) != e["size"]:
                    raise ValueError(f"algo-0 inflate mismatch")
            elif algo == 2:
                raw = decrypt_algo2(e, blob)
                if raw is None:
                    raise ValueError(f"algo-2 seed not found")
            elif algo == 3:
                skipped.append(f"[algo 3] {name}")
                continue
            else:
                skipped.append(f"[algo {algo}] {name}")
                continue

            dst = out_dir / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(raw)
            n_ok[algo] += 1
        except Exception as ex:
            n_fail += 1
            if not quiet:
                print(f"  FAIL  {name}  algo={e['algorithm']}: {ex}")

        now = time.time()
        if not quiet and now - last >= 5.0:
            elapsed = now - t0
            rate = (i + 1) / elapsed
            print(f"  ... {i+1}/{len(entries)} (algo0={n_ok[0]} algo2={n_ok[2]} "
                  f"skipped={len(skipped)} fail={n_fail}) {rate:.1f}/s")
            last = now

    if skipped:
        (out_dir / "_skipped.txt").write_text("\n".join(skipped))

    total_ok = sum(n_ok.values())
    elapsed = time.time() - t0
    print(f"{kom_path.name}: ok={total_ok} (a0={n_ok[0]} a2={n_ok[2]}) "
          f"skipped={len(skipped)} fail={n_fail}  {elapsed:.1f}s  -> {out_dir}")
    return total_ok, len(skipped), n_fail


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("path", type=Path, help="single .kom file, or root dir with --all")
    ap.add_argument("--all", action="store_true", help="recursively extract every .kom under path")
    ap.add_argument("--out", type=Path, default=Path.cwd() / "extracted")
    ap.add_argument("--quiet", action="store_true", help="less verbose output")
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    if args.all:
        targets = sorted(args.path.rglob("*.kom"))
        if not targets:
            print(f"no .kom files found under {args.path}")
            sys.exit(1)
        g_ok = g_skip = g_fail = 0
        for p in targets:
            ok, skip, fail = extract(p, args.out, quiet=args.quiet)
            g_ok += ok
            g_skip += skip
            g_fail += fail
        print(f"\nTotal across {len(targets)} archives: "
              f"ok={g_ok:,}  skipped_algo3={g_skip:,}  fail={g_fail:,}")
    else:
        extract(args.path, args.out, quiet=args.quiet)


if __name__ == "__main__":
    main()
