"""Grand Chase .kom extractor — Algorithms 0, 2, and 3.

Unpacks files from "KOG GC TEAM MASSFILE V.1.0" archives.

    Algo 0  (plain zlib)                             - supported
    Algo 2  (Blowfish ECB + zlib)                    - supported
    Algo 3  (AES-256-CBC -> zlib -> Blowfish ECB)    - supported

Requires: Python 3.10+ and pycryptodome (`pip install pycryptodome`).

USAGE
    python extract_kom.py "path/to/one.kom"
    python extract_kom.py --all "C:/Program Files (x86)/Steam/steamapps/common/GrandChase"
    python extract_kom.py my.kom --out ./out

OUTPUT
    extracted/<archive_stem>/
        _index.xml        - the decrypted file index
        _skipped.txt      - entries that couldn't be decrypted (reason listed)
        <files...>        - plaintext extracted files

KEY DATA
    gc_keytable.py   - 796-entry XML-decrypt key table
    gc_bf_seeds.py   - 13,790-entry Blowfish key-seed table (Algo 2 and 3)
    gc_aes_keys.py   - 106 AES-256-CBC key/IV pairs (Algo 3)
"""
import argparse, struct, zlib, re, hashlib, sys, time
from pathlib import Path
from Crypto.Cipher import Blowfish, AES

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from gc_keytable import MAPPED_HEADER_KEYS as XML_KEYS
from gc_bf_seeds import SEED_TABLE
from gc_aes_keys import AES_PAIRS

HEADER_SIZE = 0x4C
FILE_RE = re.compile(
    rb'<File\s+Name="([^"]*)"\s+Size="(\d+)"\s+CompressedSize="(\d+)"\s+'
    rb'Checksum="([^"]*)"\s+FileTime="([^"]*)"\s+Algorithm="(\d+)"'
    rb'(?:\s+MappedID="([^"]*)")?\s*/>'
)
ZLIB_MAGICS = (b"\x78\x01", b"\x78\x5E", b"\x78\x9C", b"\x78\xDA")
KL_MAGIC = b"\x1bKL\x84"
LJ_MAGIC = b"\x1bLJ"
STG_BOM = b"\xff\xfe"


# ---------------------------------------------------------------------------
# XML index decryption (shared by every archive regardless of algo)
# ---------------------------------------------------------------------------
def xml_decrypt(enc: bytes, seed: int) -> bytes:
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


def parse_index(xml: bytes):
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


def inflate(b: bytes):
    for wbits in (15, -15):
        try:
            return zlib.decompress(b, wbits)
        except zlib.error:
            pass
    return None


# ---------------------------------------------------------------------------
# Blowfish pool — key = SHA256(decimal(sum)); used for Algo 2 and the inner
# layer of Algo 3.
# ---------------------------------------------------------------------------
_bf_keys_cache: list[bytes] | None = None


def _bf_keys() -> list[bytes]:
    global _bf_keys_cache
    if _bf_keys_cache is None:
        _bf_keys_cache = [
            hashlib.sha256(str(s).encode("ascii")).digest() for s in SEED_TABLE
        ]
    return _bf_keys_cache


def _looks_plaintext(buf: bytes) -> bool:
    if len(buf) < 2:
        return False
    if buf[:4] == KL_MAGIC or buf[:3] == LJ_MAGIC or buf[:2] == STG_BOM:
        return True
    if buf[:2] in ZLIB_MAGICS:
        try:
            zlib.decompress(buf)
            return True
        except zlib.error:
            return False
    return False


def decrypt_blowfish(enc: bytes, hot: set[int] | None = None,
                     expected_inflate_size: int | None = None):
    """Brute-force Blowfish ECB key against SEED_TABLE. Returns (plain, idx).

    If expected_inflate_size is given, a key is only accepted when
    zlib-inflating the Blowfish output yields exactly that many bytes. Without
    this check, false-positive keys (wrong key yields bytes that happen to be
    valid zlib of a DIFFERENT length) can be accepted.
    """
    keys = _bf_keys()
    full = len(enc) - (len(enc) % 8)
    if full < 8:
        return None, -1
    tail = enc[full:]
    head = enc[:8]

    def accept(idx):
        bf = Blowfish.new(keys[idx], Blowfish.MODE_ECB)
        out = bf.decrypt(enc[:full]) + tail
        if expected_inflate_size is not None:
            if out[:2] not in ZLIB_MAGICS:
                return None
            inflated = inflate(out)
            if inflated is None or len(inflated) != expected_inflate_size:
                return None
            return out
        return out if _looks_plaintext(out) else None

    order = []
    if hot:
        order.extend(i for i in hot if 0 <= i < len(keys))
    seen = set(order)
    order.extend(i for i in range(len(keys)) if i not in seen)

    for idx in order:
        bf = Blowfish.new(keys[idx], Blowfish.MODE_ECB)
        first = bf.decrypt(head)
        if (first[:2] not in ZLIB_MAGICS and first[:4] != KL_MAGIC
                and first[:3] != LJ_MAGIC and first[:2] != STG_BOM):
            continue
        pt = accept(idx)
        if pt is not None:
            return pt, idx
    return None, -1


# ---------------------------------------------------------------------------
# AES-256-CBC (outer layer of Algo 3)
# ---------------------------------------------------------------------------
def decrypt_aes_cbc(enc: bytes, cached_pair=None):
    """Try every AES pair; accept if output is valid zlib (possibly padded)."""
    if len(enc) < 16:
        return None, None
    pairs = [cached_pair] if cached_pair else AES_PAIRS
    for key, iv in pairs:
        try:
            ecb = AES.new(key, AES.MODE_ECB)
            first = ecb.decrypt(enc[:16])
            plain0 = bytes(a ^ b for a, b in zip(first, iv))
            if plain0[:2] not in ZLIB_MAGICS:
                continue
            cbc = AES.new(key, AES.MODE_CBC, iv)
            aligned = len(enc) - (len(enc) % 16)
            dec = cbc.decrypt(enc[:aligned])
            try:
                zlib.decompress(dec)
                return dec, (key, iv)
            except zlib.error:
                pad = dec[-1]
                if 1 <= pad <= 16 and all(b == pad for b in dec[-pad:]):
                    try:
                        zlib.decompress(dec[:-pad])
                        return dec[:-pad], (key, iv)
                    except Exception:
                        pass
        except Exception:
            continue
    return None, None


# ---------------------------------------------------------------------------
# Per-algorithm entry extractors
# ---------------------------------------------------------------------------
def extract_algo0(blob: bytes, expected_size: int):
    raw = inflate(blob)
    if raw is None or len(raw) != expected_size:
        return None
    return raw


def extract_algo2(blob: bytes, expected_size: int, bf_hot: set[int]):
    dec, idx = decrypt_blowfish(blob, bf_hot, expected_inflate_size=expected_size)
    if dec is None:
        return None
    raw = inflate(dec)
    if raw is None or len(raw) != expected_size:
        return None
    bf_hot.add(idx)
    return raw


def extract_algo3(blob: bytes, expected_size: int,
                  aes_hot: list, bf_hot: set[int]):
    aes_dec, aes_pair = decrypt_aes_cbc(blob, aes_hot[0] if aes_hot else None)
    if aes_dec is None:
        return None
    if aes_pair not in aes_hot:
        aes_hot.insert(0, aes_pair)
    try:
        inner = zlib.decompress(aes_dec)
    except zlib.error:
        pad = aes_dec[-1]
        if 1 <= pad <= 16:
            try:
                inner = zlib.decompress(aes_dec[:-pad])
            except Exception:
                return None
        else:
            return None
    # Some entries are already plain after the AES+zlib layers
    if inner[:4] == KL_MAGIC or inner[:3] == LJ_MAGIC or inner[:2] == STG_BOM:
        return inner
    # Otherwise, inner is Blowfish-encrypted
    dec, idx = decrypt_blowfish(inner, bf_hot)
    if dec is not None:
        bf_hot.add(idx)
        return dec
    return inner  # fallback: at least return the zlib-decompressed layer


# ---------------------------------------------------------------------------
# Archive-level
# ---------------------------------------------------------------------------
def load_kom(path: Path):
    data = path.read_bytes()
    if not data[:26] == b"KOG GC TEAM MASSFILE V.1.0":
        return None, None, None
    xml_size = struct.unpack_from("<I", data, 0x48)[0]
    xml = xml_decrypt(data[HEADER_SIZE:HEADER_SIZE + xml_size], xml_size)
    entries = parse_index(xml)
    cursor = HEADER_SIZE + xml_size
    for e in entries:
        e["offset"] = cursor
        cursor += e["compressed"]
    return data, xml, entries


def extract(kom_path: Path, out_root: Path, quiet: bool = False):
    data, xml, entries = load_kom(kom_path)
    if data is None:
        print(f"skip {kom_path.name}: not a V.1.0 kom")
        return 0, 0, 0

    out_dir = out_root / kom_path.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "_index.xml").write_bytes(xml.rstrip(b"\x00"))

    n_ok = {0: 0, 2: 0, 3: 0}
    n_fail = 0
    skipped = []
    bf_hot: set[int] = set()
    aes_hot: list = []
    t0 = time.time()
    last = t0

    for i, e in enumerate(entries):
        blob = data[e["offset"]:e["offset"] + e["compressed"]]
        name = e["name"].replace("\\", "/").lstrip("/")
        algo = e["algorithm"]
        try:
            if algo == 0:
                raw = extract_algo0(blob, e["size"])
                err = "algo-0 inflate mismatch"
            elif algo == 2:
                raw = extract_algo2(blob, e["size"], bf_hot)
                err = "algo-2 key not found"
            elif algo == 3:
                raw = extract_algo3(blob, e["size"], aes_hot, bf_hot)
                err = "algo-3 key not found"
            else:
                skipped.append(f"[algo {algo}] {name}")
                continue
            if raw is None:
                raise ValueError(err)
            dst = out_dir / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(raw)
            n_ok[algo] += 1
        except Exception as ex:
            n_fail += 1
            skipped.append(f"[algo {algo} FAIL] {name}: {ex}")
            if not quiet:
                print(f"  FAIL  {name}  algo={algo}: {ex}")

        now = time.time()
        if not quiet and now - last >= 5.0:
            rate = (i + 1) / (now - t0)
            print(f"  ... {i+1}/{len(entries)}  a0={n_ok[0]} a2={n_ok[2]} "
                  f"a3={n_ok[3]} fail={n_fail}  {rate:.1f}/s")
            last = now

    if skipped:
        (out_dir / "_skipped.txt").write_text("\n".join(skipped))

    total = sum(n_ok.values())
    elapsed = time.time() - t0
    print(f"{kom_path.name}: ok={total} (a0={n_ok[0]} a2={n_ok[2]} a3={n_ok[3]}) "
          f"fail={n_fail}  {elapsed:.1f}s  -> {out_dir}")
    return total, len(skipped), n_fail


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("path", type=Path, help="single .kom file, or root dir with --all")
    ap.add_argument("--all", action="store_true", help="recursively extract every .kom under path")
    ap.add_argument("--out", type=Path, default=Path.cwd() / "extracted")
    ap.add_argument("--quiet", action="store_true")
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
              f"ok={g_ok:,}  skipped={g_skip:,}  fail={g_fail:,}")
    else:
        extract(args.path, args.out, quiet=args.quiet)


if __name__ == "__main__":
    main()
