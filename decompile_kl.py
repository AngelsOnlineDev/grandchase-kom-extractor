"""Decompile Grand Chase KL bytecode (`1B KL 84`) to Lua source.

Wraps Andrian Nord's LJD decompiler (decompiler/ljd) with a 3-level fallback
pipeline and a safety thread + timeout that survives pathological inputs.

Also converts `.stg` (UTF-16-LE + BOM) string tables to UTF-8 as-is.

USAGE
    # single file
    python decompile_kl.py path/to/InitSkillInfo_0_0.lua

    # whole tree
    python decompile_kl.py --all ./extracted --out ./decompiled

The extractor output is the expected input: `.lua` entries with the
`1B 4B 4C 84` (KL) magic bytes.
"""
import argparse, io, os, sys, time, threading, shutil
from pathlib import Path

HERE = Path(__file__).parent
# Make LJD importable
sys.path.insert(0, str(HERE / "decompiler"))

# Fail loudly up-front if the LJD bundle isn't present — otherwise every
# decompile task silently errors in its worker thread and the CLI reports
# `Failed: <all files>` with no hint why.
if not (HERE / "decompiler" / "ljd" / "__init__.py").is_file():
    sys.exit(
        "error: LJD decompiler not found at "
        f"{HERE / 'decompiler' / 'ljd'}\n"
        "Re-clone or re-download the repo — `decompiler/ljd/` is required:\n"
        "  git clone https://github.com/AngelsOnlineDev/grandchase-kom-extractor"
    )

# LJD does a lot of recursion; push the recursion limit up globally
sys.setrecursionlimit(20000)

DECOMPILE_TIMEOUT = 60          # seconds base
DECOMPILE_TIMEOUT_PER_MB = 60   # seconds added per MB of input

KL_MAGIC = b"\x1bKL\x84"
LJ_MAGIC = b"\x1bLJ"
STG_BOM = b"\xff\xfe"


def _import_ljd():
    """Import LJD modules lazily so the script can --help without them."""
    import ljd.rawdump.parser
    import ljd.ast.builder
    import ljd.ast.validator
    import ljd.ast.mutator
    import ljd.ast.locals
    import ljd.ast.slotworks
    import ljd.ast.unwarper
    import ljd.ast.slotrenamer
    import ljd.ast.dce
    import ljd.lua.writer
    import ljd.lua.postprocess
    return sys.modules["ljd"]


def decompile_bytecode(raw: bytes):
    """Parse and decompile KL bytecode, trying progressively simpler pipelines.

    Returns (level, lua_source). `level` is 0 (full pipeline), 1 (no unwarper),
    or 2 (minimal) depending on which passes succeeded. Returns None if parse
    itself fails.
    """
    ljd_pkg = _import_ljd()
    import tempfile

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".lua")
    try:
        tmp.write(raw)
        tmp.close()
        header, prototype = ljd_pkg.rawdump.parser.parse(tmp.name)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    if not prototype:
        return None

    # --- Level 0: full pipeline --------------------------------------------
    try:
        ast = ljd_pkg.ast.builder.build(prototype)
        if ast is None:
            raise RuntimeError("AST build failed")
        ljd_pkg.ast.validator.validate(ast, warped=True)
        ljd_pkg.ast.mutator.pre_pass(ast)
        ljd_pkg.ast.locals.mark_locals(ast)
        ljd_pkg.ast.slotworks.eliminate_temporary(ast)
        ljd_pkg.ast.unwarper.unwarp(ast)
        try:
            ljd_pkg.ast.locals.mark_local_definitions(ast)
        except (AttributeError, KeyError, IndexError):
            pass
        try:
            ljd_pkg.ast.mutator.primary_pass(ast)
        except (AttributeError, KeyError, IndexError, AssertionError):
            pass
        try:
            ljd_pkg.ast.validator.validate(ast, warped=False)
        except Exception:
            pass
        ljd_pkg.ast.slotrenamer.rename_slots(ast)
        try:
            ljd_pkg.ast.dce.eliminate_dead_stores(ast)
        except Exception:
            pass
        buf = io.StringIO()
        ljd_pkg.lua.writer.write(buf, ast)
        return 0, ljd_pkg.lua.postprocess.postprocess(buf.getvalue())
    except (Exception, RecursionError):
        pass

    # --- Level 1: skip unwarper --------------------------------------------
    try:
        ast = ljd_pkg.ast.builder.build(prototype)
        ljd_pkg.ast.validator.validate(ast, warped=True)
        ljd_pkg.ast.mutator.pre_pass(ast)
        ljd_pkg.ast.locals.mark_locals(ast)
        ljd_pkg.ast.slotworks.eliminate_temporary(ast)
        ljd_pkg.ast.slotrenamer.rename_slots(ast)
        try:
            ljd_pkg.ast.dce.eliminate_dead_stores(ast)
        except Exception:
            pass
        buf = io.StringIO()
        ljd_pkg.lua.writer.write(buf, ast)
        return 1, ljd_pkg.lua.postprocess.postprocess(buf.getvalue())
    except (Exception, RecursionError):
        pass

    # --- Level 2: bare minimum ---------------------------------------------
    try:
        ast = ljd_pkg.ast.builder.build(prototype)
        ljd_pkg.ast.mutator.pre_pass(ast)
        ljd_pkg.ast.slotrenamer.rename_slots(ast)
        try:
            ljd_pkg.ast.dce.eliminate_dead_stores(ast)
        except Exception:
            pass
        buf = io.StringIO()
        ljd_pkg.lua.writer.write(buf, ast)
        return 2, ljd_pkg.lua.postprocess.postprocess(buf.getvalue())
    except (Exception, RecursionError):
        pass

    return None


def decompile_safe(raw: bytes):
    """Run decompile on a dedicated thread with a large stack + timeout.

    Some KL inputs make LJD recurse deeply; a separate thread with a 64 MB
    stack and a size-proportional timeout keeps one bad file from hanging
    the batch.
    """
    result = [None]

    def worker():
        try:
            result[0] = decompile_bytecode(raw)
        except BaseException:
            result[0] = None

    try:
        threading.stack_size(64 * 1024 * 1024)
    except (ValueError, RuntimeError):
        pass

    size_mb = len(raw) / (1024 * 1024)
    timeout = DECOMPILE_TIMEOUT + size_mb * DECOMPILE_TIMEOUT_PER_MB

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout=timeout)

    try:
        threading.stack_size(0)
    except (ValueError, RuntimeError):
        pass

    if t.is_alive():
        return None
    return result[0]


def convert_stg(raw: bytes) -> bytes | None:
    """Convert `.stg` UTF-16-LE (with BOM) to UTF-8. Return None if not STG."""
    if raw[:2] != STG_BOM:
        return None
    try:
        return raw[2:].decode("utf-16-le").encode("utf-8")
    except UnicodeDecodeError:
        return None


def process_file(path: Path, out_path: Path):
    """Decompile one file. Returns one of 'kl0'..'kl2', 'stg', 'copy', 'fail'."""
    raw = path.read_bytes()
    if raw[:4] == KL_MAGIC or raw[:3] == LJ_MAGIC:
        res = decompile_safe(raw)
        if res is None:
            return "fail"
        level, src = res
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(src, encoding="utf-8")
        return f"kl{level}"
    if raw[:2] == STG_BOM:
        utf8 = convert_stg(raw)
        if utf8 is None:
            return "fail"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(utf8)
        return "stg"
    # plaintext or other: copy through
    out_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, out_path)
    return "copy"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("path", type=Path, help="KL file, or a tree root with --all")
    ap.add_argument("--all", action="store_true",
                    help="process every .lua/.stg/.kstg under path")
    ap.add_argument("--out", type=Path, default=Path.cwd() / "decompiled",
                    help="output root (default ./decompiled)")
    ap.add_argument("--filter", type=str, default=None,
                    help="only process entries whose relative path contains this substring")
    args = ap.parse_args()

    if args.all:
        if not args.path.is_dir():
            print(f"--all requires a directory, got {args.path}")
            sys.exit(2)
        args.out.mkdir(parents=True, exist_ok=True)
        files = [p for p in args.path.rglob("*")
                 if p.is_file() and p.suffix.lower() in (".lua", ".stg", ".kstg")]
        if args.filter:
            files = [p for p in files if args.filter.lower()
                     in str(p.relative_to(args.path)).lower()]
        stats = {"kl0": 0, "kl1": 0, "kl2": 0, "stg": 0, "copy": 0, "fail": 0}
        t0 = time.time()
        last = t0
        for i, p in enumerate(files):
            rel = p.relative_to(args.path)
            out_path = args.out / rel
            try:
                r = process_file(p, out_path)
            except Exception:
                r = "fail"
            stats[r] = stats.get(r, 0) + 1
            now = time.time()
            if now - last >= 5.0:
                rate = (i + 1) / (now - t0)
                print(f"  ... {i+1}/{len(files)}  {stats}  {rate:.1f}/s")
                last = now
        elapsed = time.time() - t0
        print(f"\nDone in {elapsed:.1f}s  (processed {len(files)} files)")
        print(f"  KL decompiled: level0={stats['kl0']} level1={stats['kl1']} "
              f"level2={stats['kl2']}  (total {stats['kl0']+stats['kl1']+stats['kl2']})")
        print(f"  STG converted: {stats['stg']}")
        print(f"  Copied:        {stats['copy']}")
        print(f"  Failed:        {stats['fail']}")
    else:
        if not args.path.is_file():
            print(f"not a file: {args.path}")
            sys.exit(2)
        out_path = args.out if args.out.suffix else args.out / args.path.name
        r = process_file(args.path, out_path)
        print(f"{args.path.name}: {r}  ->  {out_path}")


if __name__ == "__main__":
    main()
