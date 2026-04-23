# Grand Chase `.kom` Full Extractor

Unpacks files from `KOG GC TEAM MASSFILE V.1.0` archives (Grand Chase Classic, Steam / Epic).

## Coverage

| Algorithm | Files in game | Extracts? | Content type |
|-----------|--------------:|:---------:|------------------------------|
| 0         |        16,246 | Yes   | `.wav` audio, `.kstg` strings, misc |
| 2         |       262,524 | **Yes**   | `.dds` textures, `.p3m` 3D models, `.frm` animations |
| 3         |         5,201 | No        | `.lua` scripts, `.stg` strings  |

**Total unlocked: ~98% of all game files** (278,770 of 284,000). Algo 3 scripts remain encrypted (per-file pre-inflate).

## Install

```
pip install pycryptodome
```

Python 3.10+ required.

## Usage

Extract one archive:
```
python extract_kom.py "C:/Program Files (x86)/Steam/steamapps/common/GrandChase/Texture/ui5.kom"
```

Extract the whole game install tree:
```
python extract_kom.py --all "C:/Program Files (x86)/Steam/steamapps/common/GrandChase" --out ./extracted
```

First run is slower — each unique `(MappedID, size)` combo takes ~100 ms to brute-force the Blowfish seed (~300 tries). Subsequent files with the same combo are instant via in-session cache.

Typical per-archive speed after warm-up: **50–90 files/sec**.

## Output

```
extracted/
  <archive_name>/
    _index.xml       - decrypted XML file listing
    _skipped.txt     - Algo-3 entries (not extracted)
    <files ...>      - plaintext extracted files
```

## Algorithm details

### XML index decryption
```
start_index = (12 * (xml_size % 200) + 12) / 4
keys = [KEYS[start_index + 0..2]]
output[i*4 .. i*4+4] = input[i*4 .. i*4+4] XOR keys[i % 3]
```
Key table: 796 entries, hard-coded in `gc_keytable.py`.

### Algorithm 0 (plaintext bucket)
Simple zlib deflate. Inflate, done.

### Algorithm 2 (the interesting one)
Per-file Blowfish with a key derived from a table lookup normally keyed by the file's `MappedID`:

```
permute(MappedID, file_size)        # byte swap + interleave + rotate
seed_idx = MAP[permuted]            # runtime map from komdatalist.xml — missing!
sum      = sum(SEED_TABLE[seed_idx].qword[0..4]) mod 2**64
key      = SHA256(str(sum)).digest()                 # 32 bytes
plain    = zlib.inflate(Blowfish_ECB.decrypt(ciphertext, key))
```

The runtime map is populated from a `komdatalist.xml` fetched from KOG's server, which isn't shipped with the install. We brute-force `seed_idx` per unique `(MappedID, file_size)` combination (≈ 12,000 total in the full game). First hit caches and all later occurrences are instant.

Seed table: 300 entries, hard-coded in `gc_bf_seeds.py`.

## Files

- `extract_kom.py`   – the extractor
- `gc_keytable.py`   – 796-entry XML-decrypt key table
- `gc_bf_seeds.py`   – 300-entry per-file seed sum table
- `README.md`        – this file

## Credits

Format reversed from a memory-dumped Grand Chase Epic build (unpacked `GrandChase.exe` binary). Steam build is Themida-protected; Epic build is not. :P
