# Grand Chase `.kom` Full Extractor

Unpacks files from `KOG GC TEAM MASSFILE V.1.0` archives (Grand Chase Classic, Steam / Epic).

## Coverage

| Algorithm | Files in game | Extracts? | Content type |
|-----------|--------------:|:---------:|------------------------------|
| 0         |        16,246 | **Yes**   | `.wav` audio, `.kstg` strings, misc |
| 2         |       262,524 | **Yes**   | `.dds` textures, `.p3m` 3D models, `.frm` animations |
| 3         |         5,201 | **Yes**   | `.lua` scripts, `.stg` strings |

**All three algorithms supported. ~100% of game content extractable.**

## Install

```
pip install pycryptodome
```

Python 3.10+ required.

## Usage

```
python extract_kom.py "C:/Program Files (x86)/Steam/steamapps/common/GrandChase/Texture/ui5.kom"

python extract_kom.py --all "C:/Program Files (x86)/Steam/steamapps/common/GrandChase" --out ./extracted
```

First time a new Blowfish key is hit on an archive, the brute-force takes a moment; subsequent entries in the same archive use a hot-cache and are instant. Typical speed after warm-up: 50–100 entries/sec.

## Output

```
extracted/
  <archive_name>/
    _index.xml       - decrypted XML listing of all entries
    _skipped.txt     - entries that failed to decrypt (reason shown)
    <files ...>      - plaintext extracted files
```

## Algorithm details

### XML index
Three rotating 32-bit XOR keys, indexed by `xml_size`:
```
start_index = (12 * (xml_size % 200) + 12) / 4
keys = [KEYS[start_index + 0..2]]
output[i*4 .. i*4+4] = input[i*4 .. i*4+4] XOR keys[i % 3]
```
796-entry key table in `gc_keytable.py`.

### Algorithm 0
Simple zlib inflate.

### Algorithm 2
Per-entry Blowfish-ECB with a key derived from a seed-table row:
```
bf_key = SHA256(str(SEED_TABLE[i])).digest()           # 32 bytes
plain  = zlib.inflate( Blowfish_ECB.decrypt(ct, bf_key) )
```

Normally `i` (the seed index) would be looked up in a runtime map populated from server-fetched `komdatalist.xml`. Since that file isn't shipped, we brute-force the index against `SEED_TABLE` (13,790 entries). Per-archive hot-caching keeps this fast after the first hit.

### Algorithm 3
AES-256-CBC wrapper around an Algo-2-style payload:
```
aes_plain  = AES_256_CBC.decrypt(ct, aes_key, iv)      # key/iv from AES_PAIRS
zlib_plain = zlib.inflate(aes_plain)
lua_bytes  = Blowfish_ECB.decrypt(zlib_plain, bf_key)  # same BF key scheme as Algo 2
```

AES key/IV pairs are captured from the running game via Frida hooks. 106 pairs bundled in `gc_aes_keys.py`.

## Updating keys

If you get failures on new game content after a game update (KOG can rotate AES keys), capture fresh pairs via the Frida scripts in [`rockmizx/grandchase_toolkit`](https://github.com/rockmizx/grandchase_toolkit) and append to the `AES_PAIRS` list in `gc_aes_keys.py`.

## Files

- `extract_kom.py`     – the extractor
- `gc_keytable.py`     – 796-entry XML-decrypt key table
- `gc_bf_seeds.py`     – 13,790-entry Blowfish seed table
- `gc_aes_keys.py`     – 106 AES-256-CBC key/IV pairs
- `README.md`          – this file
- `LICENSE`            – MIT

## Credits

- **Algorithm 3** (AES-256-CBC outer layer), the 13,790-entry Blowfish seed table, and the bundled AES key/IV corpus come from [`rockmizx/grandchase_toolkit`](https://github.com/rockmizx/grandchase_toolkit) (MIT licensed — see `LICENSE`).
- Format and Algorithm 2 reversing was done against the unpacked Epic build of `GrandChase.exe`. Steam builds ship Themida-protected; Epic builds do not. :P
- Partial V.0.3 reference / inspiration: [KOMCast](https://github.com/d3v1l401/KOMCast), [YuilKOM](https://github.com/YuilMuil/YuilKOM), [Els_kom_new](https://github.com/Elskom/Els_kom_new).
