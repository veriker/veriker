# build_real_compiler_minimal — V-Kernel Python Compiler Pilot

Proves that V-Kernel re-derivation generalizes to **actual deterministic
compilation**, not just recipe execution. The re-derivation primitive is:

> Re-compile the committed `.py` sources with the pinned toolchain and assert
> that the produced `.pyc` bytes equal the bundled `.pyc` bytes.

Toolchain identity is anchored in the recipe via `cache_tag`
(e.g. `"cpython-314"`), which encodes interpreter family + major/minor version.

---

## Quick start

```bash
cd veriker

# Build
python examples/build_real_compiler_minimal/_build_bundle.py \
       --out-dir /tmp/build_real_compiler_bundle

# Verify
python examples/build_real_compiler_minimal/verify.py \
       --bundle-dir /tmp/build_real_compiler_bundle
# stdout: PASS

# Tests (happy path + tamper tests)
python -m pytest tests/test_build_real_compiler_minimal.py -v
```

---

## How determinism is achieved

### PEP 552 CHECKED_HASH mode

CPython `.pyc` files have a 16-byte header:

```
[4 bytes magic number]  [4 bytes flags]  [8 bytes source-hash or mtime]
```

In the default `TIMESTAMP` mode, bytes 8-15 encode the source file's mtime.
mtime varies between machines and over time — not re-derivable.

In `CHECKED_HASH` mode (`flags = 0x03`), bytes 8-15 encode a hash of the
**source content** instead.  The output is purely a function of:

- source bytes
- `sys.implementation.cache_tag` (= interpreter family + major/minor)
- `optimize` level

This makes the `.pyc` bytes re-derivable from the committed source.

### SOURCE_DATE_EPOCH=0

The standard [reproducible-builds.org](https://reproducible-builds.org/docs/source-date-epoch/)
environment variable. CPython respects it during bytecode compilation to
suppress timestamp embedding. Set to `"0"` before invoking `py_compile`.

### cache_tag as toolchain identity

`sys.implementation.cache_tag` (e.g. `"cpython-314"`) is the standard CPython
identifier written into the magic number at the front of every `.pyc` file.
The recipe pins this value at build time; the verifier checks it first — a
`cache_tag` mismatch (different Python version) exits with
`BUILD_PY_TOOLCHAIN_MISMATCH` rather than a confusing byte-diff.

---

## gcc-equivalent shape

The same primitive works for native code:

```python
subprocess.run(
    ["gcc", "-c", "-o", out_path, src_path],
    env={"SOURCE_DATE_EPOCH": "0"},
    check=True,
)
```

This pilot uses `py_compile` only because the v-kernel-pilot skill mandates
stdlib-only re-derivation packs (no cross-platform toolchain dependency in CI).

---

## Tamper-test flow

### Primary tamper — source mutation

```bash
# 1. Build clean bundle
python _build_bundle.py --out-dir /tmp/tbr

# 2. Mutate sources/mod_a.py (byte change)
echo "EXTRA = 999" >> /tmp/tbr/sources/mod_a.py

# 3. Re-align mod_a.py SHA in manifest so FileIntegrityManySmall passes
python -c "
import hashlib, json, pathlib
d = pathlib.Path('/tmp/tbr')
data = (d/'sources/mod_a.py').read_bytes()
m = json.loads((d/'manifest.json').read_text())
m['files']['sources/mod_a.py'] = hashlib.sha256(data).hexdigest()
(d/'manifest.json').write_text(json.dumps(m, indent=2))
"

# 4. Verify — must FAIL with BUILD_PY_REDERIVATION_MISMATCH
python verify.py --bundle-dir /tmp/tbr
# stderr: [build_py_re_derivation] BUILD_PY_REDERIVATION_MISMATCH: ...
```

The `.pyc` in `payload/artifacts/mod_a.pyc` was compiled from the original
source; re-compiling from the mutated source produces different bytes.
`BuildPyReDerivationCheck` catches this even though the file SHA passed.

### Bonus tamper — toolchain mismatch

```bash
# Mutate recipe cache_tag to a fake value
python -c "
import json, hashlib, pathlib
d = pathlib.Path('/tmp/tbr')
recipe_path = d/'recipe/build_recipe.json'
r = json.loads(recipe_path.read_text())
r['cache_tag'] = 'fake-cache-tag-3000'
recipe_bytes = json.dumps(r, indent=2, sort_keys=True).encode()
recipe_path.write_bytes(recipe_bytes)
m = json.loads((d/'manifest.json').read_text())
m['files']['recipe/build_recipe.json'] = hashlib.sha256(recipe_bytes).hexdigest()
(d/'manifest.json').write_text(json.dumps(m, indent=2))
"

python verify.py --bundle-dir /tmp/tbr
# stderr: [build_py_re_derivation] BUILD_PY_TOOLCHAIN_MISMATCH: ...
```

---

## Bundle layout

```
<bundle-dir>/
  sources/
    mod_a.py           deterministic constant module
    mod_b.py           deterministic computation module
    mod_c.py           deterministic class module
  recipe/
    build_recipe.json  pinned recipe (schema, interpreter, cache_tag, sources)
  payload/
    artifacts/
      mod_a.pyc        bundled compiled bytecode
      mod_b.pyc
      mod_c.pyc
  manifest.json        per-file SHA-256 + typed_checks declaration
```

---

## Reason codes

| Code | Meaning |
|---|---|
| `BUILD_PY_REDERIVED` | ok=True — all .pyc bytes match |
| `BUILD_PY_REDERIVATION_MISMATCH` | re-derived .pyc bytes differ from bundled |
| `BUILD_PY_TOOLCHAIN_MISMATCH` | verifier's cache_tag != recipe's cache_tag |
| `BUILD_PY_REDERIVATION_TIMEOUT` | re-derivation pack subprocess exceeded 60 s |

---

*Part of the NEXI V-Kernel audit-bundle patent portfolio (S0 integrator, N-domain table).*
