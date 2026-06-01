# tsf-hash

Hashing and cracking from a test suite, packaged as an external Test
Environment (TE) repository.

Library:

- `tapi_hash` — engine-side, built as a shared library: computing a
  digest with one of many algorithms, telling from a hash string what
  made it, recovering a preimage with a cracker, looking a hash up in a
  precomputed table, and reading a set of hashes as a credential-strength
  posture.
  - `tapi_hash` — algorithms, the tools the agent has, computing a
    digest, and identifying one;
  - `tapi_hash_crack` — recovering a preimage with hashcat or John the
    Ripper: a wordlist, a brute-force mask, or a rule set;
  - `tapi_hash_rainbow` — a lookup in a precomputed (rainbow) table with
    RainbowCrack;
  - `tapi_hash_audit` — a hash read as a credential-strength posture,
    reported through tsf-cybersec.

TE has no hashing or cracking of its own.

## Authorized use only

The cracking half of this library recovers credentials. It is built for
an **authorized** assessment — a pilot, a CTF, credential-strength
auditing of a system you own or are engaged to test — and for nothing
else. Point it only at hashes you are permitted to attack. The library
never writes a recovered secret into a log or a verdict; it hands it
back to the caller, and where it goes next is the test's responsibility.

## Usage

Declare the repositories in an external libraries catalog and pass it to
`dispatcher.sh --external=external.yml`:

```yaml
repositories:
  - name: tsf_devtool
    url: https://github.com/interpretica-io/tsf-devtool.git
    ref: <tag>
    libs:
      - tapi_devtool
  - name: tsf_cybersec
    url: https://github.com/interpretica-io/tsf-cybersec.git
    ref: <tag>
    libs:
      - tapi_cybersec
  - name: tsf_hash
    url: https://github.com/interpretica-io/tsf-hash.git
    ref: <tag>
    libs:
      - tapi_hash
```

Bind them in `builder.conf`:

```
TE_EXT_REPO_USE([tsf_devtool], [], [tapi_devtool])
TE_EXT_REPO_USE([tsf_cybersec], [], [tapi_cybersec])
TE_EXT_REPO_USE([tsf_hash], [], [tapi_hash])
```

Then add `tapi_hash` to `te_libs` in the suite's `meson.build`. Requires
TE with `TE_EXT_REPO` support and an **RPC** job factory
(`ta_rpcprovider` on the agent): every call reads what a command printed,
which needs output channels, and only that factory has them.

```c
te_string digest = TE_STRING_INIT;

if (!tapi_hash_available(factory, 10000))
    TEST_SKIP("There is no python3 on the agent to hash with");
CHECK_RC(tapi_hash_compute(factory, TAPI_HASH_SHA256,
                           "secret", 6, NULL, 0, 10000, &digest));
```

## Everything runs on the agent

The same shape as tsf-smb: the digest is computed and the cracker is
driven on a Test Agent behind a job factory, and only what a tool
printed is read back. A digest of a few algorithms could be done in the
engine, but a cracker cannot, and keeping both on the agent means one
code path and one place the work happens.

Nothing secret goes on the command line. A message to hash, a guessed
password and a wordlist are files the caller wrote, and the tool is
pointed at the file — what is on `argv` is visible to anyone running
`ps` on the agent. A recovered plaintext is read from the tool's own
output file, never from `argv`, and never logged.

## The algorithms

The breadth for a plain digest is a small `python3` helper on the agent
(`hashlib`, `zlib` and `crypt`), for the same reason tsf-smb negotiates
SMB with one: a helper reads far more algorithms than juggling
`md5sum`, `sha256sum` and `openssl` would.

| Family | Algorithms |
|---|---|
| Fast digests | MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512, BLAKE2b |
| Checksum | CRC32 (recognised so it can be flagged, never a password hash) |
| Windows | LM, NTLM |
| Unix crypt(3) | DES crypt, MD5-crypt (`$1$`), bcrypt (`$2*$`), SHA-256/512 crypt (`$5$`/`$6$`), yescrypt (`$y$`) |
| Key derivation | PBKDF2-HMAC-SHA256, scrypt, Argon2id |

`tapi_hash_identify()` reads a hash string the other way: a `$6$…` is a
SHA-512 crypt and nothing else, while a bare 32 hex characters is MD5 or
NTLM or an LM half, so it returns every candidate, not one answer.

## The crackers, and no pretence

The crackers are the real ones, each asked whether it is there before it
is used; a capability a backend lacks is refused with `TE_EOPNOTSUPP`,
never quietly skipped.

| | hashcat | John the Ripper | RainbowCrack |
|---|---|---|---|
| dictionary (wordlist) | yes | yes | — |
| rules over a wordlist | yes | yes | — |
| brute force (mask) | yes | yes (`--mask`/incremental) | — |
| precomputed table | — | — | yes |
| algorithm selected by | `-m <mode>` | `--format=<name>` | the table's own naming |

- **hashcat** — the algorithm is an `-m` mode, the attack an `-a` number,
  the runtime capped by `--runtime`, and the plaintext read from an
  `--outfile-format 2` file that holds the recovered secret alone.
- **John the Ripper** — the algorithm is a `--format`, the run capped by
  `--max-run-time`, and the plaintext read from `john --show`.
- **RainbowCrack** — `rcrack <tables_dir> -h <hash>`; the plaintext is
  parsed from its result line.

The algorithm maps (`crack_hashcat_mode`, `crack_john_format`) cover the
common set and are the first place to extend; an algorithm not in a
backend's map is refused rather than guessed at.

## What the posture is worth

`tapi_hash_audit()` reads a hash as a credential-strength posture and
reports through tsf-cybersec. The algorithm class is judged first, then
the work factor of a slow scheme, and last — only when the policy names
a wordlist or a tables directory — whether the credential can actually
be recovered.

| Finding | Severity | Read from |
|---|---|---|
| `hash.weak-algorithm` | high | a fast, unsalted digest guards a password |
| `hash.weak-algorithm` (LM) | critical | LM, a DES scheme with no real strength |
| `hash.fast-salted` | medium | a salted but fast scheme (DES/MD5 crypt) |
| `hash.low-work-factor` | medium | a slow scheme tuned too low (bcrypt cost) |
| `hash.cracked-dictionary` | critical | the credential fell to a wordlist within the budget |
| `hash.in-rainbow-table` | critical | the credential was in a precomputed table |
| `hash.not-assessed` | info | the algorithm could not be told from the hash |

The recovery findings need a wordlist (with a time budget) or a tables
directory in the policy, the way tsf-smb's guest-write check needs a
share; without one they are skipped. A recovered secret never enters a
finding — it says only that recovery succeeded and by what means, so the
verdict stays stable and secret-free for `conf/trc.xml`.

## What was verified, and what was not

**The digest/identify helper — validated locally.** The bundled `python3`
helper was extracted from the built-in source and run: `md5("secret")`
came back `5ebe2294ecd0e0f08eab7690d2a6ee69` (the known vector),
SHA-256, SHA3-256, CRC32 and PBKDF2-HMAC-SHA256 all produced digests, and
`identify` classified `$6$`, `$2b$` and the bare-hex lengths correctly.
It has **not** yet been run through a Test Agent behind a job factory.

**NTLM and crypt(3) depend on the agent.** NTLM is `md4` of the UTF-16LE
password, and a stock OpenSSL 3 build has dropped `md4` from `hashlib` —
there the helper answers `unsupported` rather than a wrong hash. The
crypt(3) schemes need the agent's `crypt` module, which Python 3.13
removed; there they answer `unsupported` too. Cracking NTLM or a crypt
hash does not go through the helper, so this limits only `tapi_hash_compute`.

**The crackers and the table lookup — written, not yet run.** The
hashcat, John and RainbowCrack drivers were written from the tools'
documented command lines and output shapes and compiled clean, but the
agent-run verification is owed. The output parsers (hashcat's
plaintext-only outfile, `john --show`'s `user:plaintext:…`, rcrack's
result line) are the first place to check against a live tool, and the
algorithm maps the first place to extend.

## Scope

- **Cracking spends real time and touches real credentials.** A crack
  attempt is bounded by the policy's time budget; without one it can run
  as long as the timeout allows. Give it a budget in an audit.
- **The helper, hash files and output files are written on the agent**
  and removed again, even when a call fails.
- **A recovered secret is the caller's to hold.** The library returns it
  and never logs it; a test that keeps or prints it does so on its own.
