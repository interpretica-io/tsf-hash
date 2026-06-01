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
    TEST_SKIP("There is no openssl on the agent to hash with");
CHECK_RC(tapi_hash_compute(factory, TAPI_HASH_SHA256,
                           "secret", 6, NULL, 0, 10000, &digest));
```

## Everything runs on the agent

The same shape as tsf-smb: the digest is computed and the cracker is
driven on a Test Agent behind a job factory with stock tools, and only
what a tool printed is read back. A digest of a few algorithms could be
done in the engine, but a cracker cannot, and keeping both on the agent
means one code path and one place the work happens. The two things that
need no tool at all — CRC32 and identifying a hash from its shape — are
done in C in the library.

Nothing secret goes on the command line. A message to hash is a
binary-safe file the caller wrote; a password handed to `mkpasswd` or
`argon2` is a file fed on standard input; a guessed password and a
wordlist for a cracker are files too. What is on `argv` is visible to
anyone running `ps` on the agent. A recovered plaintext is read from the
tool's own output, never from `argv`, and never logged.

## The algorithms

No helper of our own: stock tools do the work, each checked before use.

| Family | Algorithms | Computed by |
|---|---|---|
| Fast digests | MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512, BLAKE2b | `openssl dgst` |
| Checksum | CRC32 (recognised so it can be flagged, never a password hash) | in C, here |
| Windows | NTLM | `openssl dgst -md4` (ASCII password) |
| Unix crypt(3) | DES crypt, MD5-crypt (`$1$`), bcrypt (`$2*$`), SHA-256/512 crypt (`$5$`/`$6$`), yescrypt (`$y$`) | `mkpasswd -m <method>` |
| Password hashing | Argon2id | `argon2` |

`tapi_hash_compute` covers the rows above. LM (compute), and PBKDF2 and
scrypt (compute), are **not** produced here: LM has no safe stock
producer, and the only stock CLI for the two KDFs would put the password
on `argv`. All three are still first-class **cracking** targets, and all
are still **identified** and judged by the audit — computing them is the
only gap.

`tapi_hash_identify()` reads a hash string the other way, in pure C: a
`$6$…` is a SHA-512 crypt and nothing else, while a bare 32 hex
characters is MD5 or NTLM or an LM half, so it returns every candidate,
not one answer.

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

**CRC32 and identify — verified in C.** CRC32 is computed here; its
output was checked byte-for-byte against `zlib.crc32` for several inputs
(`crc32("secret")` = `5ca2e8e5`, and the standard "quick brown fox"
vector `414fa339`). `tapi_hash_identify()` is pure string inspection and
needs no tool. All five source files compile clean under `-Wall
-Wextra` against the TE headers.

**The tool drivers — written from documented command lines, not yet run
through an agent.** `openssl dgst` for the digests, `mkpasswd -m` for the
crypt schemes, `argon2` for Argon2, and the hashcat/John/RainbowCrack
drivers were written from each tool's documented invocation and output
shape and compiled clean, but the agent-run verification is owed. The
output parsers (openssl's `-r` "hash *file", `mkpasswd`'s bare hash,
`argon2 -e`'s encoded string, hashcat's plaintext-only outfile, `john
--show`, rcrack's result line) are the first place to check against a
live tool, and the algorithm maps the first place to extend.

**NTLM computation is best-effort.** NTLM is MD4 of the UTF-16LE
password. The conversion here is the ASCII/Latin-1 one, and MD4 is legacy
in OpenSSL 3, so `tapi_hash_compute` tries a plain `openssl dgst -md4`
first and the `-provider legacy` form second — which also covers an
OpenSSL 1.1 that has no `-provider` option. A non-ASCII password or an
OpenSSL without MD4 at all is the limit. Cracking NTLM goes through
hashcat/john and is unaffected.

## Scope

- **Cracking spends real time and touches real credentials.** A crack
  attempt is bounded by the policy's time budget; without one it can run
  as long as the timeout allows. Give it a budget in an audit.
- **Message, password, hash and output files are written on the agent**
  and removed again, even when a call fails.
- **A recovered secret is the caller's to hold.** The library returns it
  and never logs it; a test that keeps or prints it does so on its own.
