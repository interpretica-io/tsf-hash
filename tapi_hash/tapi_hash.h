/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Hashes from a test
 *
 * @defgroup tapi_hash Hashing and cracking (tapi_hash)
 * @{
 *
 * Hashes from a Test Agent: computing a digest with one of many
 * algorithms, telling from a hash string what made it, and - the other
 * direction - trying to recover what a hash was made from, by a
 * wordlist, a brute-force mask, a rule set or a precomputed table.
 *
 * - @ref tapi_hash - algorithms, the tools the agent has, computing a
 *   digest, and identifying one;
 * - @ref tapi_hash_crack - recovering a preimage with hashcat or John
 *   the Ripper;
 * - @ref tapi_hash_rainbow - a lookup in a precomputed (rainbow) table;
 * - @ref tapi_hash_audit - a set of hashes read as a credential-strength
 *   posture, reported through tsf-cybersec.
 *
 * Everything runs on the agent behind a job factory, the same shape as
 * the other tsf-* libraries: the digest is computed and the cracker is
 * driven on the agent, and only what a tool printed is read back. A
 * digest of a handful of algorithms could be done in the engine, but a
 * cracker cannot, and keeping both on the agent means one code path and
 * one place the work actually happens.
 *
 * @section tapi_hash_authorized Authorized use only
 *
 * The cracking half of this library recovers credentials. It exists for
 * an authorized assessment - a pilot, a CTF, credential-strength
 * auditing of a system you own or are engaged to test - and for nothing
 * else. Point it only at hashes you are permitted to attack.
 *
 * @section tapi_hash_backends The tools, and no pretence
 *
 * The breadth of algorithms for a plain digest is a small @c python3
 * helper on the agent (@c hashlib and @c crypt), for the same reason
 * tsf-smb negotiates SMB with one: a helper reads far more algorithms
 * than juggling @c md5sum, @c sha256sum and @c openssl would. The
 * crackers are the real ones - @c hashcat and @c john - and the tables
 * are @c rcrack (RainbowCrack) and @c ophcrack. Each is asked whether
 * it is there before it is used; a capability a backend lacks is
 * refused with @c TE_EOPNOTSUPP, never quietly skipped.
 *
 * @code
 * te_string digest = TE_STRING_INIT;
 *
 * if (!tapi_hash_available(factory, 10000))
 *     TEST_SKIP("There is no python3 on the agent to hash with");
 * CHECK_RC(tapi_hash_compute(factory, TAPI_HASH_SHA256,
 *                            "secret", 6, NULL, 0, 10000, &digest));
 * @endcode
 */

#ifndef __TSF_TAPI_HASH_H__
#define __TSF_TAPI_HASH_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Default timeout for one hashing command, ms. */
#define TAPI_HASH_TIMEOUT_MS 30000

/**
 * A hashing algorithm. The plain digests and the password schemes are
 * one enum because a hash string is identified without knowing yet
 * which kind it is.
 */
typedef enum tapi_hash_alg {
    /** Not set. */
    TAPI_HASH_NONE = 0,

    /* Plain digests. */
    /** MD5 - fast, broken, still found. */
    TAPI_HASH_MD5,
    /** SHA-1 - fast, deprecated. */
    TAPI_HASH_SHA1,
    /** SHA-224. */
    TAPI_HASH_SHA224,
    /** SHA-256. */
    TAPI_HASH_SHA256,
    /** SHA-384. */
    TAPI_HASH_SHA384,
    /** SHA-512. */
    TAPI_HASH_SHA512,
    /** SHA3-256. */
    TAPI_HASH_SHA3_256,
    /** SHA3-512. */
    TAPI_HASH_SHA3_512,
    /** BLAKE2b-512. */
    TAPI_HASH_BLAKE2B,
    /** CRC32 - a checksum, not a hash; here to be recognised as weak. */
    TAPI_HASH_CRC32,

    /* Windows. */
    /** LM - the DES-based one, catastrophically weak. */
    TAPI_HASH_LM,
    /** NTLM - MD4 of the UTF-16LE password, unsalted. */
    TAPI_HASH_NTLM,

    /* Unix password schemes (crypt(3)). */
    /** Traditional DES crypt - two-character salt, 8-char password. */
    TAPI_HASH_DESCRYPT,
    /** MD5-crypt, @c $1$. */
    TAPI_HASH_MD5CRYPT,
    /** bcrypt, @c $2a$/$2b$/$2y$ - a cost parameter. */
    TAPI_HASH_BCRYPT,
    /** SHA-256 crypt, @c $5$ - a rounds parameter. */
    TAPI_HASH_SHA256CRYPT,
    /** SHA-512 crypt, @c $6$ - a rounds parameter. */
    TAPI_HASH_SHA512CRYPT,
    /** yescrypt, @c $y$ - the current glibc default. */
    TAPI_HASH_YESCRYPT,

    /* Password-based key derivation. */
    /** PBKDF2-HMAC-SHA256 - an iteration count. */
    TAPI_HASH_PBKDF2_SHA256,
    /** scrypt. */
    TAPI_HASH_SCRYPT,
    /** Argon2id - the modern default. */
    TAPI_HASH_ARGON2,
} tapi_hash_alg;

/**
 * The property of an algorithm the audit cares about: how much work one
 * guess costs an attacker.
 */
typedef enum tapi_hash_class {
    /** A plain, unsalted, fast digest - MD5, SHA-1, NTLM. The worst. */
    TAPI_HASH_CLASS_FAST_UNSALTED,
    /** A salted but still fast digest - DES crypt, MD5-crypt. */
    TAPI_HASH_CLASS_FAST_SALTED,
    /** A deliberately slow, salted scheme - bcrypt, yescrypt, argon2. */
    TAPI_HASH_CLASS_SLOW,
    /** A checksum, never a password hash - CRC32. */
    TAPI_HASH_CLASS_CHECKSUM,
} tapi_hash_class;

/** Compute a digest of some bytes. */
#define TAPI_HASH_FEAT_COMPUTE  (1u << 0)
/** Identify an algorithm from a hash string. */
#define TAPI_HASH_FEAT_IDENTIFY (1u << 1)
/** Crack a hash with a wordlist. */
#define TAPI_HASH_FEAT_DICT     (1u << 2)
/** Crack a hash with a brute-force mask. */
#define TAPI_HASH_FEAT_MASK     (1u << 3)
/** Crack a hash with a rule set over a wordlist. */
#define TAPI_HASH_FEAT_RULES    (1u << 4)
/** Look a hash up in a precomputed (rainbow) table. */
#define TAPI_HASH_FEAT_RAINBOW  (1u << 5)

/**
 * Is there a @c python3 on the agent to compute and identify with?
 *
 * @param factory       Job factory.
 * @param timeout_ms    Timeout, ms.
 *
 * @return @c true when the helper can run.
 */
extern bool tapi_hash_available(tapi_job_factory_t *factory, int timeout_ms);

/**
 * Compute a digest of some bytes.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  alg          Algorithm.
 * @param[in]  data         The bytes to hash.
 * @param[in]  len          How many.
 * @param[in]  salt         Salt for a password scheme, or @c NULL. For
 *                          a plain digest it is ignored.
 * @param[in]  salt_len     Salt length.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] hash         String to append the result to - a hex
 *                          digest, or the @c crypt(3) string for a
 *                          password scheme.
 *
 * @return Status code.
 * @retval TE_EOPNOTSUPP    The agent's helper cannot do @p alg (a
 *                          missing @c md4 or @c argon2, say).
 */
extern te_errno tapi_hash_compute(tapi_job_factory_t *factory,
                                  tapi_hash_alg alg, const void *data,
                                  size_t len, const void *salt,
                                  size_t salt_len, int timeout_ms,
                                  te_string *hash);

/**
 * Compute a digest of a file on the agent.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  alg          Algorithm (a plain digest; a password scheme
 *                          is refused with @c TE_EINVAL).
 * @param[in]  path         Path on the agent.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] hash         String to append the hex digest to.
 *
 * @return Status code.
 */
extern te_errno tapi_hash_compute_file(tapi_job_factory_t *factory,
                                       tapi_hash_alg alg, const char *path,
                                       int timeout_ms, te_string *hash);

/**
 * Identify what could have made a hash string.
 *
 * A @c $6$... is a SHA-512 crypt and nothing else; a bare 32 hex
 * characters is MD5 or NTLM or an unsalted MD5 of something - so this
 * appends every candidate, most likely first, not one answer.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  hash         The hash string.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] algs         Vector of #tapi_hash_alg to append to.
 *
 * @return Status code.
 */
extern te_errno tapi_hash_identify(tapi_job_factory_t *factory,
                                   const char *hash, int timeout_ms,
                                   te_vec *algs);

/**
 * What work class an algorithm is - what the audit judges it by.
 *
 * @param alg       Algorithm.
 *
 * @return The class.
 */
extern tapi_hash_class tapi_hash_alg_class(tapi_hash_alg alg);

/**
 * Spell out an algorithm, as @c "sha512crypt" or @c "ntlm".
 *
 * @param alg       Algorithm.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_hash_alg2str(tapi_hash_alg alg);

/**
 * Parse an algorithm name, as this library or hashcat/john spell it.
 *
 * @param name      The name.
 *
 * @return The algorithm, or @ref TAPI_HASH_NONE.
 */
extern tapi_hash_alg tapi_hash_str2alg(const char *name);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_HASH_H__ */

/**@} <!-- END tapi_hash --> */
