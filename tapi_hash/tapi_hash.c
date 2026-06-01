/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Hashing: algorithms, computing a digest, identifying one
 *
 * No helper of our own: stock tools on the agent do the work. A plain
 * digest is @c openssl @c dgst - one tool for the whole digest set; a
 * crypt(3) password scheme is @c mkpasswd (libcrypt), which covers DES,
 * MD5, bcrypt, the SHA crypts and yescrypt with one consistent output;
 * Argon2 is the @c argon2 tool. CRC32 and the hash identifier are pure
 * C here, needing nothing on the agent at all.
 *
 * A message to hash is a binary-safe file on the agent; a password to
 * an @c mkpasswd or @c argon2 is a file fed on standard input. Neither
 * is ever on @c argv.
 */

#define TE_LGR_USER "TAPI HASH"

#include "te_config.h"

#include <stdint.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_hash.h"
#include "tapi_hash_internal.h"

/** One algorithm, its canonical name and its work class. */
typedef struct hash_alg_desc {
    tapi_hash_alg alg;
    const char *name;
    tapi_hash_class cls;
    /** @c true for a plain digest of arbitrary bytes (usable on a file). */
    bool is_digest;
} hash_alg_desc;

static const hash_alg_desc hash_algs[] = {
    { TAPI_HASH_MD5,          "md5",          TAPI_HASH_CLASS_FAST_UNSALTED, true },
    { TAPI_HASH_SHA1,         "sha1",         TAPI_HASH_CLASS_FAST_UNSALTED, true },
    { TAPI_HASH_SHA224,       "sha224",       TAPI_HASH_CLASS_FAST_UNSALTED, true },
    { TAPI_HASH_SHA256,       "sha256",       TAPI_HASH_CLASS_FAST_UNSALTED, true },
    { TAPI_HASH_SHA384,       "sha384",       TAPI_HASH_CLASS_FAST_UNSALTED, true },
    { TAPI_HASH_SHA512,       "sha512",       TAPI_HASH_CLASS_FAST_UNSALTED, true },
    { TAPI_HASH_SHA3_256,     "sha3_256",     TAPI_HASH_CLASS_FAST_UNSALTED, true },
    { TAPI_HASH_SHA3_512,     "sha3_512",     TAPI_HASH_CLASS_FAST_UNSALTED, true },
    { TAPI_HASH_BLAKE2B,      "blake2b",      TAPI_HASH_CLASS_FAST_UNSALTED, true },
    { TAPI_HASH_CRC32,        "crc32",        TAPI_HASH_CLASS_CHECKSUM,      true },
    { TAPI_HASH_LM,           "lm",           TAPI_HASH_CLASS_FAST_UNSALTED, false },
    { TAPI_HASH_NTLM,         "ntlm",         TAPI_HASH_CLASS_FAST_UNSALTED, false },
    { TAPI_HASH_DESCRYPT,     "descrypt",     TAPI_HASH_CLASS_FAST_SALTED,   false },
    { TAPI_HASH_MD5CRYPT,     "md5crypt",     TAPI_HASH_CLASS_FAST_SALTED,   false },
    { TAPI_HASH_BCRYPT,       "bcrypt",       TAPI_HASH_CLASS_SLOW,          false },
    { TAPI_HASH_SHA256CRYPT,  "sha256crypt",  TAPI_HASH_CLASS_SLOW,          false },
    { TAPI_HASH_SHA512CRYPT,  "sha512crypt",  TAPI_HASH_CLASS_SLOW,          false },
    { TAPI_HASH_YESCRYPT,     "yescrypt",     TAPI_HASH_CLASS_SLOW,          false },
    { TAPI_HASH_PBKDF2_SHA256,"pbkdf2_sha256",TAPI_HASH_CLASS_SLOW,          false },
    { TAPI_HASH_SCRYPT,       "scrypt",       TAPI_HASH_CLASS_SLOW,          false },
    { TAPI_HASH_ARGON2,       "argon2",       TAPI_HASH_CLASS_SLOW,          false },
};

/** Find an algorithm's descriptor, or @c NULL. */
static const hash_alg_desc *
hash_desc(tapi_hash_alg alg)
{
    size_t i;

    for (i = 0; i < TE_ARRAY_LEN(hash_algs); i++)
    {
        if (hash_algs[i].alg == alg)
            return &hash_algs[i];
    }

    return NULL;
}

/** The openssl @c dgst spelling of a plain digest, or @c NULL. */
static const char *
hash_openssl_dgst(tapi_hash_alg alg)
{
    switch (alg)
    {
        case TAPI_HASH_MD5:      return "md5";
        case TAPI_HASH_SHA1:     return "sha1";
        case TAPI_HASH_SHA224:   return "sha224";
        case TAPI_HASH_SHA256:   return "sha256";
        case TAPI_HASH_SHA384:   return "sha384";
        case TAPI_HASH_SHA512:   return "sha512";
        case TAPI_HASH_SHA3_256: return "sha3-256";
        case TAPI_HASH_SHA3_512: return "sha3-512";
        case TAPI_HASH_BLAKE2B:  return "blake2b512";
        default:                 return NULL;
    }
}

/** The mkpasswd @c -m method for a crypt(3) scheme, or @c NULL. */
static const char *
hash_mkpasswd_method(tapi_hash_alg alg)
{
    switch (alg)
    {
        case TAPI_HASH_DESCRYPT:    return "descrypt";
        case TAPI_HASH_MD5CRYPT:    return "md5crypt";
        case TAPI_HASH_BCRYPT:      return "bcrypt";
        case TAPI_HASH_SHA256CRYPT: return "sha256crypt";
        case TAPI_HASH_SHA512CRYPT: return "sha512crypt";
        case TAPI_HASH_YESCRYPT:    return "yescrypt";
        default:                    return NULL;
    }
}

/* See description in tapi_hash.h */
const char *
tapi_hash_alg2str(tapi_hash_alg alg)
{
    const hash_alg_desc *d = hash_desc(alg);

    return d != NULL ? d->name : "none";
}

/* See description in tapi_hash.h */
tapi_hash_alg
tapi_hash_str2alg(const char *name)
{
    size_t i;

    if (name == NULL)
        return TAPI_HASH_NONE;

    for (i = 0; i < TE_ARRAY_LEN(hash_algs); i++)
    {
        if (strcasecmp(name, hash_algs[i].name) == 0)
            return hash_algs[i].alg;
    }

    if (strcasecmp(name, "sha-1") == 0)
        return TAPI_HASH_SHA1;
    if (strcasecmp(name, "sha-256") == 0)
        return TAPI_HASH_SHA256;
    if (strcasecmp(name, "sha-512") == 0)
        return TAPI_HASH_SHA512;
    if (strcasecmp(name, "argon2id") == 0)
        return TAPI_HASH_ARGON2;

    return TAPI_HASH_NONE;
}

/* See description in tapi_hash.h */
tapi_hash_class
tapi_hash_alg_class(tapi_hash_alg alg)
{
    const hash_alg_desc *d = hash_desc(alg);

    return d != NULL ? d->cls : TAPI_HASH_CLASS_FAST_UNSALTED;
}

/* See description in tapi_hash.h */
bool
tapi_hash_available(tapi_job_factory_t *factory, int timeout_ms)
{
    /* openssl is what a plain digest needs; the schemes add their own. */
    return tapi_hash_have_tool(factory, "openssl", timeout_ms);
}

/** CRC32 (IEEE 802.3 / zlib polynomial), computed here on the engine. */
static uint32_t
hash_crc32(const unsigned char *p, size_t n)
{
    uint32_t crc = 0xffffffffu;
    size_t i;
    int k;

    for (i = 0; i < n; i++)
    {
        crc ^= p[i];
        for (k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }

    return crc ^ 0xffffffffu;
}

/** Take the first whitespace-delimited token of @p text into @p dest. */
static bool
hash_first_token(const char *text, te_string *dest)
{
    size_t n;

    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n')
        text++;
    n = strcspn(text, " \t\r\n");
    if (n == 0)
        return false;

    te_string_append(dest, "%.*s", (int)n, text);
    return true;
}

/** Run "openssl dgst" over @p msg_file, optionally loading the legacy provider. */
static te_errno
hash_openssl_run(tapi_job_factory_t *factory, const char *ossl,
                 bool legacy, const char *msg_file, int timeout_ms,
                 te_string *hash)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    tapi_hash_arg(&args, "dgst");
    if (legacy)
    {
        tapi_hash_arg(&args, "-provider");
        tapi_hash_arg(&args, "legacy");
        tapi_hash_arg(&args, "-provider");
        tapi_hash_arg(&args, "default");
    }
    tapi_hash_arg(&args, "-%s", ossl);
    tapi_hash_arg(&args, "-r");
    tapi_hash_arg(&args, "%s", msg_file);

    rc = tapi_hash_sh(factory, "openssl", &args, timeout_ms, &out, &out,
                      &code);
    if (rc == 0 && code == TAPI_HASH_EXIT_NOT_FOUND)
        rc = TE_RC(TE_TAPI, TE_ENOSYS);
    else if (rc == 0 && code != 0)
        rc = TE_RC(TE_TAPI, TE_EFAIL);
    else if (rc == 0 && !hash_first_token(te_string_value(&out), hash))
        rc = TE_RC(TE_TAPI, TE_EPROTO);

    te_vec_deep_free(&args);
    te_string_free(&out);

    return rc;
}

/** Compute a plain digest (openssl), NTLM (openssl md4) or CRC32 (here). */
static te_errno
hash_compute_digest(tapi_job_factory_t *factory, tapi_hash_alg alg,
                    const void *data, size_t len, int timeout_ms,
                    te_string *hash)
{
    te_string msg_file = TE_STRING_INIT;
    te_errno rc;

    if (alg == TAPI_HASH_CRC32)
    {
        te_string_append(hash, "%08x", hash_crc32(data, len));
        return 0;
    }

    if (alg == TAPI_HASH_NTLM)
    {
        /*
         * NTLM is MD4 of the UTF-16LE password. The conversion here is
         * the ASCII/Latin-1 one (each byte, then a zero byte); a
         * non-ASCII password would need a real UTF-8 to UTF-16LE step.
         * MD4 is legacy in OpenSSL 3, so the plain run is tried first
         * and the legacy provider only if it fails - which also works
         * on an OpenSSL 1.1 that has no -provider option.
         */
        unsigned char *u16 = TE_ALLOC(len * 2 + 1);
        size_t i;

        for (i = 0; i < len; i++)
            u16[i * 2] = ((const unsigned char *)data)[i];

        rc = tapi_hash_ta_bytes(factory, "-ntlm", u16, len * 2, &msg_file);
        free(u16);
        if (rc == 0)
        {
            rc = hash_openssl_run(factory, "md4", false, msg_file.ptr,
                                  timeout_ms, hash);
            if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_ENOSYS)
            {
                te_string_reset(hash);
                rc = hash_openssl_run(factory, "md4", true, msg_file.ptr,
                                      timeout_ms, hash);
            }
        }
        tapi_hash_ta_unlink(factory, msg_file.ptr);
        return rc;
    }

    /* A plain digest through openssl dgst. */
    rc = tapi_hash_ta_bytes(factory, "-hashmsg", data, len, &msg_file);
    if (rc == 0)
    {
        rc = hash_openssl_run(factory, hash_openssl_dgst(alg), false,
                              msg_file.ptr, timeout_ms, hash);
    }
    tapi_hash_ta_unlink(factory, msg_file.ptr);

    return rc;
}

/* See description in tapi_hash.h */
te_errno
tapi_hash_compute(tapi_job_factory_t *factory, tapi_hash_alg alg,
                  const void *data, size_t len, const void *salt,
                  size_t salt_len, int timeout_ms, te_string *hash)
{
    const hash_alg_desc *d = hash_desc(alg);
    const char *method;
    te_string pw = TE_STRING_INIT;
    te_string pw_file = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    te_vec args = TE_VEC_INIT(char *);
    int code = 0;
    te_errno rc;

    if (d == NULL)
    {
        ERROR("Unknown hash algorithm %d", alg);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    /* Digests, NTLM and CRC32. */
    if (d->is_digest || alg == TAPI_HASH_NTLM)
        return hash_compute_digest(factory, alg, data, len, timeout_ms, hash);

    method = hash_mkpasswd_method(alg);
    if (method == NULL && alg != TAPI_HASH_ARGON2)
    {
        /*
         * PBKDF2 and scrypt have no stock CLI that takes the password
         * off argv, so computing them is refused rather than leaking
         * it; they are still crackable through hashcat/john.
         */
        ERROR("Computing %s without a helper is not supported; "
              "it can still be cracked", d->name);
        return TE_RC(TE_TAPI, TE_EOPNOTSUPP);
    }

    /* The password is a file fed on stdin, never on argv. */
    te_string_append(&pw, "%.*s", (int)len, (const char *)data);
    rc = tapi_hash_ta_file(factory, "-pw", &pw, &pw_file);
    if (rc != 0)
        goto out;

    if (method != NULL)
    {
        tapi_hash_arg(&args, "-m");
        tapi_hash_arg(&args, "%s", method);
        if (salt != NULL)
        {
            tapi_hash_arg(&args, "-S");
            tapi_hash_arg(&args, "%.*s", (int)salt_len, (const char *)salt);
        }
        rc = tapi_hash_sh_infile(factory, "mkpasswd", &args, pw_file.ptr,
                                 timeout_ms, &out, &out, &code);
    }
    else
    {
        /* argon2 <salt> -id -e : salt is a positional, min 8 bytes. */
        if (salt != NULL && salt_len >= 8)
            tapi_hash_arg(&args, "%.*s", (int)salt_len, (const char *)salt);
        else
            tapi_hash_arg(&args, "tsfhashsalt");
        tapi_hash_arg(&args, "-id");
        tapi_hash_arg(&args, "-e");
        rc = tapi_hash_sh_infile(factory, "argon2", &args, pw_file.ptr,
                                 timeout_ms, &out, &out, &code);
    }

    if (rc == 0 && code == TAPI_HASH_EXIT_NOT_FOUND)
        rc = TE_RC(TE_TAPI, TE_ENOSYS);
    else if (rc == 0 && code != 0)
        rc = TE_RC(TE_TAPI, TE_EFAIL);
    else if (rc == 0 && !hash_first_token(te_string_value(&out), hash))
        rc = TE_RC(TE_TAPI, TE_EPROTO);

out:
    tapi_hash_ta_unlink(factory, pw_file.ptr);
    te_vec_deep_free(&args);
    te_string_free(&pw);
    te_string_free(&pw_file);
    te_string_free(&out);

    return rc;
}

/* See description in tapi_hash.h */
te_errno
tapi_hash_compute_file(tapi_job_factory_t *factory, tapi_hash_alg alg,
                       const char *path, int timeout_ms, te_string *hash)
{
    const char *ossl = hash_openssl_dgst(alg);

    if (alg == TAPI_HASH_CRC32)
    {
        ERROR("CRC32 of a file on the agent is not supported here");
        return TE_RC(TE_TAPI, TE_EOPNOTSUPP);
    }
    if (ossl == NULL)
    {
        ERROR("%s is not a plain digest a file can be hashed with",
              tapi_hash_alg2str(alg));
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    return hash_openssl_run(factory, ossl, false, path, timeout_ms, hash);
}

/** Is @p s non-empty and all hex? */
static bool
hash_is_hex(const char *s)
{
    if (s == NULL || *s == '\0')
        return false;

    for (; *s != '\0'; s++)
    {
        if (strchr("0123456789abcdefABCDEF", *s) == NULL)
            return false;
    }

    return true;
}

/** Append an algorithm to the candidate vector. */
static void
hash_add(te_vec *algs, tapi_hash_alg alg)
{
    TE_VEC_APPEND(algs, alg);
}

/* See description in tapi_hash.h */
te_errno
tapi_hash_identify(tapi_job_factory_t *factory, const char *hash,
                   int timeout_ms, te_vec *algs)
{
    UNUSED(factory);
    UNUSED(timeout_ms);

    if (hash == NULL || algs == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    if (strncmp(hash, "$6$", 3) == 0)
        hash_add(algs, TAPI_HASH_SHA512CRYPT);
    else if (strncmp(hash, "$5$", 3) == 0)
        hash_add(algs, TAPI_HASH_SHA256CRYPT);
    else if (strncmp(hash, "$1$", 3) == 0)
        hash_add(algs, TAPI_HASH_MD5CRYPT);
    else if (strncmp(hash, "$2a$", 4) == 0 || strncmp(hash, "$2b$", 4) == 0 ||
             strncmp(hash, "$2y$", 4) == 0)
        hash_add(algs, TAPI_HASH_BCRYPT);
    else if (strncmp(hash, "$y$", 3) == 0)
        hash_add(algs, TAPI_HASH_YESCRYPT);
    else if (strncmp(hash, "$argon2", 7) == 0)
        hash_add(algs, TAPI_HASH_ARGON2);
    else if (strncmp(hash, "$scrypt$", 8) == 0)
        hash_add(algs, TAPI_HASH_SCRYPT);
    else if (hash_is_hex(hash))
    {
        switch (strlen(hash))
        {
            case 8:
                hash_add(algs, TAPI_HASH_CRC32);
                break;
            case 32:
                hash_add(algs, TAPI_HASH_MD5);
                hash_add(algs, TAPI_HASH_NTLM);
                hash_add(algs, TAPI_HASH_LM);
                break;
            case 40:
                hash_add(algs, TAPI_HASH_SHA1);
                break;
            case 56:
                hash_add(algs, TAPI_HASH_SHA224);
                break;
            case 64:
                hash_add(algs, TAPI_HASH_SHA256);
                hash_add(algs, TAPI_HASH_SHA3_256);
                break;
            case 96:
                hash_add(algs, TAPI_HASH_SHA384);
                break;
            case 128:
                hash_add(algs, TAPI_HASH_SHA512);
                hash_add(algs, TAPI_HASH_SHA3_512);
                hash_add(algs, TAPI_HASH_BLAKE2B);
                break;
            default:
                break;
        }
    }

    return 0;
}
