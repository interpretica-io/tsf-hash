/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Hashing: algorithms, computing a digest, identifying one
 *
 * The breadth of algorithms is the bundled @c python3 helper, run on
 * the agent. A message to hash is written to a file on the agent and
 * the helper is pointed at it, so nothing being hashed is on @c argv.
 */

#define TE_LGR_USER "TAPI HASH"

#include "te_config.h"

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

    /* A few aliases the tools use. */
    if (strcasecmp(name, "sha-1") == 0)
        return TAPI_HASH_SHA1;
    if (strcasecmp(name, "sha-256") == 0)
        return TAPI_HASH_SHA256;
    if (strcasecmp(name, "sha-512") == 0)
        return TAPI_HASH_SHA512;
    if (strcasecmp(name, "md5crypt") == 0 || strcasecmp(name, "md5-crypt") == 0)
        return TAPI_HASH_MD5CRYPT;
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
    return tapi_hash_have_tool(factory, "python3", timeout_ms);
}

/** Read the "hash <value>" line the helper printed. */
static te_errno
hash_read_result(const char *out, te_string *hash)
{
    const char *line = strstr(out, "hash ");

    if (line != NULL && (line == out || line[-1] == '\n'))
    {
        const char *v = line + strlen("hash ");
        size_t n = strcspn(v, "\r\n");

        te_string_append(hash, "%.*s", (int)n, v);
        return 0;
    }

    if (strstr(out, "unsupported ") != NULL)
        return TE_RC(TE_TAPI, TE_EOPNOTSUPP);

    return TE_RC(TE_TAPI, TE_EPROTO);
}

/* See description in tapi_hash.h */
te_errno
tapi_hash_compute(tapi_job_factory_t *factory, tapi_hash_alg alg,
                  const void *data, size_t len, const void *salt,
                  size_t salt_len, int timeout_ms, te_string *hash)
{
    const hash_alg_desc *d = hash_desc(alg);
    te_vec args = TE_VEC_INIT(char *);
    te_string msg_hex = TE_STRING_INIT;
    te_string msg_file = TE_STRING_INIT;
    te_string salt_arg = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    if (d == NULL)
    {
        ERROR("Unknown hash algorithm %d", alg);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    /* The message goes to a file, hex-encoded, never on argv. */
    tapi_hash_hex(&msg_hex, data, len);
    rc = tapi_hash_ta_file(factory, "-hashmsg", &msg_hex, &msg_file);
    if (rc != 0)
        goto out;

    tapi_hash_arg(&args, "compute");
    tapi_hash_arg(&args, "%s", d->name);
    tapi_hash_arg(&args, "%s", msg_file.ptr);
    if (salt != NULL)
    {
        /*
         * A KDF wants raw salt bytes, so they go as hex; a crypt(3)
         * scheme wants a setting string, so it goes verbatim.
         */
        if (alg == TAPI_HASH_PBKDF2_SHA256 || alg == TAPI_HASH_SCRYPT)
            tapi_hash_hex(&salt_arg, salt, salt_len);
        else
            te_string_append(&salt_arg, "%.*s", (int)salt_len,
                             (const char *)salt);
        tapi_hash_arg(&args, "%s", salt_arg.ptr);
    }

    rc = tapi_hash_python(factory, &args, timeout_ms, &out, &code);
    if (rc == 0)
        rc = hash_read_result(te_string_value(&out), hash);

out:
    tapi_hash_ta_unlink(factory, msg_file.ptr);
    te_vec_deep_free(&args);
    te_string_free(&msg_hex);
    te_string_free(&msg_file);
    te_string_free(&salt_arg);
    te_string_free(&out);

    return rc;
}

/* See description in tapi_hash.h */
te_errno
tapi_hash_compute_file(tapi_job_factory_t *factory, tapi_hash_alg alg,
                       const char *path, int timeout_ms, te_string *hash)
{
    const hash_alg_desc *d = hash_desc(alg);
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    if (d == NULL || !d->is_digest)
    {
        ERROR("%s is not a plain digest a file can be hashed with",
              tapi_hash_alg2str(alg));
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    /*
     * The helper reads the message as a hex file; a raw file is hashed
     * by pointing the helper at a small wrapper is overkill, so this
     * uses the stock digesting tools instead when they are the exact
     * algorithm, falling back to nothing for the SHA-3/BLAKE2 family a
     * bare coreutils may lack. For a first cut it drives openssl, which
     * covers the whole digest set on one command.
     */
    tapi_hash_arg(&args, "dgst");
    tapi_hash_arg(&args, "-%s", d->name);
    tapi_hash_arg(&args, "-r");
    tapi_hash_arg(&args, "%s", path);

    rc = tapi_hash_sh(factory, "openssl", &args, timeout_ms, &out, &out,
                      &code);
    if (rc == 0 && code == TAPI_HASH_EXIT_NOT_FOUND)
        rc = TE_RC(TE_TAPI, TE_ENOSYS);
    if (rc == 0 && code == 0)
    {
        const char *text = te_string_value(&out);
        size_t n = strcspn(text, " \t\r\n");

        if (n == 0)
            rc = TE_RC(TE_TAPI, TE_EPROTO);
        else
            te_string_append(hash, "%.*s", (int)n, text);
    }
    else if (rc == 0)
    {
        rc = TE_RC(TE_TAPI, TE_EFAIL);
    }

    te_vec_deep_free(&args);
    te_string_free(&out);

    return rc;
}

/* See description in tapi_hash.h */
te_errno
tapi_hash_identify(tapi_job_factory_t *factory, const char *hash,
                   int timeout_ms, te_vec *algs)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    const char *line;
    int code = 0;
    te_errno rc;

    if (hash == NULL || algs == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    tapi_hash_arg(&args, "identify");
    tapi_hash_arg(&args, "%s", hash);

    rc = tapi_hash_python(factory, &args, timeout_ms, &out, &code);
    if (rc != 0)
        goto out;

    for (line = te_string_value(&out); line != NULL && *line != '\0'; )
    {
        if (strncmp(line, "alg ", 4) == 0)
        {
            char name[64] = "";
            tapi_hash_alg alg;

            sscanf(line + 4, "%63[^\r\n]", name);
            alg = tapi_hash_str2alg(name);
            if (alg != TAPI_HASH_NONE)
                TE_VEC_APPEND(algs, alg);
        }

        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }

out:
    te_vec_deep_free(&args);
    te_string_free(&out);

    return rc;
}
