/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Cracking a hash with hashcat or John the Ripper
 *
 * The hash goes to a file on the agent; the cracker is run against it
 * with the wanted attack, capped by a runtime budget; and the result
 * is read from the tool's own output (hashcat's @c -o file in
 * plaintext-only format, or @c john @c --show). The recovered secret
 * is never on @c argv and never in a log line - it is handed back to
 * the caller in the result.
 *
 * The algorithm maps below cover the common set and are the first
 * place to extend; an algorithm not in a backend's map is refused with
 * @c TE_EOPNOTSUPP rather than guessed at.
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
#include "tapi_hash_crack.h"
#include "tapi_hash_internal.h"

/** hashcat @c -m mode for an algorithm, or @c -1 when unmapped. */
static int
crack_hashcat_mode(tapi_hash_alg alg)
{
    switch (alg)
    {
        case TAPI_HASH_MD5:          return 0;
        case TAPI_HASH_SHA1:         return 100;
        case TAPI_HASH_SHA224:       return 1300;
        case TAPI_HASH_SHA256:       return 1400;
        case TAPI_HASH_SHA384:       return 10800;
        case TAPI_HASH_SHA512:       return 1700;
        case TAPI_HASH_SHA3_256:     return 17400;
        case TAPI_HASH_SHA3_512:     return 17600;
        case TAPI_HASH_BLAKE2B:      return 600;
        case TAPI_HASH_NTLM:         return 1000;
        case TAPI_HASH_LM:           return 3000;
        case TAPI_HASH_DESCRYPT:     return 1500;
        case TAPI_HASH_MD5CRYPT:     return 500;
        case TAPI_HASH_BCRYPT:       return 3200;
        case TAPI_HASH_SHA256CRYPT:  return 7400;
        case TAPI_HASH_SHA512CRYPT:  return 1800;
        case TAPI_HASH_PBKDF2_SHA256:return 10900;
        case TAPI_HASH_SCRYPT:       return 8900;
        case TAPI_HASH_CRC32:        return 11500;
        default:                     return -1;
    }
}

/** John the Ripper @c --format for an algorithm, or @c NULL. */
static const char *
crack_john_format(tapi_hash_alg alg)
{
    switch (alg)
    {
        case TAPI_HASH_MD5:          return "raw-md5";
        case TAPI_HASH_SHA1:         return "raw-sha1";
        case TAPI_HASH_SHA224:       return "raw-sha224";
        case TAPI_HASH_SHA256:       return "raw-sha256";
        case TAPI_HASH_SHA384:       return "raw-sha384";
        case TAPI_HASH_SHA512:       return "raw-sha512";
        case TAPI_HASH_BLAKE2B:      return "raw-blake2";
        case TAPI_HASH_NTLM:         return "nt";
        case TAPI_HASH_LM:           return "lm";
        case TAPI_HASH_DESCRYPT:     return "descrypt";
        case TAPI_HASH_MD5CRYPT:     return "md5crypt";
        case TAPI_HASH_BCRYPT:       return "bcrypt";
        case TAPI_HASH_SHA256CRYPT:  return "sha256crypt";
        case TAPI_HASH_SHA512CRYPT:  return "sha512crypt";
        case TAPI_HASH_YESCRYPT:     return "crypt";
        case TAPI_HASH_PBKDF2_SHA256:return "pbkdf2-hmac-sha256";
        case TAPI_HASH_SCRYPT:       return "scrypt";
        case TAPI_HASH_ARGON2:       return "argon2";
        case TAPI_HASH_CRC32:        return "crc32";
        default:                     return NULL;
    }
}

/** Resolve @ref TAPI_HASH_CRACK_AUTO to whatever the agent has. */
static tapi_hash_crack_backend
crack_resolve(tapi_job_factory_t *factory, tapi_hash_crack_backend backend,
              int timeout_ms)
{
    if (backend != TAPI_HASH_CRACK_AUTO)
        return backend;
    if (tapi_hash_have_tool(factory, "hashcat", timeout_ms))
        return TAPI_HASH_CRACK_HASHCAT;
    if (tapi_hash_have_tool(factory, "john", timeout_ms))
        return TAPI_HASH_CRACK_JOHN;
    return TAPI_HASH_CRACK_AUTO;
}

/* See description in tapi_hash_crack.h */
bool
tapi_hash_crack_available(tapi_job_factory_t *factory,
                          tapi_hash_crack_backend backend, int timeout_ms)
{
    switch (backend)
    {
        case TAPI_HASH_CRACK_HASHCAT:
            return tapi_hash_have_tool(factory, "hashcat", timeout_ms);
        case TAPI_HASH_CRACK_JOHN:
            return tapi_hash_have_tool(factory, "john", timeout_ms);
        default:
            return crack_resolve(factory, TAPI_HASH_CRACK_AUTO, timeout_ms) !=
                   TAPI_HASH_CRACK_AUTO;
    }
}

/** Drive hashcat; @p out_file already exists on the agent. */
static te_errno
crack_hashcat(tapi_job_factory_t *factory, const tapi_hash_crack_spec *spec,
              const char *hash_file, const char *out_file, int timeout_ms,
              tapi_hash_crack_result *result)
{
    int mode = crack_hashcat_mode(spec->alg);
    te_vec args = TE_VEC_INIT(char *);
    te_string plain = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    if (mode < 0)
    {
        ERROR("hashcat has no mapped mode for %s",
              tapi_hash_alg2str(spec->alg));
        return TE_RC(TE_TAPI, TE_EOPNOTSUPP);
    }

    tapi_hash_arg(&args, "-m");
    tapi_hash_arg(&args, "%d", mode);
    tapi_hash_arg(&args, "-a");
    tapi_hash_arg(&args, "%d",
                  spec->attack == TAPI_HASH_ATTACK_MASK ? 3 : 0);
    tapi_hash_arg(&args, "--quiet");
    tapi_hash_arg(&args, "--potfile-disable");
    /* Format 2 writes the plaintext alone, so the secret is all there is. */
    tapi_hash_arg(&args, "--outfile-format");
    tapi_hash_arg(&args, "2");
    tapi_hash_arg(&args, "-o");
    tapi_hash_arg(&args, "%s", out_file);
    if (spec->time_budget_ms > 0)
    {
        tapi_hash_arg(&args, "--runtime");
        tapi_hash_arg(&args, "%d", (spec->time_budget_ms + 999) / 1000);
    }
    tapi_hash_arg(&args, "%s", hash_file);

    switch (spec->attack)
    {
        case TAPI_HASH_ATTACK_MASK:
            if (spec->mask == NULL)
            {
                rc = TE_RC(TE_TAPI, TE_EINVAL);
                goto out;
            }
            tapi_hash_arg(&args, "%s", spec->mask);
            break;
        case TAPI_HASH_ATTACK_RULES:
            if (spec->wordlist == NULL)
            {
                rc = TE_RC(TE_TAPI, TE_EINVAL);
                goto out;
            }
            tapi_hash_arg(&args, "%s", spec->wordlist);
            if (spec->rules != NULL)
            {
                tapi_hash_arg(&args, "-r");
                tapi_hash_arg(&args, "%s", spec->rules);
            }
            break;
        default:
            if (spec->wordlist == NULL)
            {
                rc = TE_RC(TE_TAPI, TE_EINVAL);
                goto out;
            }
            tapi_hash_arg(&args, "%s", spec->wordlist);
            break;
    }

    /*
     * hashcat's exit code says cracked (0) / exhausted (1) / aborted by
     * the runtime cap (2); anything else is a real error. The verdict
     * is the output file, read either way.
     */
    rc = tapi_hash_sh(factory, "hashcat", &args, timeout_ms, NULL, NULL,
                      &code);
    if (rc == 0 && code == TAPI_HASH_EXIT_NOT_FOUND)
    {
        rc = TE_RC(TE_TAPI, TE_ENOSYS);
        goto out;
    }
    if (rc != 0)
        goto out;
    if (code != 0 && code != 1 && code != 2)
        WARN("hashcat exited %d", code);

    rc = tapi_hash_read_ta_text(factory, out_file, &plain);
    if (rc == 0 && plain.len != 0)
    {
        size_t n = strcspn(plain.ptr, "\r\n");

        result->cracked = true;
        te_string_append(&result->plaintext, "%.*s", (int)n, plain.ptr);
    }
    else if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
    {
        rc = 0; /* No output file means nothing cracked. */
    }

out:
    te_vec_deep_free(&args);
    te_string_free(&plain);

    return rc;
}

/** Drive John the Ripper. */
static te_errno
crack_john(tapi_job_factory_t *factory, const tapi_hash_crack_spec *spec,
           const char *hash_file, int timeout_ms,
           tapi_hash_crack_result *result)
{
    const char *format = crack_john_format(spec->alg);
    te_vec args = TE_VEC_INIT(char *);
    te_string show = TE_STRING_INIT;
    const char *sep;
    int code = 0;
    te_errno rc;

    if (spec->alg != TAPI_HASH_NONE && format == NULL)
    {
        ERROR("John has no mapped format for %s",
              tapi_hash_alg2str(spec->alg));
        return TE_RC(TE_TAPI, TE_EOPNOTSUPP);
    }

    if (format != NULL)
        tapi_hash_arg(&args, "--format=%s", format);
    if (spec->time_budget_ms > 0)
        tapi_hash_arg(&args, "--max-run-time=%d",
                      (spec->time_budget_ms + 999) / 1000);

    switch (spec->attack)
    {
        case TAPI_HASH_ATTACK_MASK:
            if (spec->mask != NULL)
                tapi_hash_arg(&args, "--mask=%s", spec->mask);
            else
                tapi_hash_arg(&args, "--incremental");
            break;
        case TAPI_HASH_ATTACK_RULES:
            if (spec->wordlist == NULL)
            {
                rc = TE_RC(TE_TAPI, TE_EINVAL);
                goto out;
            }
            tapi_hash_arg(&args, "--wordlist=%s", spec->wordlist);
            if (spec->rules != NULL)
                tapi_hash_arg(&args, "--rules=%s", spec->rules);
            else
                tapi_hash_arg(&args, "--rules");
            break;
        default:
            if (spec->wordlist == NULL)
            {
                rc = TE_RC(TE_TAPI, TE_EINVAL);
                goto out;
            }
            tapi_hash_arg(&args, "--wordlist=%s", spec->wordlist);
            break;
    }
    tapi_hash_arg(&args, "%s", hash_file);

    rc = tapi_hash_sh(factory, "john", &args, timeout_ms, NULL, NULL, &code);
    if (rc == 0 && code == TAPI_HASH_EXIT_NOT_FOUND)
    {
        rc = TE_RC(TE_TAPI, TE_ENOSYS);
        goto out;
    }
    if (rc != 0)
        goto out;

    /* "john --show" prints "<user>:<plaintext>:..." for each cracked hash. */
    {
        te_vec show_args = TE_VEC_INIT(char *);

        tapi_hash_arg(&show_args, "--show");
        if (format != NULL)
            tapi_hash_arg(&show_args, "--format=%s", format);
        tapi_hash_arg(&show_args, "%s", hash_file);

        rc = tapi_hash_sh(factory, "john", &show_args, timeout_ms, &show,
                          NULL, &code);
        te_vec_deep_free(&show_args);
    }
    if (rc != 0)
        goto out;

    /*
     * The first line is "<user>:<plaintext>:...". The username field is
     * "?" for a bare hash file. Take the second colon-separated field.
     */
    sep = strchr(te_string_value(&show), ':');
    if (sep != NULL)
    {
        const char *p = sep + 1;
        size_t n = strcspn(p, ":\r\n");

        if (n != 0)
        {
            result->cracked = true;
            te_string_append(&result->plaintext, "%.*s", (int)n, p);
        }
    }

out:
    te_vec_deep_free(&args);
    te_string_free(&show);

    return rc;
}

/* See description in tapi_hash_crack.h */
te_errno
tapi_hash_crack(tapi_job_factory_t *factory, const tapi_hash_crack_spec *spec,
                const char *hash, int timeout_ms,
                tapi_hash_crack_result *result)
{
    tapi_hash_crack_backend backend;
    te_string hash_data = TE_STRING_INIT;
    te_string hash_file = TE_STRING_INIT;
    te_string out_file = TE_STRING_INIT;
    te_errno rc;

    if (spec == NULL || hash == NULL || result == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    /* An all-zero te_string is an empty one, so memset is enough here. */
    memset(result, 0, sizeof(*result));

    backend = crack_resolve(factory, spec->backend, timeout_ms);
    if (backend == TAPI_HASH_CRACK_AUTO)
    {
        ERROR("There is no hashcat or john on the agent");
        return TE_RC(TE_TAPI, TE_ENOSYS);
    }
    result->backend = backend;

    te_string_append(&hash_data, "%s\n", hash);
    rc = tapi_hash_ta_file(factory, "-crack.hash", &hash_data, &hash_file);
    if (rc != 0)
        goto out;

    if (backend == TAPI_HASH_CRACK_HASHCAT)
    {
        rc = tapi_hash_ta_file(factory, "-crack.out", NULL, &out_file);
        if (rc == 0)
        {
            rc = crack_hashcat(factory, spec, hash_file.ptr, out_file.ptr,
                               timeout_ms, result);
        }
    }
    else
    {
        rc = crack_john(factory, spec, hash_file.ptr, timeout_ms, result);
    }

out:
    tapi_hash_ta_unlink(factory, hash_file.ptr);
    if (out_file.len != 0)
        tapi_hash_ta_unlink(factory, out_file.ptr);
    te_string_free(&hash_data);
    te_string_free(&hash_file);
    te_string_free(&out_file);

    if (rc != 0)
        tapi_hash_crack_result_free(result);

    return rc;
}

/* See description in tapi_hash_crack.h */
void
tapi_hash_crack_result_free(tapi_hash_crack_result *result)
{
    if (result != NULL)
        te_string_free(&result->plaintext);
}
