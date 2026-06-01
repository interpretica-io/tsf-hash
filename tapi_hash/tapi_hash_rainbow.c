/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Rainbow-table lookup with RainbowCrack
 *
 * @c rcrack is pointed at a directory of tables and given the hash; it
 * prints, among a status summary, the plaintext it recovered. The
 * plaintext is parsed out and returned to the caller, never logged.
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
#include "tapi_hash_rainbow.h"
#include "tapi_hash_internal.h"

/* See description in tapi_hash_rainbow.h */
bool
tapi_hash_rainbow_available(tapi_job_factory_t *factory,
                            tapi_hash_rainbow_backend backend, int timeout_ms)
{
    UNUSED(backend);
    return tapi_hash_have_tool(factory, "rcrack", timeout_ms);
}

/**
 * Pull the plaintext out of an rcrack result line for @p hash.
 *
 * rcrack prints a per-hash line; across versions it has been both
 * "<hash>  <hex>  <plaintext>" (tab or space separated) and
 * "plaintext of <hash> is <plaintext>". Both are handled: the "is "
 * form first, then the field after the hash.
 */
static bool
rainbow_parse(const char *out, const char *hash, te_string *plain)
{
    const char *line;

    for (line = out; line != NULL && *line != '\0'; )
    {
        const char *nl = strchr(line, '\n');
        size_t len = nl != NULL ? (size_t)(nl - line) : strlen(line);
        char buf[1024];

        if (len < sizeof(buf))
        {
            const char *is;

            te_strlcpy(buf, line, len + 1);

            is = strstr(buf, " is ");
            if (is != NULL && strstr(buf, hash) != NULL)
            {
                const char *v = is + strlen(" is ");
                size_t n = strcspn(v, "\r\n");

                if (n != 0 && strncmp(v, "not found", 9) != 0)
                {
                    te_string_append(plain, "%.*s", (int)n, v);
                    return true;
                }
            }
            else if (strstr(buf, hash) != NULL)
            {
                const char *v = buf + strlen(hash);

                while (*v == ' ' || *v == '\t' || *v == ':')
                    v++;
                /* Skip the intermediate hex field, if any. */
                if (strchr(v, ' ') != NULL || strchr(v, '\t') != NULL)
                {
                    const char *sp = v + strcspn(v, " \t");

                    while (*sp == ' ' || *sp == '\t')
                        sp++;
                    if (*sp != '\0')
                        v = sp;
                }
                {
                    size_t n = strcspn(v, "\r\n");

                    if (n != 0)
                    {
                        te_string_append(plain, "%.*s", (int)n, v);
                        return true;
                    }
                }
            }
        }

        line = nl != NULL ? nl + 1 : NULL;
    }

    return false;
}

/* See description in tapi_hash_rainbow.h */
te_errno
tapi_hash_rainbow_lookup(tapi_job_factory_t *factory,
                         tapi_hash_rainbow_backend backend,
                         const char *tables_dir, tapi_hash_alg alg,
                         const char *hash, int timeout_ms,
                         tapi_hash_crack_result *result)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    UNUSED(backend);
    UNUSED(alg);

    if (tables_dir == NULL || hash == NULL || result == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    memset(result, 0, sizeof(*result));

    if (!tapi_hash_have_tool(factory, "rcrack", timeout_ms))
    {
        ERROR("There is no rcrack on the agent");
        return TE_RC(TE_TAPI, TE_ENOSYS);
    }

    /* rcrack <tables_dir> -h <hash>: the hash is not a secret, the plain is. */
    tapi_hash_arg(&args, "%s", tables_dir);
    tapi_hash_arg(&args, "-h");
    tapi_hash_arg(&args, "%s", hash);

    rc = tapi_hash_sh(factory, "rcrack", &args, timeout_ms, &out, &out, &code);
    if (rc == 0 && code == TAPI_HASH_EXIT_NOT_FOUND)
    {
        rc = TE_RC(TE_TAPI, TE_ENOSYS);
        goto out;
    }
    if (rc != 0)
        goto out;

    result->backend = TAPI_HASH_CRACK_AUTO;
    if (rainbow_parse(te_string_value(&out), hash, &result->plaintext))
        result->cracked = true;

out:
    te_vec_deep_free(&args);
    te_string_free(&out);

    if (rc != 0)
        tapi_hash_crack_result_free(result);

    return rc;
}
