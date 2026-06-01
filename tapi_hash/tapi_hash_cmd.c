/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Hash TAPI: running a tool
 *
 * The runner is the same shape as tsf-smb's: a tool is run behind
 * @c /bin/sh so that @c argv[0] is the program and @c "$@" its
 * arguments untouched, with a fixed @c PATH and @c LC_ALL=C given as
 * the whole of the job's environment. Nothing secret goes on @c argv -
 * a message to hash and a password to try are files the caller wrote,
 * and the tool is pointed at the file or fed it on standard input.
 */

#define TE_LGR_USER "TAPI HASH"

#include "te_config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_cfg_base.h"
#include "tapi_file.h"
#include "rcf_api.h"

#include "tapi_devtool_run.h"
#include "tapi_hash_internal.h"

/** Arguments of a command, as a plain vector of strings. */
typedef struct hash_cmd_opt {
    size_t n_args;
    const char **args;
} hash_cmd_opt;

static const tapi_job_opt_bind hash_cmd_binds[] = TAPI_JOB_OPT_SET(
    TAPI_JOB_OPT_ARRAY_PTR(hash_cmd_opt, n_args, args,
        TAPI_JOB_OPT_CONTENT(TAPI_JOB_OPT_STRING, NULL, false))
);

/* See description in tapi_hash_internal.h */
void
tapi_hash_arg(te_vec *args, const char *fmt, ...)
{
    te_string built = TE_STRING_INIT;
    char *arg;
    va_list ap;

    va_start(ap, fmt);
    te_string_append_va(&built, fmt, ap);
    va_end(ap);

    arg = built.ptr != NULL ? built.ptr : TE_STRDUP("");
    TE_VEC_APPEND(args, arg);
}

/** Run @p program with @p args and @p env, and wait for it. */
static te_errno
hash_run(tapi_job_factory_t *factory, const char *name, const char *program,
         const te_vec *args, const char **env, int timeout_ms,
         te_string *out, te_string *err, int *exit_code)
{
    hash_cmd_opt opt = {
        .n_args = te_vec_size(args),
        .args = te_vec_size(args) == 0 ? NULL :
                (const char **)te_vec_get((te_vec *)args, 0),
    };
    tapi_devtool_output output;
    tapi_devtool_run run = TAPI_DEVTOOL_RUN_INIT;
    te_errno rc;

    rc = tapi_devtool_run_init_env(&run, factory, name, program,
                                   hash_cmd_binds, &opt, NULL, env);
    if (rc != 0)
        return rc;

    rc = tapi_devtool_run_start(&run);
    if (rc == 0)
        rc = tapi_devtool_run_wait(&run, timeout_ms);

    if (rc != 0)
    {
        tapi_devtool_run_fini(&run);
        return rc;
    }

    tapi_devtool_run_get_output(&run, &output);

    if (out != NULL && output.out != NULL)
        te_string_append(out, "%s", output.out);
    if (err != NULL && output.err != NULL)
        te_string_append(err, "%s", output.err);

    if (exit_code != NULL)
    {
        *exit_code = output.status.type == TAPI_JOB_STATUS_EXITED ?
                     output.status.value : -1;
    }

    return tapi_devtool_run_fini(&run);
}

/** The environment of every job here: a known PATH and a C locale. */
static void
hash_env(const char **env)
{
    env[0] = "PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:"
             "/usr/local/sbin:/opt/hashcat:/opt/john/run";
    env[1] = "LC_ALL=C";
    env[2] = NULL;
}

/* See description in tapi_hash_internal.h */
te_errno
tapi_hash_sh(tapi_job_factory_t *factory, const char *program,
             const te_vec *args, int timeout_ms, te_string *out,
             te_string *err, int *exit_code)
{
    te_vec sh_args = TE_VEC_INIT(char *);
    const char *env[3];
    char * const *arg;
    te_errno rc;

    hash_env(env);

    tapi_hash_arg(&sh_args, "-c");
    tapi_hash_arg(&sh_args, "exec \"$0\" \"$@\"");
    tapi_hash_arg(&sh_args, "%s", program);
    if (args != NULL)
    {
        TE_VEC_FOREACH((te_vec *)args, arg)
            tapi_hash_arg(&sh_args, "%s", *arg);
    }

    rc = hash_run(factory, program, "/bin/sh", &sh_args, env, timeout_ms,
                  out, err, exit_code);

    te_vec_deep_free(&sh_args);

    return rc;
}

/* See description in tapi_hash_internal.h */
te_errno
tapi_hash_sh_infile(tapi_job_factory_t *factory, const char *program,
                    const te_vec *args, const char *infile, int timeout_ms,
                    te_string *out, te_string *err, int *exit_code)
{
    te_vec sh_args = TE_VEC_INIT(char *);
    const char *env[3];
    char * const *arg;
    te_errno rc;

    hash_env(env);

    /*
     * A POSIX line that takes the input file and the program off the
     * front of the arguments and execs the program with the rest, its
     * standard input redirected from the file. "$0" is a throwaway
     * shell name; "$1" the input file, "$2" the program.
     */
    tapi_hash_arg(&sh_args, "-c");
    tapi_hash_arg(&sh_args,
                  "IN=$1; PROG=$2; shift 2; exec \"$PROG\" \"$@\" <\"$IN\"");
    tapi_hash_arg(&sh_args, "sh");
    tapi_hash_arg(&sh_args, "%s", infile);
    tapi_hash_arg(&sh_args, "%s", program);
    if (args != NULL)
    {
        TE_VEC_FOREACH((te_vec *)args, arg)
            tapi_hash_arg(&sh_args, "%s", *arg);
    }

    rc = hash_run(factory, program, "/bin/sh", &sh_args, env, timeout_ms,
                  out, err, exit_code);

    te_vec_deep_free(&sh_args);

    return rc;
}

/* See description in tapi_hash_internal.h */
const char *
tapi_hash_factory_ta(tapi_job_factory_t *factory)
{
    const char *ta = tapi_job_factory_ta(factory);

    if (ta == NULL)
        ERROR("Cannot determine the agent behind the job factory");

    return ta;
}

/* See description in tapi_hash_internal.h */
te_errno
tapi_hash_ta_file(tapi_job_factory_t *factory, const char *suffix,
                  const te_string *data, te_string *path)
{
    const char *ta = tapi_hash_factory_ta(factory);
    char *tmp_dir;
    te_errno rc;

    if (ta == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    tmp_dir = tapi_cfg_base_get_ta_dir(ta, TAPI_CFG_BASE_TA_DIR_TMP);
    if (tmp_dir == NULL)
        return TE_RC(TE_TAPI, TE_EFAIL);

    tapi_file_make_custom_pathname(path, tmp_dir, suffix);
    free(tmp_dir);

    rc = tapi_file_create_ta(ta, path->ptr, "%.*s",
                             data != NULL ? (int)data->len : 0,
                             data != NULL ? data->ptr : "");
    if (rc != 0)
        ERROR("Failed to write %s on TA %s: %r", path->ptr, ta, rc);

    return rc;
}

/* See description in tapi_hash_internal.h */
te_errno
tapi_hash_ta_bytes(tapi_job_factory_t *factory, const char *suffix,
                   const void *data, size_t len, te_string *path)
{
    const char *ta = tapi_hash_factory_ta(factory);
    char *tmp_dir;
    char *local;
    te_errno rc;

    if (ta == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    /* A binary-safe local file on the engine, then copied to the agent. */
    local = tapi_file_create(len, len != 0 ? (char *)data : (char *)"", false);
    if (local == NULL)
    {
        ERROR("Failed to create a local file for %zu bytes", len);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }

    tmp_dir = tapi_cfg_base_get_ta_dir(ta, TAPI_CFG_BASE_TA_DIR_TMP);
    if (tmp_dir == NULL)
    {
        remove(local);
        free(local);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }
    tapi_file_make_custom_pathname(path, tmp_dir, suffix);
    free(tmp_dir);

    rc = rcf_ta_put_file(ta, 0, local, path->ptr);
    if (rc != 0)
        ERROR("Failed to put %s on TA %s: %r", path->ptr, ta, rc);

    remove(local);
    free(local);

    return rc;
}

/* See description in tapi_hash_internal.h */
void
tapi_hash_ta_unlink(tapi_job_factory_t *factory, const char *path)
{
    const char *ta = tapi_hash_factory_ta(factory);

    if (ta != NULL && path != NULL)
        tapi_file_ta_unlink_fmt(ta, "%s", path);
}

/* See description in tapi_hash_internal.h */
te_errno
tapi_hash_read_ta_text(tapi_job_factory_t *factory, const char *path,
                       te_string *dest)
{
    const char *ta = tapi_hash_factory_ta(factory);
    char *buf = NULL;
    te_errno rc;

    if (ta == NULL || path == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    rc = tapi_file_read_ta(ta, path, &buf);
    if (rc == 0)
    {
        te_string_append(dest, "%s", buf);
        free(buf);
    }

    return rc;
}

/* See description in tapi_hash_internal.h */
bool
tapi_hash_have_tool(tapi_job_factory_t *factory, const char *program,
                    int timeout_ms)
{
    te_vec args = TE_VEC_INIT(char *);
    const char *env[3];
    int code = 0;
    te_errno rc;

    hash_env(env);

    tapi_hash_arg(&args, "-c");
    tapi_hash_arg(&args, "command -v \"$0\" >/dev/null 2>&1");
    tapi_hash_arg(&args, "%s", program);

    rc = hash_run(factory, "command -v", "/bin/sh", &args, env, timeout_ms,
                  NULL, NULL, &code);

    te_vec_deep_free(&args);

    return rc == 0 && code == 0;
}

/* See description in tapi_hash_internal.h */
void
tapi_hash_hex(te_string *dest, const void *data, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    const unsigned char *p = data;
    size_t i;

    for (i = 0; i < len; i++)
    {
        te_string_append(dest, "%c%c", digits[p[i] >> 4],
                         digits[p[i] & 0x0f]);
    }
}
