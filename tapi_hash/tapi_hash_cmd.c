/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Hash TAPI: running a tool, and the bundled helper
 *
 * The runner is the same shape as tsf-smb's: a tool is run behind
 * @c /bin/sh so that @c argv[0] is the program and @c "$@" its
 * arguments untouched, with a fixed @c PATH and @c LC_ALL=C given as
 * the whole of the job's environment. Nothing secret goes on @c argv -
 * a message to hash, a guessed password and a wordlist are files the
 * caller wrote, and the tool is pointed at the file.
 */

#define TE_LGR_USER "TAPI HASH"

#include "te_config.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_cfg_base.h"
#include "tapi_file.h"

#include "tapi_devtool_run.h"
#include "tapi_hash_internal.h"

/*
 * The bundled helper. One command:
 *
 *   compute <alg> <msgfile> [saltstring] [iters]
 *       prints "hash <hex-or-cryptstring>" or "unsupported <reason>".
 *       The message is the raw bytes of <msgfile>, hex-encoded.
 *   identify <hashstring>
 *       prints one "alg <name>" line per candidate.
 *
 * It uses single quotes throughout and no backslashes, so it embeds as
 * a C string without escaping. crypt(3) schemes need the agent's crypt
 * module; where it is gone (Python 3.13+ dropped it) they answer
 * "unsupported" rather than a wrong hash.
 */
const char tapi_hash_helper_py[] =
"import sys,hashlib,binascii,zlib\n"
"try:\n"
" import crypt\n"
"except Exception:\n"
" crypt=None\n"
"def out(tag,val=''):\n"
" sys.stdout.write(tag+' '+val+'\\n')\n"
"def is_hex(s):\n"
" if not s: return False\n"
" for c in s:\n"
"  if c not in '0123456789abcdefABCDEF': return False\n"
" return True\n"
"def compute(alg,salt,iters,msg):\n"
" plain=['md5','sha1','sha224','sha256','sha384','sha512','sha3_256','sha3_512','blake2b']\n"
" if alg in plain:\n"
"  h=hashlib.new(alg); h.update(msg); out('hash',h.hexdigest()); return\n"
" if alg=='crc32':\n"
"  out('hash','%08x'%(zlib.crc32(msg)&0xffffffff)); return\n"
" if alg=='ntlm':\n"
"  try:\n"
"   pw=msg.decode('utf-8','surrogateescape'); h=hashlib.new('md4'); h.update(pw.encode('utf-16-le')); out('hash',h.hexdigest())\n"
"  except Exception as e:\n"
"   out('unsupported','ntlm: '+str(e))\n"
"  return\n"
" if alg=='pbkdf2_sha256':\n"
"  s=binascii.unhexlify(salt) if salt else b''; n=int(iters) if iters else 100000\n"
"  out('hash',binascii.hexlify(hashlib.pbkdf2_hmac('sha256',msg,s,n)).decode()); return\n"
" if alg=='scrypt':\n"
"  s=binascii.unhexlify(salt) if salt else b''\n"
"  try:\n"
"   out('hash',binascii.hexlify(hashlib.scrypt(msg,salt=s,n=16384,r=8,p=1)).decode())\n"
"  except Exception as e:\n"
"   out('unsupported','scrypt: '+str(e))\n"
"  return\n"
" methods={'descrypt':'CRYPT','md5crypt':'MD5','sha256crypt':'SHA256','sha512crypt':'SHA512','bcrypt':'BLOWFISH','yescrypt':'YESCRYPT'}\n"
" if alg in methods:\n"
"  if crypt is None:\n"
"   out('unsupported',alg+': no crypt module on this python'); return\n"
"  try:\n"
"   pw=msg.decode('utf-8','surrogateescape')\n"
"   if salt:\n"
"    setting=salt\n"
"   else:\n"
"    setting=crypt.mksalt(getattr(crypt,'METHOD_'+methods[alg]))\n"
"   r=crypt.crypt(pw,setting)\n"
"   if r is None:\n"
"    out('unsupported',alg+': crypt returned None')\n"
"   else:\n"
"    out('hash',r)\n"
"  except Exception as e:\n"
"   out('unsupported',alg+': '+str(e))\n"
"  return\n"
" out('unsupported',alg+': not known to this helper')\n"
"def identify(s):\n"
" c=[]\n"
" if s.startswith('$6$'): c.append('sha512crypt')\n"
" elif s.startswith('$5$'): c.append('sha256crypt')\n"
" elif s.startswith('$1$'): c.append('md5crypt')\n"
" elif s.startswith('$2a$') or s.startswith('$2b$') or s.startswith('$2y$'): c.append('bcrypt')\n"
" elif s.startswith('$y$'): c.append('yescrypt')\n"
" elif s.startswith('$argon2'): c.append('argon2')\n"
" elif s.startswith('$scrypt$'): c.append('scrypt')\n"
" elif is_hex(s):\n"
"  n=len(s)\n"
"  if n==8: c.append('crc32')\n"
"  elif n==32: c+=['md5','ntlm','lm']\n"
"  elif n==40: c.append('sha1')\n"
"  elif n==56: c.append('sha224')\n"
"  elif n==64: c+=['sha256','sha3_256']\n"
"  elif n==96: c.append('sha384')\n"
"  elif n==128: c+=['sha512','sha3_512','blake2b']\n"
" for a in c: out('alg',a)\n"
"def main():\n"
" if len(sys.argv)<2: out('unsupported','no command'); return 2\n"
" cmd=sys.argv[1]\n"
" if cmd=='identify':\n"
"  if len(sys.argv)<3: out('unsupported','identify needs a hash'); return 2\n"
"  identify(sys.argv[2]); return 0\n"
" if cmd=='compute':\n"
"  alg=sys.argv[2] if len(sys.argv)>2 else ''\n"
"  msgfile=sys.argv[3] if len(sys.argv)>3 else ''\n"
"  salt=sys.argv[4] if len(sys.argv)>4 and sys.argv[4] else None\n"
"  iters=sys.argv[5] if len(sys.argv)>5 and sys.argv[5] else None\n"
"  try:\n"
"   raw=open(msgfile,'rb').read().strip()\n"
"   msg=binascii.unhexlify(raw)\n"
"  except Exception as e:\n"
"   out('unsupported','bad input: '+str(e)); return 2\n"
"  compute(alg,salt,iters,msg); return 0\n"
" out('unsupported','unknown command '+cmd); return 2\n"
"sys.exit(main())\n";

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
static const char *
hash_env(int index)
{
    static const char *env[] = {
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:"
        "/opt/hashcat:/opt/john/run",
        "LC_ALL=C",
        NULL,
    };

    return env[index];
}

/* See description in tapi_hash_internal.h */
te_errno
tapi_hash_sh(tapi_job_factory_t *factory, const char *program,
             const te_vec *args, int timeout_ms, te_string *out,
             te_string *err, int *exit_code)
{
    te_vec sh_args = TE_VEC_INIT(char *);
    const char *env[] = { hash_env(0), hash_env(1), NULL };
    char * const *arg;
    te_errno rc;

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
te_errno
tapi_hash_python(tapi_job_factory_t *factory, const te_vec *args,
                 int timeout_ms, te_string *out, int *exit_code)
{
    const char *ta = tapi_hash_factory_ta(factory);
    te_vec py_args = TE_VEC_INIT(char *);
    te_string script = TE_STRING_INIT;
    te_string helper = TE_STRING_INIT;
    char *tmp_dir;
    char * const *arg;
    int code = 0;
    te_errno rc;

    if (ta == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    tmp_dir = tapi_cfg_base_get_ta_dir(ta, TAPI_CFG_BASE_TA_DIR_TMP);
    if (tmp_dir == NULL)
        return TE_RC(TE_TAPI, TE_EFAIL);
    tapi_file_make_custom_pathname(&script, tmp_dir, "-hashhelper.py");
    free(tmp_dir);

    te_string_append(&helper, "%s", tapi_hash_helper_py);
    rc = tapi_file_create_ta(ta, script.ptr, "%s", helper.ptr);
    if (rc != 0)
    {
        ERROR("Failed to put the hash helper on TA %s: %r", ta, rc);
        goto out;
    }

    tapi_hash_arg(&py_args, "%s", script.ptr);
    if (args != NULL)
    {
        TE_VEC_FOREACH((te_vec *)args, arg)
            tapi_hash_arg(&py_args, "%s", *arg);
    }

    rc = tapi_hash_sh(factory, "python3", &py_args, timeout_ms, out, NULL,
                      &code);
    if (rc == 0 && code == TAPI_HASH_EXIT_NOT_FOUND)
        rc = TE_RC(TE_TAPI, TE_ENOSYS);
    if (exit_code != NULL)
        *exit_code = code;

out:
    tapi_hash_ta_unlink(factory, script.ptr);
    te_vec_deep_free(&py_args);
    te_string_free(&script);
    te_string_free(&helper);

    return rc;
}

/* See description in tapi_hash_internal.h */
bool
tapi_hash_have_tool(tapi_job_factory_t *factory, const char *program,
                    int timeout_ms)
{
    te_vec args = TE_VEC_INIT(char *);
    const char *env[] = { hash_env(0), hash_env(1), NULL };
    int code = 0;
    te_errno rc;

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
