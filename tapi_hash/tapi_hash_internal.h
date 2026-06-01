/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Hash TAPI: internal helpers
 *
 * Internal to tsf-hash; not installed.
 */

#ifndef __TSF_TAPI_HASH_INTERNAL_H__
#define __TSF_TAPI_HASH_INTERNAL_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Exit status of a POSIX shell that could not find the program. */
#define TAPI_HASH_EXIT_NOT_FOUND 127

/** Append one argument to a vector, taking ownership of it. */
extern void tapi_hash_arg(te_vec *args, const char *fmt, ...)
    TE_LIKE_PRINTF(2, 3);

/**
 * Run a tool on a POSIX agent and wait for it.
 *
 * The job gets a fixed @c PATH with the sbin directories and the common
 * cracker install prefixes, and @c LC_ALL=C so the tools print the
 * English the parsers read. The program is run through @c /bin/sh
 * because TE starts a job with @c execvpe(), which looks the program up
 * in the agent's @c PATH and not the job's.
 *
 * A secret - a password guessed, a message being hashed, a wordlist -
 * never goes on the command line: it is written to a file on the agent
 * and the tool is pointed at the file. What is on @c argv is visible to
 * anyone running @c ps on the agent.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  program      Program name.
 * @param[in]  args         Arguments after @c argv[0].
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] out          Standard output, or @c NULL.
 * @param[out] err          Standard error, or @c NULL.
 * @param[out] exit_code    Exit status, or @c NULL; @c -1 for a signal
 *                          and @ref TAPI_HASH_EXIT_NOT_FOUND when the
 *                          program is not installed.
 *
 * @return Status code of running the tool, not of the tool.
 */
extern te_errno tapi_hash_sh(tapi_job_factory_t *factory, const char *program,
                             const te_vec *args, int timeout_ms,
                             te_string *out, te_string *err, int *exit_code);

/**
 * Run the bundled @c python3 helper with @p args.
 *
 * The helper is put on the agent once per call under its temporary
 * directory and removed again. It is the breadth of algorithms for a
 * digest and the identifier for a hash string. A message it hashes is
 * passed as the path of a file the caller wrote, never on @c argv.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  args         Arguments after the script path.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] out          Standard output.
 * @param[out] exit_code    Exit status, or @c NULL.
 *
 * @return Status code.
 * @retval TE_ENOSYS        There is no @c python3 on the agent.
 */
extern te_errno tapi_hash_python(tapi_job_factory_t *factory,
                                 const te_vec *args, int timeout_ms,
                                 te_string *out, int *exit_code);

/** The bundled helper's source, defined once in tapi_hash_cmd.c. */
extern const char tapi_hash_helper_py[];

/** The agent a factory runs on, for putting files there. */
extern const char *tapi_hash_factory_ta(tapi_job_factory_t *factory);

/**
 * Write @p data to a fresh file under the agent's temporary directory.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  suffix       A suffix for the name, e.g. @c ".hash".
 * @param[in]  data         The bytes, or @c NULL for an empty file.
 * @param[out] path         String to put the created path in.
 *
 * @return Status code.
 */
extern te_errno tapi_hash_ta_file(tapi_job_factory_t *factory,
                                  const char *suffix, const te_string *data,
                                  te_string *path);

/** Remove a file from the agent, ignoring a failure. */
extern void tapi_hash_ta_unlink(tapi_job_factory_t *factory,
                                const char *path);

/**
 * Read a text file from the agent into a string.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  path         Path on the agent.
 * @param[out] dest         String to append the contents to.
 *
 * @return Status code.
 * @retval TE_ENOENT        There is no such file (nothing was cracked).
 */
extern te_errno tapi_hash_read_ta_text(tapi_job_factory_t *factory,
                                       const char *path, te_string *dest);

/** Is @p program on the agent's @c PATH? */
extern bool tapi_hash_have_tool(tapi_job_factory_t *factory,
                                const char *program, int timeout_ms);

/** Append @p len bytes of @p data to @p dest as lowercase hex. */
extern void tapi_hash_hex(te_string *dest, const void *data, size_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_HASH_INTERNAL_H__ */
