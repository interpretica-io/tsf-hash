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
 * Run a tool with its standard input redirected from a file on the
 * agent.
 *
 * This is how a secret reaches a tool that reads its input on stdin
 * (@c mkpasswd, @c argon2) without being on @c argv: the caller writes
 * it to a file and it is fed in as @c "< file". The redirection is done
 * by a POSIX @c /bin/sh line, so @p infile and @p program are ordinary
 * words in it, not the shell's own.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  program      Program name.
 * @param[in]  args         Arguments after @c argv[0].
 * @param[in]  infile       File on the agent to feed as standard input.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] out          Standard output, or @c NULL.
 * @param[out] err          Standard error, or @c NULL.
 * @param[out] exit_code    Exit status, or @c NULL.
 *
 * @return Status code.
 */
extern te_errno tapi_hash_sh_infile(tapi_job_factory_t *factory,
                                    const char *program, const te_vec *args,
                                    const char *infile, int timeout_ms,
                                    te_string *out, te_string *err,
                                    int *exit_code);

/** The agent a factory runs on, for putting files there. */
extern const char *tapi_hash_factory_ta(tapi_job_factory_t *factory);

/**
 * Write text to a fresh file under the agent's temporary directory.
 *
 * For the crackers' hash files and password files, which are text.
 * Binary bytes go through tapi_hash_ta_bytes() instead, which does not
 * stop at a NUL.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  suffix       A suffix for the name, e.g. @c ".hash".
 * @param[in]  data         The text, or @c NULL for an empty file.
 * @param[out] path         String to put the created path in.
 *
 * @return Status code.
 */
extern te_errno tapi_hash_ta_file(tapi_job_factory_t *factory,
                                  const char *suffix, const te_string *data,
                                  te_string *path);

/**
 * Write raw bytes to a fresh file under the agent's temporary directory.
 *
 * Binary-safe, unlike tapi_hash_ta_file(): the bytes go to a local file
 * on the engine and are copied to the agent, so an embedded NUL is kept.
 * This is what a message being hashed is written with.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  suffix       A suffix for the name.
 * @param[in]  data         The bytes (may be @c NULL when @p len is 0).
 * @param[in]  len          How many bytes.
 * @param[out] path         String to put the created agent path in.
 *
 * @return Status code.
 */
extern te_errno tapi_hash_ta_bytes(tapi_job_factory_t *factory,
                                   const char *suffix, const void *data,
                                   size_t len, te_string *path);

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
