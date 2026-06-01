/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Looking a hash up in a precomputed table
 *
 * @defgroup tapi_hash_rainbow Rainbow tables
 * @ingroup tapi_hash
 * @{
 *
 * A hash looked up in a set of precomputed (rainbow) tables, rather
 * than searched for: the work was done ahead of time and stored, and a
 * lookup trades disk for the time a fresh crack would take. RainbowCrack
 * (@c rcrack) is the backend; the tables are a directory the agent can
 * read, made or downloaded ahead of the test.
 *
 * A found preimage is a recovered credential, and the same rule holds:
 * the plaintext comes back to the caller, never into a log verdict.
 *
 * The result is the same #tapi_hash_crack_result a live crack returns -
 * a table lookup is a crack whose work was precomputed - so the two are
 * read the same way.
 *
 * @code
 * tapi_hash_crack_result result;
 *
 * CHECK_RC(tapi_hash_rainbow_lookup(factory, TAPI_HASH_RAINBOW_AUTO,
 *                                   "/srv/tables/ntlm", TAPI_HASH_NTLM,
 *                                   hash, 120000, &result));
 * @endcode
 */

#ifndef __TSF_TAPI_HASH_RAINBOW_H__
#define __TSF_TAPI_HASH_RAINBOW_H__

#include "te_defs.h"
#include "te_errno.h"
#include "tapi_job.h"

#include "tapi_hash.h"
#include "tapi_hash_crack.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Which table engine to drive. */
typedef enum tapi_hash_rainbow_backend {
    /** Ask the agent which of the others it has. */
    TAPI_HASH_RAINBOW_AUTO = 0,
    /** RainbowCrack (@c rcrack). */
    TAPI_HASH_RAINBOW_RCRACK,
} tapi_hash_rainbow_backend;

/**
 * Is a table engine on the agent?
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_HASH_RAINBOW_AUTO.
 * @param timeout_ms    Timeout, ms.
 *
 * @return @c true when the backend is there.
 */
extern bool tapi_hash_rainbow_available(tapi_job_factory_t *factory,
                                        tapi_hash_rainbow_backend backend,
                                        int timeout_ms);

/**
 * Look a hash up in a directory of precomputed tables.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  backend      Backend, or @ref TAPI_HASH_RAINBOW_AUTO.
 * @param[in]  tables_dir   Directory of tables on the agent.
 * @param[in]  alg          The algorithm the hash is (the tables must
 *                          match it); @ref TAPI_HASH_NONE when the
 *                          tables' own naming is enough.
 * @param[in]  hash         The hash string.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] result       What was found; release with
 *                          tapi_hash_crack_result_free().
 *
 * @return Status code of running the lookup, not the verdict.
 * @retval TE_ENOSYS        No table engine on the agent.
 * @retval TE_ENOENT        The tables directory is not there.
 */
extern te_errno tapi_hash_rainbow_lookup(tapi_job_factory_t *factory,
                                         tapi_hash_rainbow_backend backend,
                                         const char *tables_dir,
                                         tapi_hash_alg alg, const char *hash,
                                         int timeout_ms,
                                         tapi_hash_crack_result *result);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_HASH_RAINBOW_H__ */

/**@} <!-- END tapi_hash_rainbow --> */
