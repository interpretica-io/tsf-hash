/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What a hash is worth as a credential store
 *
 * @defgroup tapi_hash_audit Credential-strength posture
 * @ingroup tapi_hash
 * @{
 *
 * A hash read as a credential-strength posture and reported through
 * tsf-cybersec: is the algorithm one that should never guard a password
 * (a fast, unsalted digest, or a checksum); is a slow scheme tuned too
 * low (a bcrypt cost that buys no time); and - when the policy allows
 * the work - can the credential actually be recovered, from a wordlist
 * within a time budget or from a rainbow table.
 *
 * The recovery findings need a wordlist or a tables directory in the
 * policy and are skipped without one, the way tsf-smb's guest-write
 * check needs a share. A recovered secret is never put in a finding:
 * the finding says only that it was recovered and how.
 *
 * | Finding | Severity | Read from |
 * |---|---|---|
 * | @c hash.weak-algorithm | high | a fast, unsalted digest guards a password (LM: critical) |
 * | @c hash.fast-salted | medium | a salted but fast scheme (DES/MD5 crypt) |
 * | @c hash.low-work-factor | medium | a slow scheme tuned too low (bcrypt cost) |
 * | @c hash.cracked-dictionary | critical | the credential fell to a wordlist within the budget |
 * | @c hash.in-rainbow-table | critical | the credential was in a precomputed table |
 * | @c hash.not-assessed | info | the algorithm could not be told (nothing to judge) |
 *
 * This runs a cracker against a real credential; use it only in an
 * authorized assessment.
 *
 * @code
 * tapi_hash_audit_policy policy = tapi_hash_default_audit_policy;
 * tapi_cybersec_report report;
 *
 * policy.wordlist = "/usr/share/wordlists/rockyou.txt";
 * policy.crack_budget_ms = 3600000;
 * tapi_cybersec_report_init(&report);
 * CHECK_RC(tapi_hash_audit(factory, TAPI_HASH_SHA512CRYPT, hash, &policy,
 *                          3700000, &report));
 * tapi_cybersec_report_log(&report);
 * @endcode
 */

#ifndef __TSF_TAPI_HASH_AUDIT_H__
#define __TSF_TAPI_HASH_AUDIT_H__

#include "te_defs.h"
#include "te_errno.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"
#include "tapi_hash.h"
#include "tapi_hash_crack.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What a hash store is expected to be. */
typedef struct tapi_hash_audit_policy {
    /**
     * A fast, unsalted digest is acceptable as a password store. Almost
     * never true; left here so a deliberate case can say so.
     */
    bool allow_fast_unsalted;
    /** The least bcrypt cost that is not a finding. Default @c 10. */
    unsigned int min_bcrypt_cost;
    /**
     * A wordlist on the agent to attempt a dictionary crack with, or
     * @c NULL to skip the recovery check.
     */
    const char *wordlist;
    /**
     * A rule set for the dictionary attempt, or @c NULL for a plain
     * wordlist run.
     */
    const char *rules;
    /**
     * How long the crack attempt may run, ms, or @c 0 to skip it even
     * when a wordlist is set. This is the "crackable within?" budget.
     */
    int crack_budget_ms;
    /** Cracker for the attempt, or @ref TAPI_HASH_CRACK_AUTO. */
    tapi_hash_crack_backend crack_backend;
    /**
     * A directory of rainbow tables on the agent to look the hash up
     * in, or @c NULL to skip the table check.
     */
    const char *rainbow_tables;
} tapi_hash_audit_policy;

/**
 * The default: nothing fast-unsalted is allowed, bcrypt cost at least
 * 10, and neither recovery check runs (no wordlist, no tables).
 */
extern const tapi_hash_audit_policy tapi_hash_default_audit_policy;

/**
 * Read a hash's credential-strength posture into @p report.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  alg          The algorithm the hash is, or
 *                          @ref TAPI_HASH_NONE to identify it first.
 * @param[in]  hash         The hash string.
 * @param[in]  policy       What is expected, or @c NULL for the default.
 * @param[in]  timeout_ms   Timeout for the whole audit, ms - larger
 *                          than @a crack_budget_ms.
 * @param[out] report       Report to append findings to.
 *
 * @return Status code of reading the posture, not its verdict.
 */
extern te_errno tapi_hash_audit(tapi_job_factory_t *factory,
                                tapi_hash_alg alg, const char *hash,
                                const tapi_hash_audit_policy *policy,
                                int timeout_ms, tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_HASH_AUDIT_H__ */

/**@} <!-- END tapi_hash_audit --> */
