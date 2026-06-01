/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief A hash read as a credential-strength posture
 *
 * The algorithm class is judged first - a fast unsalted digest guarding
 * a password is a finding on its own - then the work factor of a slow
 * scheme, and last, when the policy allows the work, whether the
 * credential can actually be recovered from a wordlist or a table.
 * A recovered secret is never written into a finding; the finding says
 * only that recovery succeeded and by what means.
 */

#define TE_LGR_USER "TAPI HASH"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_cybersec.h"
#include "tapi_hash.h"
#include "tapi_hash_crack.h"
#include "tapi_hash_rainbow.h"
#include "tapi_hash_audit.h"
#include "tapi_hash_internal.h"

/* See description in tapi_hash_audit.h */
const tapi_hash_audit_policy tapi_hash_default_audit_policy = {
    .allow_fast_unsalted = false,
    .min_bcrypt_cost = 10,
    .wordlist = NULL,
    .rules = NULL,
    .crack_budget_ms = 0,
    .crack_backend = TAPI_HASH_CRACK_AUTO,
    .rainbow_tables = NULL,
};

/** The bcrypt cost from a @c $2b$NN$... string, or @c -1. */
static int
audit_bcrypt_cost(const char *hash)
{
    if (hash == NULL || hash[0] != '$' || hash[1] != '2')
        return -1;
    /* $2a$/$2b$/$2y$ then two cost digits and a $. */
    if (hash[2] == '\0' || hash[3] != '$')
        return -1;
    if (hash[4] < '0' || hash[4] > '9' || hash[5] < '0' || hash[5] > '9')
        return -1;

    return (hash[4] - '0') * 10 + (hash[5] - '0');
}

/** Add the algorithm-class findings. */
static void
audit_algorithm(tapi_hash_alg alg, const char *hash, const char *subject,
                const tapi_hash_audit_policy *policy,
                tapi_cybersec_report *report)
{
    tapi_hash_class cls = tapi_hash_alg_class(alg);

    if (cls == TAPI_HASH_CLASS_FAST_UNSALTED && !policy->allow_fast_unsalted)
    {
        if (alg == TAPI_HASH_LM)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_CRITICAL,
                                     "hash.weak-algorithm", subject,
                                     "LM: a DES-based scheme with no real "
                                     "strength, trivially recovered");
        }
        else
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "hash.weak-algorithm", subject,
                                     "%s is a fast, unsalted digest, wrong "
                                     "for a password: billions of guesses a "
                                     "second and no per-hash salt",
                                     tapi_hash_alg2str(alg));
        }
    }
    else if (cls == TAPI_HASH_CLASS_CHECKSUM)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "hash.weak-algorithm", subject,
                                 "%s is a checksum, not a password hash",
                                 tapi_hash_alg2str(alg));
    }
    else if (cls == TAPI_HASH_CLASS_FAST_SALTED)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "hash.fast-salted", subject,
                                 "%s is salted but fast, so a per-hash guess "
                                 "is still cheap",
                                 tapi_hash_alg2str(alg));
    }

    if (alg == TAPI_HASH_BCRYPT)
    {
        int cost = audit_bcrypt_cost(hash);

        if (cost >= 0 && (unsigned int)cost < policy->min_bcrypt_cost)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "hash.low-work-factor", subject,
                                     "bcrypt cost %d is below the wanted %u, "
                                     "so each guess is cheaper than it should "
                                     "be", cost, policy->min_bcrypt_cost);
        }
    }
}

/* See description in tapi_hash_audit.h */
te_errno
tapi_hash_audit(tapi_job_factory_t *factory, tapi_hash_alg alg,
                const char *hash, const tapi_hash_audit_policy *policy,
                int timeout_ms, tapi_cybersec_report *report)
{
    const char *subject = "hash";

    if (hash == NULL || report == NULL)
    {
        ERROR("A hash audit needs a hash and a report");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }
    if (policy == NULL)
        policy = &tapi_hash_default_audit_policy;

    /* Identify the algorithm when the caller did not name it. */
    if (alg == TAPI_HASH_NONE)
    {
        te_vec algs = TE_VEC_INIT(tapi_hash_alg);

        if (tapi_hash_identify(factory, hash, timeout_ms, &algs) == 0 &&
            te_vec_size(&algs) != 0)
        {
            alg = TE_VEC_GET(tapi_hash_alg, &algs, 0);
        }
        te_vec_free(&algs);
    }
    if (alg == TAPI_HASH_NONE)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                                 "hash.not-assessed", subject,
                                 "The algorithm could not be told from the "
                                 "hash, so nothing was judged");
        return 0;
    }

    audit_algorithm(alg, hash, subject, policy, report);

    /* Recovery from a wordlist, when the policy allows the work. */
    if (policy->wordlist != NULL && policy->crack_budget_ms > 0)
    {
        tapi_hash_crack_spec spec = TAPI_HASH_CRACK_SPEC_INIT;
        tapi_hash_crack_result result;
        te_errno crc;

        spec.backend = policy->crack_backend;
        spec.alg = alg;
        spec.attack = policy->rules != NULL ? TAPI_HASH_ATTACK_RULES :
                      TAPI_HASH_ATTACK_DICT;
        spec.wordlist = policy->wordlist;
        spec.rules = policy->rules;
        spec.time_budget_ms = policy->crack_budget_ms;

        crc = tapi_hash_crack(factory, &spec, hash, timeout_ms, &result);
        if (crc == 0 && result.cracked)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_CRITICAL,
                                     "hash.cracked-dictionary", subject,
                                     "The credential was recovered from the "
                                     "wordlist within the time budget");
        }
        else if (TE_RC_GET_ERROR(crc) == TE_ENOSYS)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                                     "hash.not-assessed", subject,
                                     "No cracker on the agent, so the "
                                     "wordlist recovery was not attempted");
        }
        tapi_hash_crack_result_free(&result);
    }

    /* Recovery from a precomputed table, when one is given. */
    if (policy->rainbow_tables != NULL)
    {
        tapi_hash_crack_result result;
        te_errno rrc;

        rrc = tapi_hash_rainbow_lookup(factory, TAPI_HASH_RAINBOW_AUTO,
                                       policy->rainbow_tables, alg, hash,
                                       timeout_ms, &result);
        if (rrc == 0 && result.cracked)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_CRITICAL,
                                     "hash.in-rainbow-table", subject,
                                     "The credential was found in a "
                                     "precomputed table");
        }
        tapi_hash_crack_result_free(&result);
    }

    return 0;
}
