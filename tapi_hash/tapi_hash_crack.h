/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Recovering a preimage from a hash
 *
 * @defgroup tapi_hash_crack Cracking a hash
 * @ingroup tapi_hash
 * @{
 *
 * The other direction: given a hash, try to recover what it was made
 * from - by a wordlist, a brute-force mask, or a rule set over a
 * wordlist - with hashcat or John the Ripper on the agent.
 *
 * This recovers credentials, and is for an authorized assessment only.
 *
 * The hash to attack and the wordlist are files on the agent, and the
 * recovered secret is read from the tool's own output file, never from
 * @c argv - so the plaintext is not visible to @c ps, and this library
 * never puts it into a log verdict either. The caller gets it back in
 * @ref tapi_hash_crack_result::plaintext to do with as the test needs.
 *
 * @code
 * tapi_hash_crack_spec spec = TAPI_HASH_CRACK_SPEC_INIT;
 * tapi_hash_crack_result result;
 *
 * spec.alg = TAPI_HASH_MD5;
 * spec.attack = TAPI_HASH_ATTACK_DICT;
 * spec.wordlist = "/usr/share/wordlists/rockyou.txt";
 * spec.time_budget_ms = 60000;
 * CHECK_RC(tapi_hash_crack(factory, &spec, "5f4dcc3b5aa765d61d8327deb882cf99",
 *                          90000, &result));
 * if (result.cracked)
 *     RING("recovered in %.1fs", result.seconds);
 * tapi_hash_crack_result_free(&result);
 * @endcode
 */

#ifndef __TSF_TAPI_HASH_CRACK_H__
#define __TSF_TAPI_HASH_CRACK_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "tapi_job.h"

#include "tapi_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Which cracker to drive. */
typedef enum tapi_hash_crack_backend {
    /** Ask the agent which of the others it has. */
    TAPI_HASH_CRACK_AUTO = 0,
    /** hashcat. */
    TAPI_HASH_CRACK_HASHCAT,
    /** John the Ripper. */
    TAPI_HASH_CRACK_JOHN,
} tapi_hash_crack_backend;

/** How to search the space of candidate preimages. */
typedef enum tapi_hash_attack {
    /** Each word of a wordlist. */
    TAPI_HASH_ATTACK_DICT = 0,
    /** Each word of a wordlist, mangled by a rule set. */
    TAPI_HASH_ATTACK_RULES,
    /** Every string a mask describes (brute force). */
    TAPI_HASH_ATTACK_MASK,
} tapi_hash_attack;

/** What to attack a hash with. */
typedef struct tapi_hash_crack_spec {
    /** Cracker, or @ref TAPI_HASH_CRACK_AUTO. */
    tapi_hash_crack_backend backend;
    /** The algorithm the hash is; @ref TAPI_HASH_NONE to let the tool guess. */
    tapi_hash_alg alg;
    /** The attack. */
    tapi_hash_attack attack;
    /**
     * Wordlist path on the agent, for @ref TAPI_HASH_ATTACK_DICT and
     * @ref TAPI_HASH_ATTACK_RULES.
     */
    const char *wordlist;
    /**
     * Rule set for @ref TAPI_HASH_ATTACK_RULES: a hashcat rule file, or
     * a John rule section name, or @c NULL for the tool's default set.
     */
    const char *rules;
    /**
     * Mask for @ref TAPI_HASH_ATTACK_MASK, in hashcat notation
     * (@c "?l?l?l?d"). John is driven in incremental mode when this is
     * @c NULL.
     */
    const char *mask;
    /**
     * Stop after this much wall time, ms, or @c 0 for no limit. A
     * budget is how a strength audit asks "was it crackable in an
     * hour?" without waiting forever.
     */
    int time_budget_ms;
} tapi_hash_crack_spec;

/** Initializer for #tapi_hash_crack_spec. */
#define TAPI_HASH_CRACK_SPEC_INIT { .backend = TAPI_HASH_CRACK_AUTO }

/** What a crack attempt found. */
typedef struct tapi_hash_crack_result {
    /** @c true when the hash was recovered. */
    bool cracked;
    /** The recovered preimage; empty when not cracked. Caller frees. */
    te_string plaintext;
    /** Wall-clock time the attempt took, seconds. */
    double seconds;
    /** The backend that ran. */
    tapi_hash_crack_backend backend;
} tapi_hash_crack_result;

/**
 * Is a cracker on the agent?
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_HASH_CRACK_AUTO for any.
 * @param timeout_ms    Timeout, ms.
 *
 * @return @c true when the backend (or any, for @c AUTO) is there.
 */
extern bool tapi_hash_crack_available(tapi_job_factory_t *factory,
                                      tapi_hash_crack_backend backend,
                                      int timeout_ms);

/**
 * Try to recover the preimage of a hash.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  spec         What to attack it with.
 * @param[in]  hash         The hash string.
 * @param[in]  timeout_ms   Timeout for the whole run, ms - make it
 *                          larger than @a time_budget_ms.
 * @param[out] result       What was found; release with
 *                          tapi_hash_crack_result_free().
 *
 * @return Status code of running the cracker, not the verdict: a hash
 *         that was not cracked is @c 0 with @a cracked @c false.
 * @retval TE_EOPNOTSUPP    The backend does not know @a alg, or the
 *                          attack asks for something it cannot do.
 * @retval TE_ENOSYS        No cracker on the agent.
 */
extern te_errno tapi_hash_crack(tapi_job_factory_t *factory,
                                const tapi_hash_crack_spec *spec,
                                const char *hash, int timeout_ms,
                                tapi_hash_crack_result *result);

/**
 * Release a crack result.
 *
 * @param result    Result.
 */
extern void tapi_hash_crack_result_free(tapi_hash_crack_result *result);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_HASH_CRACK_H__ */

/**@} <!-- END tapi_hash_crack --> */
