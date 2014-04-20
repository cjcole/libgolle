/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_COMMIT_H
#define LIBGOLLE_COMMIT_H

#include "bin.h"
#include "platform.h"
#include "errors.h"


/*!
 * \file golle/commit.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Defines functions for a commitment scheme.
 */

/*!
 * \defgroup commit Bit Commitment
 * @{
 * 
 *
 * The protocol for bit commitment scheme is as such:
 * - The user creates a `secret` ::golle_bin_t
 * - The user creates a ::golle_commit_t using the `secret`, which generates
 *    two random sequences, `r1` and `r2`, and the hash `h` of 
 *    (`r1`, `r2`, `secret`).
 * - The user sends `r1` and `h` to one or more parties. At this point,
 *    the commitment is non-malleable.
 * - The external parties cannot determine the contents of the `secret`,
 *    even if the `secret` is one bit.
 * - Later, the user may reveal the `secret` by sending `r1`, `r2`, 
 *    and the `secret`  to the external parties.
 * - The external parties can verify that the `secret` has not changed by checking 
 *    the hash (see ::golle_commit_verify).
 */

/*!
 * \struct golle_commit_t
 * \brief Holds the values for a bit commitment.
 */
typedef struct golle_commit_t {
  golle_bin_t *secret; /*!< Holds the secret of the originating user. */
  golle_bin_t *rsend; /*!< The first random value. Sent along with `hash`. */
  golle_bin_t *rkeep; /*!< The second random value. Kept secret. */
  golle_bin_t *hash; /*!< The hash of the other members. */
} golle_commit_t;


/*!
 * \brief Generate a new bit commitment to a value.
 * \param secret The secret that is to be commited to.
 * \return A new golle_commit_t, or `NULL` if allocation failed or
 * `secret` is `NULL` or secret is of size zero. 
 * The other three members of the structure will be set.
 *
 * \note The new returned structure will have a _copy_ of the
 * `secret` passed in to the function.
 */
GOLLE_EXTERN golle_commit_t *golle_commit_new (const golle_bin_t *secret);

/*!
 * \brief Free resources allocated by a call to ::golle_commit_new.
 * \param commitment A pointer returned by ::golle_commit_new().
 */
GOLLE_EXTERN void golle_commit_delete (golle_commit_t *commitment);

/*!
 * \brief Verify a commmitment.
 * \param commitment The commitment to verify.
 * \return GOLLE_COMMIT_PASSED if the commitment was verified.
 * GOLLE_COMMIT_FAILED if the commitment verification did not pass.
 * GOLLE_ERROR if any `commitment`, or any member of `commitment` is `NULL`.
 * GOLLE_ECRYPTO if hash checking failed.
 *
 * \note The caller should have first received `rsend` and `hash`, then
 * independantly received `secret` and `rkeep`. A full ::golle_commit_t
 * is required to verify that the `secret` value is correct.
 */
GOLLE_EXTERN golle_error golle_commit_verify (const golle_commit_t *commitment);

/*!
 * \brief Release the buffers associated with a commit
 * without freeing the commit structure itself.
 * \param commit The commit structure whose buffers should be freed.
 */
GOLLE_INLINE void golle_commit_clear (golle_commit_t *commit) {
  if (commit) {
    golle_bin_delete (commit->secret); commit->secret = NULL;
    golle_bin_delete (commit->rsend); commit->rsend = NULL;
    golle_bin_delete (commit->rkeep); commit->rkeep = NULL;
    golle_bin_delete (commit->hash); commit->hash = NULL;
  }
}

/*!
 * \brief Copy a commit structure, bin for bin.
 * \param[out] dest Will have each member set to copied buffer.
 * \param src Contains the buffers to copy from.
 * \return ::GOLLE_OK if OK, :GOLLE_ERROR if either param is `NULL`,
 * ::GOLLE_EMEM if memory failed.
 */
GOLLE_EXTERN golle_error golle_commit_copy (golle_commit_t *dest,
					    const golle_commit_t *src);

/*!
 * @}
 */

#endif
