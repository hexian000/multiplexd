/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "shared_mutex.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <threads.h>

int smtx_init(smtx_t *mutex)
{
	memset(mutex, 0, sizeof(*mutex));
	int status = mtx_init(&mutex->state_mu, mtx_plain);
	if (status != thrd_success) {
		return status;
	}
	status = cnd_init(&mutex->shared_cond);
	if (status != thrd_success) {
		mtx_destroy(&mutex->state_mu);
		return status;
	}
	status = cnd_init(&mutex->exclusive_cond);
	if (status != thrd_success) {
		mtx_destroy(&mutex->state_mu);
		cnd_destroy(&mutex->shared_cond);
		return status;
	}
	return thrd_success;
}

/* First of two threads.h statuses that is not thrd_success, else thrd_success. */
static int first_error(const int first, const int second)
{
	return first != thrd_success ? first : second;
}

int smtx_lock(smtx_t *mutex)
{
	const int status = mtx_lock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	mutex->state.exclusive_waiting++;
	while (mutex->state.exclusive || mutex->state.shared_count > 0) {
		const int wait =
			cnd_wait(&mutex->exclusive_cond, &mutex->state_mu);
		if (wait != thrd_success) {
			/* the wait returned without honoring the request, with
			 * state_mu still held; roll back this writer's pending
			 * registration so a later writer cannot be starved by a
			 * count that never drains, then surface the failure */
			mutex->state.exclusive_waiting--;
			int notify = thrd_success;
			if (!mutex->state.exclusive &&
			    mutex->state.exclusive_waiting == 0) {
				/* the rollback falsified the readers' predicate
				 * (exclusive || exclusive_waiting > 0) with no
				 * release to follow, so wake them here or never */
				notify = cnd_broadcast(&mutex->shared_cond);
			}
			const int unlock = mtx_unlock(&mutex->state_mu);
			return first_error(wait, first_error(notify, unlock));
		}
	}
	assert(mutex->state.exclusive_waiting > 0);
	mutex->state.exclusive_waiting--;
	mutex->state.exclusive = true;
	return mtx_unlock(&mutex->state_mu);
}

int smtx_trylock(smtx_t *mutex)
{
	const int status = mtx_trylock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	if (mutex->state.exclusive || mutex->state.shared_count > 0 ||
	    mutex->state.exclusive_waiting > 0) {
		/* defer to a writer already blocked in smtx_lock(), matching
		 * smtx_trysharedlock()'s writer-preference check, so a trylock
		 * retry loop cannot starve the queued writer */
		const int unlock = mtx_unlock(&mutex->state_mu);
		/* a failed release must not be reported as thrd_busy: the
		 * caller would retry against a state_mu that is still held */
		return first_error(unlock, thrd_busy);
	}
	mutex->state.exclusive = true;
	return mtx_unlock(&mutex->state_mu);
}

int smtx_unlock(smtx_t *mutex)
{
	const int status = mtx_lock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	assert(mutex->state.exclusive);
	assert(mutex->state.shared_count == 0);
	mutex->state.exclusive = false;
	/* Clearing `exclusive` unblocks a writer (predicate exclusive ||
	 * shared_count > 0) if one is queued, otherwise the readers (predicate
	 * exclusive || exclusive_waiting > 0). The two are mutually exclusive: with
	 * a writer queued the readers' predicate is still true, so a broadcast only
	 * wakes them to re-wait (a thundering herd on a read-heavy lock); with none
	 * queued nobody waits on exclusive_cond (a parked writer always holds an
	 * un-decremented exclusive_waiting), so the signal is a no-op. */
	int notify;
	if (mutex->state.exclusive_waiting > 0) {
		notify = cnd_signal(&mutex->exclusive_cond);
	} else {
		notify = cnd_broadcast(&mutex->shared_cond);
	}
	/* the lock is already released; report a failed wakeup rather than let a
	 * successful unlock mask it, leaving blocked threads unwoken */
	const int unlock = mtx_unlock(&mutex->state_mu);
	return first_error(notify, unlock);
}

int smtx_sharedlock(smtx_t *mutex)
{
	const int status = mtx_lock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	while (mutex->state.exclusive || mutex->state.exclusive_waiting > 0) {
		const int wait =
			cnd_wait(&mutex->shared_cond, &mutex->state_mu);
		if (wait != thrd_success) {
			/* nothing was registered before the wait, so only the
			 * still-held state_mu needs releasing before the failure
			 * is surfaced */
			const int unlock = mtx_unlock(&mutex->state_mu);
			return first_error(wait, unlock);
		}
	}
	mutex->state.shared_count++;
	return mtx_unlock(&mutex->state_mu);
}

int smtx_trysharedlock(smtx_t *mutex)
{
	const int status = mtx_trylock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	if (mutex->state.exclusive || mutex->state.exclusive_waiting > 0) {
		const int unlock = mtx_unlock(&mutex->state_mu);
		return first_error(unlock, thrd_busy);
	}
	mutex->state.shared_count++;
	return mtx_unlock(&mutex->state_mu);
}

int smtx_sharedunlock(smtx_t *mutex)
{
	const int status = mtx_lock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	assert(!mutex->state.exclusive);
	assert(mutex->state.shared_count > 0);
	mutex->state.shared_count--;
	int notify = thrd_success;
	if (mutex->state.shared_count == 0) {
		/* Only a writer can be unblocked here: `exclusive` is already
		 * false and `exclusive_waiting` is untouched, so every parked
		 * reader's predicate is unchanged and broadcasting to them
		 * would wake all of them only to re-wait -- a thundering herd
		 * on a lock built for read-heavy use. */
		notify = cnd_signal(&mutex->exclusive_cond);
	}
	/* the share is already released; report a failed wakeup rather than let
	 * a successful unlock mask it, leaving a queued writer unwoken */
	const int unlock = mtx_unlock(&mutex->state_mu);
	return first_error(notify, unlock);
}

void smtx_destroy(smtx_t *mutex)
{
	mtx_destroy(&mutex->state_mu);
	cnd_destroy(&mutex->shared_cond);
	cnd_destroy(&mutex->exclusive_cond);
}
