/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "shared_mutex.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <threads.h>

#define THRD_ASSERT(expr)                                                      \
	do {                                                                   \
		const int status = (expr);                                     \
		(void)status;                                                  \
		assert(status == thrd_success);                                \
	} while (0)

int smtx_init(smtx_t *restrict mutex)
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

static inline void notify_waiters(smtx_t *restrict mutex)
{
	THRD_ASSERT(cnd_signal(&mutex->exclusive_cond));
	THRD_ASSERT(cnd_broadcast(&mutex->shared_cond));
}

int smtx_lock(smtx_t *restrict mutex)
{
	int status = mtx_lock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	mutex->state.exclusive_waiting++;
	while (mutex->state.exclusive || mutex->state.shared_count > 0) {
		THRD_ASSERT(cnd_wait(&mutex->exclusive_cond, &mutex->state_mu));
	}
	assert(mutex->state.exclusive_waiting > 0);
	mutex->state.exclusive_waiting--;
	mutex->state.exclusive = true;
	return mtx_unlock(&mutex->state_mu);
}

int smtx_trylock(smtx_t *restrict mutex)
{
	int status = mtx_lock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	if (mutex->state.exclusive || mutex->state.shared_count > 0 ||
	    mutex->state.exclusive_waiting > 0) {
		/* defer to a writer already blocked in smtx_lock(), matching
		 * smtx_trysharedlock()'s writer-preference check, so a trylock
		 * retry loop cannot starve the queued writer */
		THRD_ASSERT(mtx_unlock(&mutex->state_mu));
		return thrd_busy;
	}
	mutex->state.exclusive = true;
	return mtx_unlock(&mutex->state_mu);
}

int smtx_unlock(smtx_t *restrict mutex)
{
	int status = mtx_lock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	assert(mutex->state.exclusive);
	assert(mutex->state.shared_count == 0);
	mutex->state.exclusive = false;
	notify_waiters(mutex);
	return mtx_unlock(&mutex->state_mu);
}

int smtx_sharedlock(smtx_t *restrict mutex)
{
	int status = mtx_lock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	while (mutex->state.exclusive || mutex->state.exclusive_waiting > 0) {
		THRD_ASSERT(cnd_wait(&mutex->shared_cond, &mutex->state_mu));
	}
	mutex->state.shared_count++;
	return mtx_unlock(&mutex->state_mu);
}

int smtx_trysharedlock(smtx_t *restrict mutex)
{
	int status = mtx_lock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	if (mutex->state.exclusive || mutex->state.exclusive_waiting > 0) {
		THRD_ASSERT(mtx_unlock(&mutex->state_mu));
		return thrd_busy;
	}
	mutex->state.shared_count++;
	return mtx_unlock(&mutex->state_mu);
}

int smtx_sharedunlock(smtx_t *restrict mutex)
{
	int status = mtx_lock(&mutex->state_mu);
	if (status != thrd_success) {
		return status;
	}
	assert(!mutex->state.exclusive);
	assert(mutex->state.shared_count > 0);
	mutex->state.shared_count--;
	if (mutex->state.shared_count == 0) {
		notify_waiters(mutex);
	}
	return mtx_unlock(&mutex->state_mu);
}

void smtx_destroy(smtx_t *restrict mutex)
{
	mtx_destroy(&mutex->state_mu);
	cnd_destroy(&mutex->shared_cond);
	cnd_destroy(&mutex->exclusive_cond);
}
