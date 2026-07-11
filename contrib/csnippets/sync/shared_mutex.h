/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SYNC_SHARED_MUTEX_H
#define SYNC_SHARED_MUTEX_H

#include <stdbool.h>
#include <stdint.h>
#include <threads.h>

typedef struct {
	struct {
		uint_least32_t shared_count;
		/* count, not a flag: multiple writers can be concurrently
		 * blocked in smtx_lock, and a woken writer must not clear
		 * this while another is still waiting (see smtx_lock). */
		uint_least32_t exclusive_waiting;
		bool exclusive : 1;
	} state;
	mtx_t state_mu;
	cnd_t shared_cond;
	cnd_t exclusive_cond;
} smtx_t;

/**
 * @brief Initialize a shared (reader/writer) mutex.
 * @param[out] mutex The mutex to initialize.
 * @return thrd_success, or thrd_error/thrd_nomem on failure.
 */
int smtx_init(smtx_t *mutex);

/**
 * @brief Acquire the exclusive (writer) lock, blocking until it is held.
 * @details Writer-preferred: while a writer is waiting, new shared locks are
 * refused so the writer cannot be starved.
 * @param mutex The mutex.
 * @return thrd_success, or thrd_error on failure.
 */
int smtx_lock(smtx_t *mutex);

/**
 * @brief Try to acquire the exclusive (writer) lock without blocking.
 * @param mutex The mutex.
 * @return thrd_success if acquired; thrd_busy if a holder, reader, or waiting
 * writer prevents it; thrd_error on failure.
 */
int smtx_trylock(smtx_t *mutex);

/**
 * @brief Release the exclusive (writer) lock.
 * @param mutex The mutex, currently held exclusively by the caller.
 * @return thrd_success, or thrd_error on failure.
 */
int smtx_unlock(smtx_t *mutex);

/**
 * @brief Acquire a shared (reader) lock, blocking until it is held.
 * @details Blocks while a writer holds or is waiting for the lock.
 * @param mutex The mutex.
 * @return thrd_success, or thrd_error on failure.
 */
int smtx_sharedlock(smtx_t *mutex);

/**
 * @brief Try to acquire a shared (reader) lock without blocking.
 * @param mutex The mutex.
 * @return thrd_success if acquired; thrd_busy if a writer holds or is waiting;
 * thrd_error on failure.
 */
int smtx_trysharedlock(smtx_t *mutex);

/**
 * @brief Release a shared (reader) lock.
 * @param mutex The mutex, currently held shared by the caller.
 * @return thrd_success, or thrd_error on failure.
 */
int smtx_sharedunlock(smtx_t *mutex);

/**
 * @brief Destroy a shared mutex; no thread may hold or wait on it.
 * @param mutex The mutex to destroy.
 */
void smtx_destroy(smtx_t *mutex);

#endif /* SYNC_SHARED_MUTEX_H */
