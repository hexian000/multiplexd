/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SYNC_SHARED_MUTEX_H
#define SYNC_SHARED_MUTEX_H

#include <stdatomic.h>
#include <stdbool.h>
#include <threads.h>

typedef struct {
	struct {
		size_t shared_count;
		bool exclusive : 1;
		bool exclusive_waiting : 1;
	} state;
	mtx_t state_mu;
	cnd_t shared_cond;
	cnd_t exclusive_cond;
} smtx_t;

int smtx_init(smtx_t *mutex);

int smtx_lock(smtx_t *mutex);
int smtx_trylock(smtx_t *mutex);
int smtx_unlock(smtx_t *mutex);

int smtx_sharedlock(smtx_t *mutex);
int smtx_trysharedlock(smtx_t *mutex);
int smtx_sharedunlock(smtx_t *mutex);

void smtx_destroy(smtx_t *mutex);

#endif /* SYNC_SHARED_MUTEX_H */
