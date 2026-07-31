/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "sync/executor.h"

#include "sync/task.h"
#include "sync/thrd.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <threads.h>

struct executor {
	mtx_t mu;
	cnd_t cond;
	/* Bounded ring buffer; allocated separately because workers[] is the
	 * flexible array member and a struct may have only one */
	struct task *buf;
	size_t capacity;
	size_t head;
	size_t count;
	bool exit_flag : 1;
	bool detached : 1;
	size_t nthreads;
	size_t live;
	thrd_t workers[];
};

static void free_executor(struct executor *restrict e)
{
	mtx_destroy(&e->mu);
	cnd_destroy(&e->cond);
	free(e->buf);
	free(e);
}

static bool dequeue(struct executor *e, struct task *task)
{
	THRD_ASSERT(mtx_lock(&e->mu));
	for (;;) {
		if (e->count > 0) {
			*task = e->buf[e->head];
			if (++e->head >= e->capacity) {
				e->head -= e->capacity;
			}
			e->count--;
			THRD_ASSERT(mtx_unlock(&e->mu));
			return true;
		}
		if (e->exit_flag) {
			THRD_ASSERT(mtx_unlock(&e->mu));
			return false;
		}
		THRD_ASSERT(cnd_wait(&e->cond, &e->mu));
	}
}

static int worker_main(void *p)
{
	struct executor *restrict e = p;
	struct task task;
	while (dequeue(e, &task)) {
		task.func(task.data);
	}
	/* A detached executor is freed by whichever worker exits last. */
	THRD_ASSERT(mtx_lock(&e->mu));
	const bool last = (--e->live == 0);
	const bool detached = e->detached;
	THRD_ASSERT(mtx_unlock(&e->mu));
	if (detached && last) {
		free_executor(e);
	}
	return 0;
}

struct executor *executor_create(const size_t nworkers, const size_t capacity)
{
	if (nworkers == 0) {
		/* a 0-worker executor can never run a submitted task; reject it
		 * rather than silently queue-drop (and leak) tasks, since with
		 * no worker nothing ever drains the queue */
		return NULL;
	}
	if (capacity == 0) {
		/* a 0-slot bounded queue could never accept a task */
		return NULL;
	}
	if (nworkers > (SIZE_MAX - sizeof(struct executor)) / sizeof(thrd_t)) {
		return NULL;
	}
	if (capacity > SIZE_MAX / sizeof(struct task)) {
		return NULL;
	}
	struct executor *restrict e =
		malloc(sizeof(struct executor) + nworkers * sizeof(thrd_t));
	if (e == NULL) {
		return NULL;
	}
	e->buf = malloc(sizeof(struct task) * capacity);
	if (e->buf == NULL) {
		free(e);
		return NULL;
	}
	e->exit_flag = false;
	e->detached = false;
	e->capacity = capacity;
	e->head = 0;
	e->count = 0;
	e->nthreads = 0;
	e->live = 0;
	if (mtx_init(&e->mu, mtx_plain) != thrd_success) {
		free(e->buf);
		free(e);
		return NULL;
	}
	if (cnd_init(&e->cond) != thrd_success) {
		mtx_destroy(&e->mu);
		free(e->buf);
		free(e);
		return NULL;
	}
	for (size_t i = 0; i < nworkers; i++) {
		if (thrd_create(&e->workers[i], worker_main, e) !=
		    thrd_success) {
			executor_detach(e);
			return NULL;
		}
		e->nthreads++;
		e->live++;
	}
	return e;
}

static bool enqueue(struct executor *e, const struct task *task)
{
	THRD_ASSERT(mtx_lock(&e->mu));
	if (e->exit_flag) {
		THRD_ASSERT(mtx_unlock(&e->mu));
		return false;
	}
	if (e->count == e->capacity) {
		THRD_ASSERT(mtx_unlock(&e->mu));
		return false;
	}
	size_t tail = e->head + e->count;
	if (tail >= e->capacity) {
		tail -= e->capacity;
	}
	e->buf[tail] = *task;
	e->count++;
	/* Signal while still holding the lock, as executor_detach does below
	 * and for the same reason: once the lock is released a concurrent
	 * detach can let the workers drain this item, exit, and (as the last
	 * one) free the executor, so touching e->cond after the unlock would be
	 * a use-after-free. Note executor.h disclaims concurrent submit, and
	 * this does not make that case safe on its own -- the mtx_lock above
	 * can land on an already-freed executor just the same -- but it removes
	 * the window that is ours to remove and matches the module's other
	 * enqueue paths. */
	THRD_ASSERT(cnd_signal(&e->cond));
	THRD_ASSERT(mtx_unlock(&e->mu));
	return true;
}

bool executor_submit(struct executor *e, const struct task task)
{
	return enqueue(e, &task);
}

void executor_join(struct executor *e)
{
	THRD_ASSERT(mtx_lock(&e->mu));
	e->exit_flag = true;
	/* Broadcast under the lock, as enqueue and executor_detach do. On this
	 * (non-detached) path no worker frees the executor, so the after-unlock
	 * broadcast was safe -- but signalling under the lock keeps all five
	 * notify sites in the module consistent and needs no such invariant. */
	THRD_ASSERT(cnd_broadcast(&e->cond));
	THRD_ASSERT(mtx_unlock(&e->mu));
	const size_t nthreads = e->nthreads;
	for (size_t i = 0; i < nthreads; i++) {
		THRD_ASSERT(thrd_join(e->workers[i], NULL));
	}
	free_executor(e);
}

void executor_detach(struct executor *e)
{
	/* Detach before setting exit_flag, so no worker can free the executor
	 * while this loop reads e->workers. nthreads never changes after
	 * creation, so reading it here without the lock is safe. */
	const size_t nthreads = e->nthreads;
	for (size_t i = 0; i < nthreads; i++) {
		THRD_ASSERT(thrd_detach(e->workers[i]));
	}
	THRD_ASSERT(mtx_lock(&e->mu));
	e->exit_flag = true;
	e->detached = true;
	/* Broadcast while still holding the lock: once the lock is released a
	 * worker can observe exit_flag, exit, and (as the last one) free the
	 * executor, so touching e->cond after the unlock would be a use-after-
	 * free. */
	THRD_ASSERT(cnd_broadcast(&e->cond));
	THRD_ASSERT(mtx_unlock(&e->mu));
	/* With workers, the last one to exit frees the executor; with none,
	 * there is nobody to do it, so free it here. */
	if (nthreads == 0) {
		free_executor(e);
	}
}
