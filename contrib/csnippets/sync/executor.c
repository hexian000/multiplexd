/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "sync/executor.h"
#include "sync/task.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>

#define THRD_ASSERT(expr)                                                      \
	do {                                                                   \
		const int status = (expr);                                     \
		(void)status;                                                  \
		assert(status == thrd_success);                                \
	} while (0)

struct task_item {
	struct task task;
	struct task_item *next;
};

struct executor {
	mtx_t mu;
	cnd_t cond;
	struct {
		struct task_item *head, *tail;
	} queue;
	bool exit_flag : 1;
	bool detached : 1;
	size_t nthreads;
	size_t live;
	thrd_t workers[];
};

static void executor_free(struct executor *restrict e)
{
	mtx_destroy(&e->mu);
	cnd_destroy(&e->cond);
	free(e);
}

static bool dequeue(struct executor *e, struct task *task)
{
	THRD_ASSERT(mtx_lock(&e->mu));
	for (;;) {
		struct task_item *restrict item = e->queue.head;
		if (item != NULL) {
			e->queue.head = item->next;
			if (e->queue.tail == item) {
				e->queue.tail = NULL;
			}
			THRD_ASSERT(mtx_unlock(&e->mu));
			*task = item->task;
			free(item);
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
		executor_free(e);
	}
	return 0;
}

struct executor *executor_create(const size_t nworkers)
{
	struct executor *restrict e =
		malloc(sizeof(struct executor) + nworkers * sizeof(thrd_t));
	if (e == NULL) {
		return NULL;
	}
	e->exit_flag = false;
	e->detached = false;
	e->queue.head = NULL;
	e->queue.tail = NULL;
	e->nthreads = 0;
	e->live = 0;
	if (mtx_init(&e->mu, mtx_plain) != thrd_success) {
		free(e);
		return NULL;
	}
	if (cnd_init(&e->cond) != thrd_success) {
		mtx_destroy(&e->mu);
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
	struct task_item *new_item = malloc(sizeof(struct task_item));
	if (new_item == NULL) {
		return false;
	}
	*new_item = (struct task_item){ *task, NULL };
	THRD_ASSERT(mtx_lock(&e->mu));
	struct task_item *restrict item = e->queue.tail;
	if (item != NULL) {
		item->next = new_item;
	} else {
		e->queue.head = new_item;
	}
	e->queue.tail = new_item;
	THRD_ASSERT(mtx_unlock(&e->mu));
	THRD_ASSERT(cnd_signal(&e->cond));
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
	THRD_ASSERT(mtx_unlock(&e->mu));
	THRD_ASSERT(cnd_broadcast(&e->cond));
	const size_t nthreads = e->nthreads;
	for (size_t i = 0; i < nthreads; i++) {
		THRD_ASSERT(thrd_join(e->workers[i], NULL));
	}
	executor_free(e);
}

void executor_detach(struct executor *e)
{
	/* Detach the workers while they are still blocked (the exit flag is
	 * not set yet), so e->workers stays valid for this loop and no worker
	 * can free the executor before we are done reading it. nthreads is
	 * fixed after creation, so it is safe to read without the lock. */
	const size_t nthreads = e->nthreads;
	for (size_t i = 0; i < nthreads; i++) {
		THRD_ASSERT(thrd_detach(e->workers[i]));
	}
	THRD_ASSERT(mtx_lock(&e->mu));
	e->exit_flag = true;
	e->detached = true;
	THRD_ASSERT(mtx_unlock(&e->mu));
	THRD_ASSERT(cnd_broadcast(&e->cond));
	/* With workers, the last one to exit frees the executor; with none,
	 * there is nobody to do it, so free it here. */
	if (nthreads == 0) {
		executor_free(e);
	}
}
