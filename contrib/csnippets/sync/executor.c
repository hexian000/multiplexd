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
	size_t nthreads;
	thrd_t workers[];
};

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

static int worker_main(void *p)
{
	struct task task;
	while (dequeue(p, &task)) {
		task.func(task.data);
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
	e->queue.head = NULL;
	e->queue.tail = NULL;
	e->nthreads = 0;
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
			executor_join(e);
			return NULL;
		}
		e->nthreads++;
	}
	return e;
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
	mtx_destroy(&e->mu);
	cnd_destroy(&e->cond);
	free(e);
}

bool executor_submit(struct executor *e, const struct task task)
{
	return enqueue(e, &task);
}
