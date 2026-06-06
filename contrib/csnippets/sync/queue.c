#include "sync/queue.h"
#include "utils/likely.h"

#include <assert.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* spsc_queue */
struct spsc_queue {
	size_t capacity;
	atomic_size_t read, write;
	void *items[];
};

#define INVALID_HANDLE (UINT32_C(0xFFFFFFFF))

#define MAKE_HANDLE(handle, index)                                             \
	((((handle) + UINT32_C(0x10000)) & UINT32_C(0xFFFF0000)) |             \
	 ((index) & UINT32_C(0x0000FFFF)))

struct spsc_queue *squeue_new(const size_t capacity)
{
	struct spsc_queue *restrict q =
		malloc(sizeof(struct spsc_queue) + capacity * sizeof(void *));
	if (q == NULL) {
		return NULL;
	}
	q->capacity = capacity;
	atomic_init(&q->read, 0);
	atomic_init(&q->write, 0);
	return q;
}

static inline size_t
calc_size(const size_t write, const size_t read, const size_t capacity)
{
	if (write >= read) {
		return write - read;
	}
	return write + capacity - read;
}

static size_t calc_next(const size_t index, const size_t capacity)
{
	size_t ret = index + 1;
	while (UNLIKELY(ret >= capacity)) {
		ret -= capacity;
	}
	return ret;
}

bool squeue_push(struct spsc_queue *q, void *p)
{
	assert(p != NULL);
	const size_t write =
		atomic_load_explicit(&q->write, memory_order_relaxed);
	const size_t next = calc_next(write, q->capacity);
	const size_t read =
		atomic_load_explicit(&q->read, memory_order_acquire);
	if (next == read) {
		return false;
	}
	q->items[write] = p;
	atomic_store_explicit(&q->write, next, memory_order_release);
	return true;
}

void *squeue_pop(struct spsc_queue *q)
{
	const size_t capacity = q->capacity;
	const size_t write =
		atomic_load_explicit(&q->write, memory_order_acquire);
	const size_t read =
		atomic_load_explicit(&q->read, memory_order_relaxed);
	const size_t avail = calc_size(write, read, capacity);
	if (avail == 0) {
		return NULL;
	}
	void *const p = q->items[read];
	size_t new_read = read + 1;
	if (new_read >= capacity) {
		new_read -= capacity;
	}
	atomic_store_explicit(&q->read, new_read, memory_order_release);
	return p;
}

void squeue_free(struct spsc_queue *q)
{
	free(q);
}

struct mpmc_item {
	atomic_uint_least32_t next; /* For queue linked list */
	atomic_uint_least32_t nextfree; /* For free pool linked list */
	void *payload;
};

struct mpmc_queue {
	size_t capacity;
	atomic_uint_least32_t head, tail;
	atomic_uint_least32_t pool;
	struct mpmc_item items[];
};

struct mpmc_queue *mqueue_new(const size_t capacity)
{
	if (capacity >= UINT16_MAX) {
		return NULL;
	}
	/* Allocate capacity + 1 items: slot 0 is the sentinel/dummy node */
	const size_t total_slots = capacity + 1;
	struct mpmc_queue *restrict q =
		malloc(sizeof(struct mpmc_queue) +
		       total_slots * sizeof(struct mpmc_item));
	if (q == NULL) {
		return NULL;
	}
	q->capacity = total_slots;
	/* Initialize sentinel node at index 0 */
	atomic_init(&q->items[0].next, INVALID_HANDLE);
	q->items[0].payload = NULL;
	/* head and tail both point to sentinel initially */
	atomic_init(&q->head, 0);
	atomic_init(&q->tail, 0);
	/* Free pool starts at index 1, links 1->2->3->...->capacity */
	atomic_init(&q->pool, 1);
	for (size_t i = 1; i < total_slots; i++) {
		atomic_init(&q->items[i].next, INVALID_HANDLE);
		atomic_init(&q->items[i].nextfree, (uint_least32_t)(i + 1));
		q->items[i].payload = NULL;
	}
	return q;
}

static size_t mitem_alloc(struct mpmc_queue *q)
{
	uint_least32_t old_pool =
		atomic_load_explicit(&q->pool, memory_order_acquire);
	for (;;) {
		const size_t index = (old_pool & UINT32_C(0xFFFF));
		if (index >= q->capacity) {
			return SIZE_MAX;
		}
		/* Read from dedicated free pool pointer */
		const uint_fast32_t next = atomic_load_explicit(
			&q->items[index].nextfree, memory_order_acquire);
		const uint_fast32_t new_pool = MAKE_HANDLE(old_pool, next);
		if (atomic_compare_exchange_weak_explicit(
			    &q->pool, &old_pool, new_pool, memory_order_acq_rel,
			    memory_order_acquire)) {
			return index;
		}
	}
}

static void mitem_free(struct mpmc_queue *q, const size_t index)
{
	uint_least32_t old_pool =
		atomic_load_explicit(&q->pool, memory_order_acquire);
	for (;;) {
		const uint_fast32_t old_head = old_pool & UINT32_C(0x0000FFFF);
		const uint_fast32_t new_pool = MAKE_HANDLE(old_pool, index);
		/* Store to dedicated free pool pointer */
		atomic_store_explicit(
			&q->items[index].nextfree, old_head,
			memory_order_relaxed);
		atomic_thread_fence(memory_order_release);
		if (atomic_compare_exchange_weak_explicit(
			    &q->pool, &old_pool, new_pool, memory_order_acq_rel,
			    memory_order_acquire)) {
			return;
		}
	}
}

bool mqueue_push(struct mpmc_queue *q, void *p)
{
	assert(p != NULL);
	const size_t new_item = mitem_alloc(q);
	if (UNLIKELY(new_item == SIZE_MAX)) {
		return false;
	}
	q->items[new_item].payload = p;
	atomic_store_explicit(
		&q->items[new_item].next, INVALID_HANDLE, memory_order_relaxed);

	for (;;) {
		const uint_fast32_t tail =
			atomic_load_explicit(&q->tail, memory_order_acquire);
		const size_t tail_index = tail & UINT32_C(0xFFFF);
		const uint_fast32_t next = atomic_load_explicit(
			&q->items[tail_index].next, memory_order_acquire);
		const uint_fast32_t tail2 =
			atomic_load_explicit(&q->tail, memory_order_acquire);
		if (UNLIKELY(tail != tail2)) {
			continue;
		}
		const size_t next_index = next & UINT32_C(0xFFFF);
		if (next_index >= q->capacity) {
			/* tail->next is NULL, try to link new node */
			const uint_fast32_t new_next =
				MAKE_HANDLE(next, new_item);
			if (atomic_compare_exchange_weak_explicit(
				    &q->items[tail_index].next,
				    &(uint_least32_t){ next }, new_next,
				    memory_order_release,
				    memory_order_relaxed)) {
				/* Try to swing tail to new node */
				const uint_fast32_t new_tail =
					MAKE_HANDLE(tail, new_item);
				atomic_compare_exchange_strong_explicit(
					&q->tail, &(uint_least32_t){ tail },
					new_tail, memory_order_release,
					memory_order_relaxed);
				return true;
			}
		} else {
			/* tail is lagging, help advance it */
			const uint_fast32_t new_tail =
				MAKE_HANDLE(tail, next_index);
			atomic_compare_exchange_strong_explicit(
				&q->tail, &(uint_least32_t){ tail }, new_tail,
				memory_order_release, memory_order_relaxed);
		}
	}
}

void *mqueue_pop(struct mpmc_queue *q)
{
	for (;;) {
		const uint_fast32_t head =
			atomic_load_explicit(&q->head, memory_order_acquire);
		const uint_fast32_t tail =
			atomic_load_explicit(&q->tail, memory_order_acquire);
		const size_t head_index = head & UINT32_C(0xFFFF);
		const uint_fast32_t next = atomic_load_explicit(
			&q->items[head_index].next, memory_order_acquire);
		const uint_fast32_t head2 =
			atomic_load_explicit(&q->head, memory_order_acquire);
		if (UNLIKELY(head != head2)) {
			continue;
		}
		const size_t next_index = next & UINT32_C(0xFFFF);
		if (head == tail) {
			/* Queue appears empty or tail is lagging */
			if (next_index >= q->capacity) {
				/* Queue is empty */
				return NULL;
			}
			/* Tail is lagging, help advance it */
			const uint_fast32_t new_tail =
				MAKE_HANDLE(tail, next_index);
			atomic_compare_exchange_strong_explicit(
				&q->tail, &(uint_least32_t){ tail }, new_tail,
				memory_order_release, memory_order_relaxed);
		} else {
			if (next_index >= q->capacity) {
				/* Inconsistent state, retry */
				continue;
			}
			/* Read value before CAS, as another dequeue may free the node */
			void *const p = q->items[next_index].payload;
			const uint_fast32_t new_head =
				MAKE_HANDLE(head, next_index);
			if (atomic_compare_exchange_weak_explicit(
				    &q->head, &(uint_least32_t){ head },
				    new_head, memory_order_release,
				    memory_order_relaxed)) {
				/* Successfully dequeued, free the old head (sentinel) */
				mitem_free(q, head_index);
				return p;
			}
		}
	}
}

void mqueue_free(struct mpmc_queue *q)
{
	free(q);
}
