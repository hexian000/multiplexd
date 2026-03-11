/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SYNC_QUEUE_H
#define SYNC_QUEUE_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup spsc_queue
 * @brief The single-producer/single-consumer concurrent queue.
 * @{
 */

struct spsc_queue;

struct spsc_queue *squeue_new(size_t capacity);
bool squeue_push(struct spsc_queue *q, void *p);
void *squeue_pop(struct spsc_queue *q);
void squeue_free(struct spsc_queue *q);

/** @} */

/**
 * @defgroup mpmc_queue
 * @brief The concurrent queue.
 * @details requires: capacity <= 65534 && concurrency <= 65535
 * The implementation is lockfree if platforms supports 32-bit atomic integers.
 * @{
 */

struct mpmc_queue;

struct mpmc_queue *mqueue_new(size_t capacity);
bool mqueue_push(struct mpmc_queue *q, void *p);
void *mqueue_pop(struct mpmc_queue *q);
void mqueue_free(struct mpmc_queue *q);

/** @} */

#endif /* SYNC_QUEUE_H */
