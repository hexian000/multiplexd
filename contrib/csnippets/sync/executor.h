/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SYNC_EXECUTOR_H
#define SYNC_EXECUTOR_H

#include "task.h"

#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup executor
 * @brief The asynchronous task executor.
 * @{
 */

struct executor;

/**
 * @brief Create a new executor.
 * @param[in] nworkers Number of worker threads; must be >= 1.
 * @param[in] capacity Maximum number of tasks the bounded queue can hold; must
 * be >= 1.
 * @return The new executor, or NULL if nworkers or capacity is 0, or on
 * allocation failure.
 */
struct executor *executor_create(size_t nworkers, size_t capacity);

/**
 * @brief Submit a task to executor.
 * @param[in] e The executor.
 * @param[in] task Task to be scheduled.
 * @return true on success, false if the queue is full or the executor is
 * shutting down (executor_join/executor_detach has been called).
 * @note Submitting concurrently with or after executor_join/executor_detach
 * returns is not supported and may still crash; this only covers the
 * case where exit_flag is already observably set.
 */
bool executor_submit(struct executor *e, struct task task);

/**
 * @brief Blocks the current thread until the executor finishes and free all resources used by it.
 * @param[in] e The executor.
 */
void executor_join(struct executor *e);

/**
 * @brief Detaches the executor. The resources held by the executor will be freed automatically once the executor finishes.
 * @param[in] e The executor.
 */
void executor_detach(struct executor *e);

/** @} */

#endif /* SYNC_EXECUTOR_H */
