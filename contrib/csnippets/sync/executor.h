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
 * @param[in] nworkers Number of worker threads.
 * @return If malloc failed, returns NULL.
 */
struct executor *executor_create(size_t nworkers);

/**
 * @brief Submit a task to executor.
 * @param[in] e The executor.
 * @param[in] task Task to be scheduled.
 * @return If malloc failed, returns false and no operation is performed.
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
