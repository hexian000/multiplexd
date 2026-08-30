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
 * @return The new executor, or NULL if nworkers or capacity is 0, an
 * allocation or synchronization initialization fails, or a worker thread
 * cannot be created.
 */
struct executor *executor_create(size_t nworkers, size_t capacity);

/**
 * @brief Enqueue a task for asynchronous execution (thread-safe).
 * @param[in] e The executor.
 * @param[in] task Task to be scheduled.
 * @return true on success, false if the queue is full or the executor is
 * shutting down (executor_join/executor_detach has been called).
 * @note Calling this concurrently with or after executor_join/executor_detach
 * returns is not supported and may still crash; this only covers the
 * case where exit_flag is already observably set. The one exception is a task
 * still running on this executor after executor_detach, which keeps it alive:
 * there this returns false (see executor_detach).
 */
bool executor_invoke(struct executor *e, struct task task);

/**
 * @brief Blocks the current thread until the executor finishes and free all resources used by it.
 * @details Every task already submitted runs before this returns; the queue is
 * drained rather than dropped, which is what keeps a packaged_task's closure
 * from leaking (see packaged_task.h).
 * @param[in] e The executor.
 * @warning Must not be called from a task running on this executor: joining a
 * worker thread with itself can never complete. Checked in every build;
 * violating it aborts. To shut down from within a task, use executor_detach().
 */
void executor_join(struct executor *e);

/**
 * @brief Detaches the executor. The resources held by the executor will be freed automatically once the executor finishes.
 * @details As with executor_join, every task already submitted runs before the
 * executor is freed; the queue is drained rather than dropped, so a
 * packaged_task's closure does not leak (see packaged_task.h). Unlike
 * executor_join, this may be called from a task running on this executor.
 * @param[in] e The executor.
 * @warning After this returns the executor may be freed at any time, so the
 * caller must not use @p e again. The one exception is a task still running on
 * this executor, which keeps it alive until the task returns: executor_invoke
 * from such a task returns false.
 */
void executor_detach(struct executor *e);

/** @} */

#endif /* SYNC_EXECUTOR_H */
