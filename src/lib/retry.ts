// --- Default Configuration Constants ---
const DEFAULT_LIMIT = 2;
const DEFAULT_INITIAL_DELAY = 0;
const DEFAULT_MAX_DELAY = Infinity;

/**
 * Configuration options for the backoff strategy.
 */
export interface BackoffOptions {
    /**
     * The initial delay in milliseconds before the first retry attempt.
     * Set to a value greater than 0 to enable a delay. Subsequent retries
     * will use an exponential backoff strategy (delay doubles with each attempt).
     * @default 0
     */
    initialDelay?: number;

    /**
     * The maximum delay in milliseconds allowed between retries. This puts a cap
     * on the exponential backoff, preventing excessively long wait times.
     * Use `Infinity` for no upper limit.
     * @default Infinity
     */
    maxDelay?: number;
}

/**
 * Configuration options for the retryTask function.
 */
export interface RetryOptions<TResult> {
    /**
     * The maximum number of retry attempts to make after the initial failure.
     * For example, a limit of 2 means the task will be executed a total of 3 times
     * (the initial attempt + 2 retries).
     * @default 2
     */
    limit?: number;

    /**
     * Configuration for the backoff strategy used between retries.
     * If this is not provided, retries will be attempted immediately without any delay.
     */
    backoff?: BackoffOptions;

    /**
     * An optional callback function that is executed before each retry attempt.
     * It receives the error that caused the failure, the upcoming attempt number,
     * and the calculated delay. This is useful for logging or side effects.
     * If this callback throws an error, it will be logged but will not stop the
     * retry process.
     *
     * @param error The error that triggered the retry.
     * @param attempt The number of the upcoming retry attempt (e.g., 1 for the first retry).
     * @param delay The delay in milliseconds before the next attempt.
     * @param limit The maximum number of retry attempts set in the `RetryOptions`.
     */
    onRetry?: (
        error: unknown,
        attempt: number,
        delay: number,
        limit: number,
    ) => void | PromiseLike<void>;
}

/**
 * Executes an asynchronous task and automatically retries it if it fails.
 * By default, retries happen immediately without any delay. An exponential
 * backoff delay can be enabled by setting the `initialDelay` option.
 *
 * This function is useful for handling transient errors in network requests or
 * other operations that might succeed on a subsequent attempt.
 *
 * @template TResult The expected result type of the asynchronous task.
 * @param {() => Promise<TResult>} taskFn The asynchronous function to execute.
 *   This function should not take any arguments and must return a Promise.
 * @param {RetryOptions<TResult>} [options={}] Optional configuration to control
 *   the retry behavior, such as the number of retries and delay timings.
 * @returns {Promise<TResult>} A promise that either resolves with the task's
 *   successful result or rejects with the last error encountered after all
 *   attempts have been exhausted.
 * @example
 * ```ts
 * import { retry } from "usefulljs/retry";
 *
 * // Example: Retrying a failing network request
 * let attempt = 0;
 * async function fetchUnreliableData() {
 *   attempt++;
 *   console.log(`Attempt #${attempt}...`);
 *   if (attempt < 3) {
 *     throw new Error("Network error");
 *   }
 *   return { data: "Finally!" };
 * }
 *
 * const data = await retry(fetchUnreliableData, {
 *   limit: 3,
 *   backoff: {
 *     initialDelay: 100,
 *   },
 *   onRetry: (error, attempt) => {
 *     console.log(`Attempt ${attempt} failed. Retrying...`);
 *   },
 * });
 *
 * console.log(data); // { data: 'Finally!' }
 * ```
 */
export async function retry<TResult>(
    taskFn: () => Promise<TResult>,
    options: RetryOptions<TResult> = {},
): Promise<TResult> {
    const { limit = DEFAULT_LIMIT, backoff, onRetry } = options;

    const initialDelay = backoff?.initialDelay ?? DEFAULT_INITIAL_DELAY;
    const maxDelay = backoff?.maxDelay ?? DEFAULT_MAX_DELAY;

    let lastError: unknown;

    for (let attempt = 0; attempt <= limit; attempt++) {
        try {
            return await taskFn();
        } catch (error) {
            lastError = error;

            if (attempt === limit) {
                break;
            }

            const exponentialDelay = initialDelay * Math.pow(2, attempt);
            const delay = Math.min(exponentialDelay, maxDelay);

            if (typeof onRetry === "function") {
                try {
                    const currAttempt = attempt + 1;
                    const ret = onRetry(error, currAttempt, delay, limit);
                    if (ret instanceof Promise) await ret;
                } catch (onRetryError: any) {
                    if (onRetryError instanceof Error) {
                        onRetryError.message = `Error within onRetry callback: ${onRetryError.message}`;
                        throw onRetryError;
                    } else {
                        throw new Error(
                            `Error within onRetry callback: ${onRetryError}`,
                            { cause: onRetryError },
                        );
                    }
                }
            }

            // Only introduce a delay if it's greater than 0.
            if (delay > 0) {
                await new Promise((resolve) => setTimeout(resolve, delay));
            }
        }
    }

    throw lastError;
}
