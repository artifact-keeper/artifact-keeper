import { useState, useCallback, useMemo } from 'react';
import { UseQueryResult, UseMutationResult } from '@tanstack/react-query';
import type { AxiosError } from 'axios';
import type { ApiError } from '../types';

/**
 * Error display state for inline error messages
 */
export interface ErrorDisplayState {
  /** Whether there is an error to display */
  hasError: boolean;
  /** The error message to display */
  message: string;
  /** The error code from the API, if available */
  code?: string;
  /** The HTTP status code, if available */
  statusCode?: number;
  /** Whether the error is retryable */
  isRetryable: boolean;
}

/**
 * Return type for the useApiError hook
 */
export interface UseApiErrorReturn {
  /** Current error display state */
  errorState: ErrorDisplayState;
  /** Whether a retry is currently in progress */
  isRetrying: boolean;
  /** Trigger a retry of the failed operation */
  retry: () => void;
  /** Clear the current error state */
  clearError: () => void;
  /** Manually set an error */
  setError: (error: Error | string | null) => void;
}

/**
 * Options for the useApiError hook
 */
export interface UseApiErrorOptions {
  /** Custom error message transformer */
  transformMessage?: (error: Error | AxiosError<ApiError>) => string;
  /** List of HTTP status codes that should be retryable (default: [408, 429, 500, 502, 503, 504]) */
  retryableStatusCodes?: number[];
  /** Default error message when no specific message is available */
  defaultMessage?: string;
}

const DEFAULT_RETRYABLE_STATUS_CODES = [408, 429, 500, 502, 503, 504];
const DEFAULT_ERROR_MESSAGE = 'An unexpected error occurred';

/**
 * Extract error details from various error types
 */
function extractErrorDetails(
  error: Error | AxiosError<ApiError> | string | null | undefined,
  options: UseApiErrorOptions
): { message: string; code?: string; statusCode?: number } {
  if (!error) {
    return { message: '' };
  }

  if (typeof error === 'string') {
    return { message: error };
  }

  // Check if it's an Axios error
  if ('isAxiosError' in error && error.isAxiosError) {
    const axiosError = error as AxiosError<ApiError>;
    const statusCode = axiosError.response?.status;
    const apiError = axiosError.response?.data;

    // Use custom transformer if provided
    if (options.transformMessage) {
      return {
        message: options.transformMessage(axiosError),
        code: apiError?.code,
        statusCode,
      };
    }

    // Use API error message if available
    if (apiError?.message) {
      return {
        message: apiError.message,
        code: apiError.code,
        statusCode,
      };
    }

    // Use Axios error message
    if (axiosError.message) {
      return {
        message: axiosError.message,
        statusCode,
      };
    }

    return {
      message: options.defaultMessage || DEFAULT_ERROR_MESSAGE,
      statusCode,
    };
  }

  // Regular Error object
  if (options.transformMessage) {
    return { message: options.transformMessage(error) };
  }

  return {
    message: error.message || options.defaultMessage || DEFAULT_ERROR_MESSAGE,
  };
}

/**
 * Hook for API error handling with retry functionality
 *
 * Wraps TanStack Query error handling and provides:
 * - Inline error display state
 * - Retry functionality
 * - Error message transformation
 *
 * @example
 * ```tsx
 * // With TanStack Query
 * const query = useQuery({ queryKey: ['items'], queryFn: fetchItems });
 * const { errorState, retry, isRetrying } = useApiError(query);
 *
 * // With mutation
 * const mutation = useMutation({ mutationFn: createItem });
 * const { errorState, retry, isRetrying } = useApiError(mutation);
 *
 * // In JSX
 * {errorState.hasError && (
 *   <ErrorRetry
 *     error={errorState.message}
 *     onRetry={retry}
 *     loading={isRetrying}
 *   />
 * )}
 * ```
 */
export function useApiError<TData = unknown, TError = Error>(
  queryOrMutation?:
    | UseQueryResult<TData, TError>
    | UseMutationResult<TData, TError, unknown>
    | null,
  options: UseApiErrorOptions = {}
): UseApiErrorReturn {
  const {
    retryableStatusCodes = DEFAULT_RETRYABLE_STATUS_CODES,
    defaultMessage = DEFAULT_ERROR_MESSAGE,
  } = options;

  const [manualError, setManualError] = useState<Error | string | null>(null);
  const [isRetrying, setIsRetrying] = useState(false);

  // Get error from query/mutation or manual error
  const error = useMemo(() => {
    if (manualError) return manualError;
    if (queryOrMutation?.error) return queryOrMutation.error as unknown as Error;
    return null;
  }, [manualError, queryOrMutation?.error]);

  // Extract error details
  const errorDetails = useMemo(
    () => extractErrorDetails(error, { ...options, defaultMessage }),
    [error, options, defaultMessage]
  );

  // Determine if error is retryable
  const isRetryable = useMemo(() => {
    if (!error) return false;

    // Check if it's an Axios error with a retryable status code
    if (error && typeof error === 'object' && 'isAxiosError' in error) {
      const statusCode = (error as AxiosError).response?.status;
      if (statusCode && retryableStatusCodes.includes(statusCode)) {
        return true;
      }
    }

    // Network errors are generally retryable
    if (error instanceof Error && error.message === 'Network Error') {
      return true;
    }

    // By default, allow retry for any error
    return true;
  }, [error, retryableStatusCodes]);

  // Build error display state
  const errorState: ErrorDisplayState = useMemo(
    () => ({
      hasError: !!error,
      message: errorDetails.message,
      code: errorDetails.code,
      statusCode: errorDetails.statusCode,
      isRetryable,
    }),
    [error, errorDetails, isRetryable]
  );

  // Retry function
  const retry = useCallback(() => {
    if (!queryOrMutation) return;

    setIsRetrying(true);
    setManualError(null);

    // Check if it's a query (has refetch method)
    if ('refetch' in queryOrMutation) {
      queryOrMutation.refetch().finally(() => {
        setIsRetrying(false);
      });
    }
    // Check if it's a mutation (has reset method)
    else if ('reset' in queryOrMutation) {
      queryOrMutation.reset();
      setIsRetrying(false);
    }
  }, [queryOrMutation]);

  // Clear error
  const clearError = useCallback(() => {
    setManualError(null);
    if (queryOrMutation && 'reset' in queryOrMutation) {
      queryOrMutation.reset();
    }
  }, [queryOrMutation]);

  // Set manual error
  const setError = useCallback((newError: Error | string | null) => {
    setManualError(newError);
  }, []);

  return {
    errorState,
    isRetrying,
    retry,
    clearError,
    setError,
  };
}

/**
 * Standalone hook for manual error handling without TanStack Query
 *
 * @example
 * ```tsx
 * const { errorState, setError, clearError } = useApiErrorState();
 *
 * const handleSubmit = async () => {
 *   try {
 *     clearError();
 *     await api.submit(data);
 *   } catch (err) {
 *     setError(err);
 *   }
 * };
 * ```
 */
export function useApiErrorState(
  options: UseApiErrorOptions = {}
): Omit<UseApiErrorReturn, 'isRetrying' | 'retry'> {
  const [error, setError] = useState<Error | string | null>(null);

  const { defaultMessage = DEFAULT_ERROR_MESSAGE, retryableStatusCodes = DEFAULT_RETRYABLE_STATUS_CODES } =
    options;

  // Extract error details
  const errorDetails = useMemo(
    () => extractErrorDetails(error, { ...options, defaultMessage }),
    [error, options, defaultMessage]
  );

  // Determine if error is retryable
  const isRetryable = useMemo(() => {
    if (!error) return false;

    if (error && typeof error === 'object' && 'isAxiosError' in error) {
      const statusCode = (error as AxiosError).response?.status;
      if (statusCode && retryableStatusCodes.includes(statusCode)) {
        return true;
      }
    }

    if (error instanceof Error && error.message === 'Network Error') {
      return true;
    }

    return true;
  }, [error, retryableStatusCodes]);

  // Build error display state
  const errorState: ErrorDisplayState = useMemo(
    () => ({
      hasError: !!error,
      message: errorDetails.message,
      code: errorDetails.code,
      statusCode: errorDetails.statusCode,
      isRetryable,
    }),
    [error, errorDetails, isRetryable]
  );

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const setErrorCallback = useCallback((newError: Error | string | null) => {
    setError(newError);
  }, []);

  return {
    errorState,
    clearError,
    setError: setErrorCallback,
  };
}

export default useApiError;
