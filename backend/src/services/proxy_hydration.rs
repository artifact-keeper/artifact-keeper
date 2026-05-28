use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Notify};

pub const DEFAULT_PROXY_HYDRATION_WAIT_TIMEOUT: Duration = Duration::from_secs(65);

const FOLLOWER_WAIT_SLICE: Duration = Duration::from_millis(250);

type LocalHydrationMap = Arc<Mutex<HashMap<String, Arc<Notify>>>>;

enum LocalHydrationRole {
    Leader(Arc<Notify>),
    Follower(Arc<Notify>),
}

fn local_hydration_map() -> &'static LocalHydrationMap {
    static LOCAL_HYDRATIONS: OnceLock<LocalHydrationMap> = OnceLock::new();
    LOCAL_HYDRATIONS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

async fn acquire_local_hydration(key: &str) -> LocalHydrationRole {
    let map = local_hydration_map();
    let mut guard = map.lock().await;
    if let Some(existing) = guard.get(key) {
        return LocalHydrationRole::Follower(existing.clone());
    }

    let notify = Arc::new(Notify::new());
    guard.insert(key.to_string(), notify.clone());
    LocalHydrationRole::Leader(notify)
}

async fn release_local_hydration(key: &str, notify: &Arc<Notify>) {
    let map = local_hydration_map();
    let mut guard = map.lock().await;
    let should_remove = guard
        .get(key)
        .map(|current| Arc::ptr_eq(current, notify))
        .unwrap_or(false);
    if should_remove {
        guard.remove(key);
    }
    drop(guard);
    notify.notify_waiters();
}

pub async fn coordinate_proxy_hydration<T, E, Check, CheckFut, Produce, ProduceFut, TimeoutErr>(
    lease_key: &str,
    check: Check,
    produce: Produce,
    timeout_error: TimeoutErr,
) -> std::result::Result<T, E>
where
    Check: Fn() -> CheckFut,
    CheckFut: Future<Output = std::result::Result<Option<T>, E>>,
    Produce: FnOnce() -> ProduceFut,
    ProduceFut: Future<Output = std::result::Result<T, E>>,
    TimeoutErr: Fn() -> E,
{
    let deadline = Instant::now() + DEFAULT_PROXY_HYDRATION_WAIT_TIMEOUT;
    let mut produce = Some(produce);

    loop {
        if let Some(value) = check().await? {
            return Ok(value);
        }

        if Instant::now() >= deadline {
            return Err(timeout_error());
        }

        match acquire_local_hydration(lease_key).await {
            LocalHydrationRole::Follower(notify) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(timeout_error());
                }

                let _ = tokio::time::timeout(remaining.min(FOLLOWER_WAIT_SLICE), notify.notified()).await;
            }
            LocalHydrationRole::Leader(notify) => {
                let result = async {
                    if let Some(value) = check().await? {
                        return Ok(value);
                    }

                    if Instant::now() >= deadline {
                        return Err(timeout_error());
                    }

                    produce
                        .take()
                        .expect("proxy hydration producer should only run once")()
                        .await
                }
                .await;

                release_local_hydration(lease_key, &notify).await;
                return result;
            }
        }
    }
}