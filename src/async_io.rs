use core::time::Duration;

use tokio::sync::Mutex;
use tokio::time::sleep;

pub type AsyncMytex<T> = Mutex<T>;

pub fn async_spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future)
}

pub async fn async_sleep(duration: Duration) {
    sleep(duration).await;
}
