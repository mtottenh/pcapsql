//! Running the object store's futures from synchronous readers.

use std::sync::OnceLock;

use tokio::runtime::{Handle, RuntimeFlavor};

/// Execute an async operation, handling runtime nesting correctly.
///
/// - Inside a tokio runtime: `block_in_place` + `block_on` on the current handle.
/// - On a plain thread with a `saved` handle (captured when the source was
///   opened inside a runtime, then handed to parse worker threads): run the
///   future on that runtime. This is the partitioned-parse case; without it
///   every byte-range GET from a worker thread would build and tear down a
///   fresh runtime, re-establishing the HTTP connection pool each time.
/// - Otherwise: a temporary single-threaded runtime.
/// - On a `current_thread` runtime (`#[tokio::test]`, `#[tokio::main(flavor =
///   "current_thread")]`) neither `block_in_place` nor `Handle::block_on` from
///   another thread can work: the former panics, the latter never drives the
///   runtime's I/O driver while the runtime thread is blocked. Such callers,
///   and plain threads without a saved handle, use a dedicated multi-thread
///   I/O runtime owned by this module, driven from a helper thread.
pub(super) fn run_async<F, T>(saved: Option<&Handle>, future: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(future))
        }
        // Inside a current_thread runtime: cannot block here.
        Ok(_) => io_runtime_block_on(future),
        Err(_) => match saved {
            Some(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
                handle.block_on(future)
            }
            _ => io_runtime_block_on(future),
        },
    }
}

/// A runtime handle worth saving for worker threads: only a multi-thread
/// runtime can be driven from a thread that is not its own.
pub(super) fn saveable_handle() -> Option<Handle> {
    Handle::try_current()
        .ok()
        .filter(|h| h.runtime_flavor() == RuntimeFlavor::MultiThread)
}

/// Run `future` to completion on the module's dedicated I/O runtime from a
/// helper thread, so it is safe to call from inside any tokio context.
fn io_runtime_block_on<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    static IO_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let rt = IO_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("pcapsql-cloud-io")
            .enable_all()
            .build()
            .expect("Failed to create cloud I/O runtime")
    });
    std::thread::scope(|s| {
        s.spawn(|| rt.handle().block_on(future))
            .join()
            .expect("cloud I/O future panicked")
    })
}
