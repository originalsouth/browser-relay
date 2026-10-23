//! Portable policy, QR, certificate and domain-index core. No desktop toolkit required.
pub mod cache;
pub mod certificate;
pub mod certificate_history;
pub mod ct_logs;
pub mod ct_proof;
pub mod display_text;
#[cfg(any(feature = "desktop", feature = "apple"))]
pub mod geo;
pub mod insights;
pub mod registration;
pub mod risk;
pub mod route;
pub mod transparency;
pub type Cancel = std::sync::Arc<std::sync::atomic::AtomicBool>;
#[cfg(feature = "apple")]
mod apple;
pub mod domain_list;
pub mod link;
pub mod lookalike;
pub mod qr;
pub type Result<T> = std::result::Result<T, String>;

/// A caught panic must not disable later calls or expose partially changed state.
pub(crate) fn recover_lock<T: Default>(
    mutex: &std::sync::Mutex<T>,
) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        let mut state = poisoned.into_inner();
        *state = T::default();
        mutex.clear_poison();
        state
    })
}
