use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use atomic::Atomic;

#[derive(Debug)] 
pub struct AppState {
    pub last_key_processed: Atomic<u128>,
}

impl AppState {
    pub fn new(target_address: &str) -> Self {
        AppState {
            last_key_processed: Atomic::new(0),
        }
    }
} 