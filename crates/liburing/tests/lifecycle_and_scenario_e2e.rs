//! Four complementary real-kernel test dimensions for the public runtime API.
//!
//! Ring creation and required kernel capabilities are mandatory. Every group
//! uses bounded completion waits and asserts outcomes rather than skipping work.

#[path = "lifecycle_and_scenario_e2e/integration.rs"]
mod integration;

#[path = "lifecycle_and_scenario_e2e/lifecycle.rs"]
mod lifecycle;

#[path = "lifecycle_and_scenario_e2e/scenario.rs"]
mod scenario;

#[path = "lifecycle_and_scenario_e2e/e2e.rs"]
mod e2e;

fn kernel_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    match SERIAL.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
