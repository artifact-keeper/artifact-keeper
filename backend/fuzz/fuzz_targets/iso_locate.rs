//! Fuzz the ISO9660 rootfs locator (#1966) over arbitrary bytes.
//!
//! The locator is compiled on its own from the backend source (it has no
//! crate imports), so this target builds in seconds and exercises exactly the
//! code the scan runs. Invariants: no panic, no unbounded work, and a located
//! range always lies inside the input.
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/services/iso_rootfs/locator.rs"]
#[allow(dead_code)]
mod locator;

fuzz_target!(|data: &[u8]| {
    let detected = locator::is_iso9660(data);
    match locator::locate_rootfs(data) {
        Ok(found) => {
            assert!(detected, "located a rootfs in bytes that are not ISO9660");
            let end = found.offset.checked_add(found.len);
            assert!(
                end.is_some_and(|e| e <= data.len() as u64),
                "located range {:?} outside an input of {} bytes",
                found,
                data.len()
            );
        }
        Err(locator::LocateError::NotIso9660) => assert!(!detected),
        Err(e) => {
            assert!(detected);
            let _ = e.to_string();
        }
    }
});
