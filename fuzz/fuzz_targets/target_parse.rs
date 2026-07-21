#![no_main]
use libfuzzer_sys::fuzz_target;
use vulngraph_core::target::Target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(target) = text.parse::<Target>() {
            // Canonical form must round-trip.
            let canonical = target.value().to_string();
            let reparsed = canonical.parse::<Target>().expect("canonical must reparse");
            assert_eq!(reparsed.value(), canonical);
        }
    }
});
