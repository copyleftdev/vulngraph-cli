#![no_main]
use libfuzzer_sys::fuzz_target;
use vulngraph_core::manifest::ReleaseManifest;

fuzz_target!(|data: &[u8]| {
    let _ = ReleaseManifest::parse_json(data);
});
