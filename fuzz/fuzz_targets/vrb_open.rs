#![no_main]
use libfuzzer_sys::fuzz_target;
use vulngraph_dataset::vrb::VrbReader;

fuzz_target!(|data: &[u8]| {
    // Must never panic on arbitrary bytes; a valid parse must be queryable.
    if let Ok(reader) = VrbReader::from_bytes(data) {
        let _ = reader.lookup("npm:lodash");
        let _ = reader.package_count();
    }
});
