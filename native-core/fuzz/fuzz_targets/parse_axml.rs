#![no_main]
use libfuzzer_sys::fuzz_target;
use unirevlab_native_core::{parse_axml, AxmlLimits};

fuzz_target!(|data: &[u8]| {
    // Tight limits keep a single fuzz iteration deterministic and resistant to resource amplification.
    let limits = AxmlLimits {
        max_bytes: 512 * 1024,
        max_chunks: 10_000,
        max_strings: 10_000,
        max_elements: 10_000,
        max_attributes_per_element: 512,
        max_string_bytes: 64 * 1024,
    };
    let _ = parse_axml(data, limits);
});
