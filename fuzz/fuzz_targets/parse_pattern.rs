#![no_main]
use libfuzzer_sys::fuzz_target;
use ngrind::pattern::{Alphabet, Pattern};

fuzz_target!(|data: &[u8]| {
    if data.len() > 512 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let (alphabet, rest) = if let Some(rest) = text.strip_prefix('n') {
        (Alphabet::Npub, rest)
    } else {
        (Alphabet::Hex, text.as_ref())
    };
    let mid = rest
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|i| *i <= rest.len() / 2)
        .last()
        .unwrap_or(0);
    let (a, b) = rest.split_at(mid);
    if let Ok(pattern) = Pattern::parse(alphabet, a, b) {
        let zero = [0u8; 32];
        let _ = pattern.matches(&zero);
        let _ = pattern.bits();
        let _ = pattern.expected();
        let _ = pattern.prefilter_hex();
    }
});
