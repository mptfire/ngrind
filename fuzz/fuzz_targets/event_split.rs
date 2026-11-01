#![no_main]
use libfuzzer_sys::fuzz_target;
use ngrind::event::{parse_tags, Template};
use sha2::Digest;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let content = value
        .get("content")
        .and_then(|c| c.as_str())
        .unwrap_or_default();
    let kind = value
        .get("kind")
        .and_then(|k| k.as_u64())
        .and_then(|k| u16::try_from(k).ok())
        .unwrap_or(1);
    let difficulty = value
        .get("difficulty")
        .and_then(|d| d.as_u64())
        .map(|d| (d % 256 + 1) as u32)
        .unwrap_or(16);
    let Ok(tags) = parse_tags(
        &value
            .get("tags")
            .map(|t| t.to_string())
            .unwrap_or_else(|| "[]".into()),
    ) else {
        return;
    };
    let created_at = 1_700_000_000u64;
    for fast in [true, false] {
        let template = Template {
            pubkey: "ab".repeat(32),
            kind,
            tags: tags.clone(),
            content: content.to_string(),
            difficulty,
            fast,
        };
        let split = template.split(created_at);
        for nonce in [0u64, 1, 42, u64::MAX / 3, u64::MAX] {
            let mined = template.mined(nonce);
            let joined = format!("{}{}{}", split.prefix, nonce, split.suffix);
            // the mined layout must hash to exactly the event id of the
            // re-serialized event, for every nonce and every input shape
            assert_eq!(
                sha2::Sha256::digest(joined.as_bytes()).to_vec(),
                template.id_of(created_at, &mined).to_vec(),
                "split layout diverges from the serialized event (fast: {fast}, nonce: {nonce}, input: {text:?})"
            );
        }
    }
});
