use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub fn hash_json(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn build_manifest(sections: &[(&str, &str)]) -> HashMap<String, String> {
    sections
        .iter()
        .map(|(name, content)| (name.to_string(), hash_json(content)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let h1 = hash_json("hello");
        let h2 = hash_json("hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        assert_ne!(hash_json("hello"), hash_json("world"));
    }

    #[test]
    fn hash_is_64_hex_chars() {
        assert_eq!(hash_json("test").len(), 64);
    }

    #[test]
    fn build_manifest_returns_all_keys() {
        let m = build_manifest(&[("host", "{\"a\":1}"), ("procs", "[1,2,3]")]);
        assert!(m.contains_key("host"));
        assert!(m.contains_key("procs"));
    }
}
