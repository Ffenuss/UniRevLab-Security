mod axml;

pub use axml::{parse_axml, AxmlAttribute, AxmlDocument, AxmlElement, AxmlError, AxmlLimits};
use sha2::{Digest, Sha256};

/// Computes a stable fingerprint without executing the supplied bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// A bounded native-analysis boundary. Every parser must enforce its own nested limits as well.
pub struct AnalysisLimits {
    pub max_input_bytes: u64,
    pub max_archive_entries: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 2 * 1024 * 1024 * 1024,
            max_archive_entries: 20_000,
        }
    }
}

#[cfg(target_os = "android")]
mod android_jni {
    use super::{parse_axml, AxmlLimits};
    use jni::objects::{JByteArray, JObject};
    use jni::sys::jstring;
    use jni::JNIEnv;

    /// Narrow JNI boundary: binary AndroidManifest bytes in, JSON AST out.
    /// No file access, process access, or target-code execution is available through this API.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_org_unirevlab_security_nativecore_NativeAnalysis_parseAxmlJson(
        mut env: JNIEnv,
        _object: JObject,
        input: JByteArray,
    ) -> jstring {
        let result = env
            .convert_byte_array(&input)
            .map_err(|e| e.to_string())
            .and_then(|bytes| parse_axml(&bytes, AxmlLimits::default()).map_err(|e| e.to_string()))
            .and_then(|doc| serde_json::to_string(&doc).map_err(|e| e.to_string()));

        let output = match result {
            Ok(json) => json,
            Err(error) => serde_json::json!({ "error": error }).to_string(),
        };
        match env.new_string(output) {
            Ok(value) => value.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_value() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
