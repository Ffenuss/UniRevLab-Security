use il2cpp_dumper::config::Config;
use il2cpp_dumper::executor::Il2CppExecutor;
use il2cpp_dumper::formats::elf::Elf;
use il2cpp_dumper::il2cpp::base::Il2Cpp;
use il2cpp_dumper::il2cpp::metadata::Metadata;
use il2cpp_dumper::output::decompiler::Il2CppDecompiler;
use il2cpp_dumper::output::struct_generator::StructGenerator;
use serde::Serialize;
use std::fs;
use std::path::Path;
use thiserror::Error;

const METADATA_MAGIC: [u8; 4] = [0xAF, 0x1B, 0xB1, 0xFA];
const MAX_BINARY_BYTES: u64 = 768 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum Il2CppDumpError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("IL2CPP metadata is invalid or protected: {0}")]
    Metadata(String),
    #[error("IL2CPP binary is invalid or unsupported: {0}")]
    Binary(String),
    #[error("automatic registration discovery failed: {0}")]
    Registration(String),
    #[error("dump generation failed: {0}")]
    Engine(String),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Il2CppDumpManifest {
    pub status: &'static str,
    pub engine: &'static str,
    pub engine_revision: &'static str,
    pub metadata_version: f64,
    pub architecture: String,
    pub type_count: usize,
    pub method_count: usize,
    pub image_count: usize,
    pub code_registration: String,
    pub metadata_registration: String,
    pub registration_strategy: &'static str,
    pub generated_files: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn dump_il2cpp_pair(
    binary_path: &Path,
    metadata_path: &Path,
    output_dir: &Path,
) -> Result<Il2CppDumpManifest, Il2CppDumpError> {
    validate_regular_file(binary_path, MAX_BINARY_BYTES, "libil2cpp.so")?;
    validate_regular_file(metadata_path, MAX_METADATA_BYTES, "global-metadata.dat")?;
    fs::create_dir_all(output_dir)?;

    let metadata_bytes = fs::read(metadata_path)?;
    if metadata_bytes.get(..4) != Some(METADATA_MAGIC.as_slice()) {
        return Err(Il2CppDumpError::Metadata(
            "magic AF 1B B1 FA not found; use a legitimate runtime-decrypted metadata capture when the target protects metadata".into(),
        ));
    }
    let mut metadata = Metadata::new_with_options(metadata_bytes, None, false)
        .map_err(|e| Il2CppDumpError::Metadata(e.user_message()))?;

    let binary_bytes = fs::read(binary_path)?;
    if binary_bytes.get(..4) != Some(b"\x7fELF") {
        return Err(Il2CppDumpError::Binary("expected an ELF libil2cpp.so".into()));
    }
    let is_32bit = binary_bytes.get(4).copied() == Some(1);
    let mut elf = Elf::new(binary_bytes, is_32bit)
        .map_err(|e| Il2CppDumpError::Binary(e.to_string()))?;
    elf.set_properties(metadata.version, metadata.metadata_usages_count as u64);
    if elf.check_dump() {
        return Err(Il2CppDumpError::Binary(
            "memory-dump layout needs a known image base; this build accepts normal APK ELF files automatically".into(),
        ));
    }

    let method_count = metadata.method_defs.iter().filter(|m| m.method_index >= 0).count();
    let mut code_registration;
    let mut metadata_registration;
    {
        let mut helper = elf.get_section_helper(method_count, metadata.type_defs.len(), metadata.image_defs.len());
        code_registration = helper.find_code_registration();
        metadata_registration = helper.find_metadata_registration();
    }
    let mut strategy = "section-scan";
    let mut initialized = elf.auto_plus_init(code_registration, metadata_registration)
        .map_err(|e| Il2CppDumpError::Registration(e.to_string()))?;

    if !initialized {
        if let Some((cr, mr)) = elf.symbol_search()
            .map_err(|e| Il2CppDumpError::Registration(e.to_string()))?
        {
            if elf.init_with_auto_plus(cr, mr).is_ok() {
                code_registration = Some(cr);
                metadata_registration = Some(mr);
                strategy = "symbol-table";
                initialized = true;
            }
        }
    }
    if !initialized && is_32bit {
        if let Some((cr, mr)) = elf.search_arm32(metadata.version) {
            if elf.init_with_auto_plus(cr, mr).is_ok() {
                code_registration = Some(cr);
                metadata_registration = Some(mr);
                strategy = "arm32-pattern";
                initialized = true;
            }
        }
    }
    if !initialized {
        return Err(Il2CppDumpError::Registration(
            "CodeRegistration/MetadataRegistration were not validated. The pair may not match, the binary may be protected, or the Unity layout is not supported. No offsets were emitted.".into(),
        ));
    }

    let exports = elf.list_exported_symbols().unwrap_or_default();
    let mut il2cpp = Il2Cpp::from_elf(&elf);
    il2cpp.exported_symbols = exports.iter().map(|(name, _)| name.clone()).collect();
    for (name, address) in exports {
        if name.starts_with("il2cpp_") || name.starts_with("mono_") {
            let rva = il2cpp.get_rva(address);
            il2cpp.api_export_rvas.insert(name, rva);
        }
    }

    let mut config = Config::default();
    config.generate_dummy_dll = false;
    config.generate_generics_dump = false;
    config.dump_disassembly = false;
    config.split_dump_per_type = false;
    config.dump_static_field_metadata = false;
    config.generate_struct = true;

    let mut executor = Il2CppExecutor::new(&metadata, &mut il2cpp)
        .map_err(|e| Il2CppDumpError::Engine(e.to_string()))?;
    let output = output_dir.to_string_lossy();
    Il2CppDecompiler::decompile(
        &mut executor,
        &metadata,
        &il2cpp,
        &config,
        &output,
        |_| {},
    ).map_err(|e| Il2CppDumpError::Engine(e.to_string()))?;
    StructGenerator::write_all(
        &mut executor,
        &mut metadata,
        &mut il2cpp,
        &config,
        &output,
        None,
    ).map_err(|e| Il2CppDumpError::Engine(e.to_string()))?;

    let generated_files = collect_generated_files(output_dir)?;
    if !generated_files.iter().any(|name| name == "dump.cs") {
        return Err(Il2CppDumpError::Engine("engine returned without dump.cs".into()));
    }
    let manifest = Il2CppDumpManifest {
        status: "COMPLETE",
        engine: "rodroid-il2cpp-dumper-rs",
        engine_revision: "8bfb90229539833999e725c5cf6402a435b47f15",
        metadata_version: metadata.version,
        architecture: il2cpp.detect_architecture().to_string(),
        type_count: metadata.type_defs.len(),
        method_count: metadata.method_defs.len(),
        image_count: metadata.image_defs.len(),
        code_registration: format!("0x{:X}", code_registration.unwrap_or_default()),
        metadata_registration: format!("0x{:X}", metadata_registration.unwrap_or_default()),
        registration_strategy: strategy,
        generated_files,
        warnings: vec![
            "Semantic classification is audit triage, not proof that a client-side modification succeeds.".into(),
            "Only RVAs emitted by the initialized IL2CPP engine are treated as resolved.".into(),
        ],
    };
    fs::write(output_dir.join("unirevlab-dump-manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(manifest)
}

fn validate_regular_file(path: &Path, max_bytes: u64, label: &str) -> Result<(), Il2CppDumpError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(Il2CppDumpError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{label} is not a regular file"))));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(Il2CppDumpError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{label} size is outside 1..={max_bytes} bytes"))));
    }
    Ok(())
}

fn collect_generated_files(dir: &Path) -> Result<Vec<String>, std::io::Error> {
    let mut result = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            result.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    result.sort();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_metadata_without_creating_fake_dump() {
        let base = std::env::temp_dir().join(format!("unirevlab-il2cpp-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let binary = base.join("libil2cpp.so");
        let metadata = base.join("global-metadata.dat");
        let output = base.join("output");
        fs::write(&binary, b"\x7fELF\x02placeholder").unwrap();
        fs::write(&metadata, b"not metadata").unwrap();
        let error = dump_il2cpp_pair(&binary, &metadata, &output).unwrap_err();
        assert!(error.to_string().contains("magic"));
        assert!(!output.join("dump.cs").exists());
        let _ = fs::remove_dir_all(base);
    }
}
