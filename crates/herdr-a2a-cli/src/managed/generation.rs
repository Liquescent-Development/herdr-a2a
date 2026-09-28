use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use std::collections::{BTreeMap, BTreeSet};

use super::{
    ManagedError, ManagedResult, OwnedFile, OwnershipRecord, digest_file, digest_tree, path_text,
    require_absolute_normal, tree_files, valid_digest, validate_owned_file_digest,
    validate_private_directory,
};

pub(crate) const MANAGED_PROTOCOL_MAJOR: u32 = 1;
pub(crate) const MAX_RETAINED_GENERATIONS: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationAuthorization {
    pub plugin_version: String,
    pub protocol_major: u32,
    pub broker_digest: String,
    pub pi_package_digest: String,
    pub pi_package_source: PathBuf,
    pub stable_binary: PathBuf,
    pub owned_files: Vec<OwnedFile>,
}

#[allow(dead_code)] // Consumed by generation-aware process ownership in the dependent task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizedGeneration<'a> {
    Current,
    Retained(&'a GenerationAuthorization),
}

pub(crate) fn validate_catalog(record: &OwnershipRecord, stable_root: &Path) -> ManagedResult<()> {
    validate_catalog_semantics(record, stable_root)?;
    for retained in &record.retained_generations {
        validate_generation(retained, stable_root)?;
    }
    Ok(())
}

fn validate_catalog_semantics(record: &OwnershipRecord, stable_root: &Path) -> ManagedResult<()> {
    if record.protocol_major != MANAGED_PROTOCOL_MAJOR {
        return Err(ManagedError::new(
            "generation_incompatible",
            "current managed generation uses an unsupported protocol major",
        ));
    }
    if record.retained_generations.len() > MAX_RETAINED_GENERATIONS {
        return Err(ManagedError::new(
            "retained_generation_limit",
            "ownership record exceeds the retained generation limit",
        ));
    }
    let current_root = generation_root(
        &record.stable_binary,
        &record.pi_package_source,
        stable_root,
    )?;
    let mut roots = BTreeSet::from([current_root.to_path_buf()]);
    let mut identities =
        BTreeSet::from([(record.stable_binary.clone(), record.broker_digest.clone())]);
    for retained in &record.retained_generations {
        if retained.protocol_major != MANAGED_PROTOCOL_MAJOR {
            return Err(ManagedError::new(
                "generation_incompatible",
                "retained managed generation uses an unsupported protocol major",
            ));
        }
        if retained.plugin_version.is_empty()
            || retained.plugin_version.len() > 128
            || !valid_digest(&retained.broker_digest)
            || !valid_digest(&retained.pi_package_digest)
        {
            return Err(ManagedError::new(
                "ownership_record_invalid",
                "retained generation identity is invalid",
            ));
        }
        let root = generation_root(
            &retained.stable_binary,
            &retained.pi_package_source,
            stable_root,
        )?;
        if !roots.insert(root.to_path_buf())
            || !identities.insert((
                retained.stable_binary.clone(),
                retained.broker_digest.clone(),
            ))
        {
            return Err(ManagedError::new(
                "ownership_record_invalid",
                "managed generation paths or identities overlap",
            ));
        }
    }
    Ok(())
}

fn generation_root<'a>(
    binary: &Path,
    package: &'a Path,
    stable_root: &Path,
) -> ManagedResult<&'a Path> {
    require_absolute_normal(binary, "managed generation binary")?;
    require_absolute_normal(package, "managed generation package")?;
    path_text(binary)?;
    path_text(package)?;
    let root = package.parent().ok_or_else(|| {
        ManagedError::new(
            "ownership_record_invalid",
            "managed generation package has no parent",
        )
    })?;
    if root.parent() != Some(stable_root.join("generations").as_path())
        || package != root.join("pi")
        || binary != root.join("bin/herdr-a2a")
    {
        return Err(ManagedError::new(
            "ownership_record_invalid",
            "managed generation paths are not canonical",
        ));
    }
    Ok(root)
}

fn validate_generation(
    generation: &GenerationAuthorization,
    stable_root: &Path,
) -> ManagedResult<()> {
    let root = generation_root(
        &generation.stable_binary,
        &generation.pi_package_source,
        stable_root,
    )?;
    validate_private_directory(root, 0o700)?;
    if digest_file(&generation.stable_binary)? != generation.broker_digest
        || digest_tree(&generation.pi_package_source)? != generation.pi_package_digest
    {
        return Err(ManagedError::new(
            "owned_asset_modified",
            "retained generation aggregate digests do not match assets",
        ));
    }
    let mut expected_modes = BTreeMap::from([(generation.stable_binary.clone(), 0o700)]);
    for file in tree_files(&generation.pi_package_source)? {
        expected_modes.insert(file, 0o600);
    }
    if generation.owned_files.len() != expected_modes.len() {
        return Err(ManagedError::new(
            "ownership_record_invalid",
            "retained generation owned file set is not exact",
        ));
    }
    let mut seen = BTreeSet::new();
    for owned in &generation.owned_files {
        if !seen.insert(owned.path.clone()) || expected_modes.get(&owned.path) != Some(&owned.mode)
        {
            return Err(ManagedError::new(
                "ownership_record_invalid",
                "retained generation paths or modes are not canonical and unique",
            ));
        }
        validate_owned_file_digest(
            &owned.path,
            owned.mode,
            &owned.sha256,
            "owned_asset_modified",
        )?;
    }
    if tree_files(root)? != expected_modes.keys().cloned().collect::<Vec<_>>() {
        return Err(ManagedError::new(
            "ownership_conflict",
            "retained generation contains unrecorded files",
        ));
    }
    Ok(())
}

#[allow(dead_code)] // Consumed by generation-aware process ownership in the dependent task.
pub(crate) fn authorize_executable<'a>(
    record: &'a OwnershipRecord,
    path: &Path,
    digest: &str,
) -> ManagedResult<AuthorizedGeneration<'a>> {
    if path == record.stable_binary && digest == record.broker_digest {
        return Ok(AuthorizedGeneration::Current);
    }
    record
        .retained_generations
        .iter()
        .find(|generation| generation.stable_binary == path && generation.broker_digest == digest)
        .map(AuthorizedGeneration::Retained)
        .ok_or_else(|| {
            ManagedError::new(
                "owned_process_mismatch",
                "executable is not an authenticated managed generation",
            )
        })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        AuthorizedGeneration, GenerationAuthorization, MAX_RETAINED_GENERATIONS,
        authorize_executable, validate_catalog_semantics,
    };
    use crate::managed::{InstallState, OwnershipRecord};

    fn record() -> OwnershipRecord {
        OwnershipRecord {
            schema_version: 4,
            state: InstallState::Ready,
            plugin_version: "1.0.0".to_owned(),
            protocol_major: 1,
            broker_digest: "a".repeat(64),
            pi_package_digest: "b".repeat(64),
            pi_package_source: PathBuf::from("/stable/generations/current/pi"),
            pi_config_path: PathBuf::from("/home/.pi/agent/settings.json"),
            pi_package_entry: serde_json::json!("/stable/generations/current/pi"),
            purge_authority: false,
            plugin_state_root: PathBuf::new(),
            rescue_path: PathBuf::from("/stable/rescue/uninstall.sh"),
            rescue_marker_digest: "c".repeat(64),
            install_kind: "managed".to_owned(),
            plugin_root: PathBuf::from("/plugin"),
            stable_binary: PathBuf::from("/stable/generations/current/bin/herdr-a2a"),
            ownership_path: PathBuf::from("/stable/ownership.json"),
            owned_files: Vec::new(),
            retained_generations: vec![GenerationAuthorization {
                plugin_version: "0.9.0".to_owned(),
                protocol_major: 1,
                broker_digest: "d".repeat(64),
                pi_package_digest: "e".repeat(64),
                pi_package_source: PathBuf::from("/stable/generations/retained/pi"),
                stable_binary: PathBuf::from("/stable/generations/retained/bin/herdr-a2a"),
                owned_files: Vec::new(),
            }],
            last_error: None,
        }
    }

    #[test]
    fn retained_generation_unknown_fields_fail_closed() {
        let value = serde_json::json!({
            "plugin_version": "1.0.0",
            "protocol_major": 1,
            "broker_digest": "a".repeat(64),
            "pi_package_digest": "b".repeat(64),
            "pi_package_source": "/stable/generations/retained/pi",
            "stable_binary": "/stable/generations/retained/bin/herdr-a2a",
            "owned_files": [],
            "unexpected": true,
        });
        assert!(serde_json::from_value::<GenerationAuthorization>(value).is_err());
    }

    #[test]
    fn exact_current_and_retained_executables_are_authorized() {
        let record = record();
        assert!(matches!(
            authorize_executable(
                &record,
                Path::new("/stable/generations/current/bin/herdr-a2a"),
                &"a".repeat(64),
            ),
            Ok(AuthorizedGeneration::Current)
        ));
        assert!(matches!(
            authorize_executable(
                &record,
                Path::new("/stable/generations/retained/bin/herdr-a2a"),
                &"d".repeat(64),
            ),
            Ok(AuthorizedGeneration::Retained(_))
        ));
        assert!(
            authorize_executable(
                &record,
                Path::new("/stable/generations/retained/bin/herdr-a2a"),
                &"a".repeat(64),
            )
            .is_err()
        );
    }

    #[test]
    fn catalog_rejects_duplicates_protocol_mismatch_path_escape_and_limit() {
        let stable_root = Path::new("/stable");

        let mut duplicate = record();
        duplicate.retained_generations[0].stable_binary = duplicate.stable_binary.clone();
        duplicate.retained_generations[0].pi_package_source = duplicate.pi_package_source.clone();
        assert!(validate_catalog_semantics(&duplicate, stable_root).is_err());

        let mut incompatible = record();
        incompatible.protocol_major = 2;
        assert_eq!(
            validate_catalog_semantics(&incompatible, stable_root)
                .unwrap_err()
                .code,
            "generation_incompatible"
        );
        incompatible.protocol_major = 1;
        incompatible.retained_generations[0].protocol_major = 2;
        assert_eq!(
            validate_catalog_semantics(&incompatible, stable_root)
                .unwrap_err()
                .code,
            "generation_incompatible"
        );

        let mut escaped = record();
        escaped.retained_generations[0].stable_binary =
            PathBuf::from("/outside/retained/bin/herdr-a2a");
        escaped.retained_generations[0].pi_package_source = PathBuf::from("/outside/retained/pi");
        assert!(validate_catalog_semantics(&escaped, stable_root).is_err());

        let retained = record().retained_generations.pop().unwrap();
        let mut over_limit = record();
        over_limit.retained_generations = (0..=MAX_RETAINED_GENERATIONS)
            .map(|index| GenerationAuthorization {
                stable_binary: PathBuf::from(format!(
                    "/stable/generations/retained-{index}/bin/herdr-a2a"
                )),
                pi_package_source: PathBuf::from(format!(
                    "/stable/generations/retained-{index}/pi"
                )),
                ..retained.clone()
            })
            .collect();
        assert_eq!(
            validate_catalog_semantics(&over_limit, stable_root)
                .unwrap_err()
                .code,
            "retained_generation_limit"
        );
    }
}
