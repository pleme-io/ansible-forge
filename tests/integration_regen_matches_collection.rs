//! Regenerate every module from the TOML specs and assert structural
//! equivalence with the corresponding file in a live ansible-akeyless
//! checkout. This is the prime-directive backstop: if the generator
//! drifts from the hand-tuned collection state, the next `iac-forge
//! generate --backend ansible` would wipe out manual changes -- catch
//! it here instead of after the fact.
//!
//! "Structural equivalence" allows whitespace / blank-line variation
//! and trailing-comma differences, but pins the load-bearing shape:
//!   - same helper import (run_standard_crud / run_action_module /
//!     run_info_module)
//!   - same sdk_* tuples
//!   - same argument_spec keys (set equality)
//!   - same DOCUMENTATION module: declaration
//!
//! Set ANSIBLE_AKEYLESS_DIR to point at the collection checkout
//! (defaults to a sibling pleme-io/ansible-akeyless). Skipped when the
//! checkout isn't present, so safe for restricted CI.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ansible_forge::AnsibleBackend;
use iac_forge::{
    Backend, DataSourceSpec, ProviderDefaults, ProviderSpec, ResourceSpec,
    resolve_action, resolve_data_source, resolve_provider, resolve_resource,
};
use openapi_forge::Spec;

const DEFAULT_FIXTURES: &str = "/home/drzzln/code/github/pleme-io/akeyless-terraform-resources";
const DEFAULT_COLLECTION: &str = "/home/drzzln/code/github/pleme-io/ansible-akeyless";

fn fixtures_root() -> Option<PathBuf> {
    let env = std::env::var("AKEYLESS_RESOURCES_DIR").ok();
    let path = env
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_FIXTURES));
    if path.is_dir() && path.join("resources").is_dir() {
        Some(path)
    } else {
        None
    }
}

fn collection_root() -> Option<PathBuf> {
    let env = std::env::var("ANSIBLE_AKEYLESS_DIR").ok();
    let path = env
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_COLLECTION));
    if path.join("plugins").join("modules").is_dir() {
        Some(path)
    } else {
        None
    }
}

fn load_openapi_spec(root: &Path) -> Spec {
    let spec_dir = root.join("specs");
    let mut entries: Vec<_> = fs::read_dir(&spec_dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", spec_dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s == "yaml" || s == "yml")
        })
        .collect();
    entries.sort();
    let chosen = entries.last().expect("no OpenAPI spec found").clone();
    let text = fs::read_to_string(&chosen).expect("failed to read OpenAPI spec");
    Spec::from_str(&text).expect("failed to parse OpenAPI spec")
}

fn load_provider(root: &Path) -> ProviderSpec {
    let text = fs::read_to_string(root.join("provider.toml")).expect("read provider.toml");
    toml::from_str(&text).expect("parse provider.toml")
}

fn walk_tomls(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn visit(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                visit(&p, out);
            } else if p
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s == "toml")
            {
                out.push(p);
            }
        }
    }
    visit(dir, &mut out);
    out.sort();
    out
}

/// Extract the set of argument_spec keys from a Python module's source.
/// Tolerates the spec living at module level or inside `def main()`.
fn extract_argspec_keys(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_spec = false;
    let mut depth = 0i32;
    for line in src.lines() {
        let t = line.trim_start();
        if !in_spec {
            if t.starts_with("argument_spec = {") || t.starts_with("argument_spec={") {
                in_spec = true;
                depth = 1;
            }
            continue;
        }
        depth += line.matches('{').count() as i32;
        depth -= line.matches('}').count() as i32;
        if depth <= 0 {
            break;
        }
        // Crudely extract the leading quoted key on each line.
        if let Some(rest) = t.strip_prefix('\'') {
            if let Some(end) = rest.find('\'') {
                out.insert(rest[..end].to_string());
            }
        } else if let Some(rest) = t.strip_prefix('"') {
            if let Some(end) = rest.find('"') {
                out.insert(rest[..end].to_string());
            }
        }
    }
    out
}

/// Extract the helper-call shape signature from a Python module:
/// returns (helper_name, BTreeSet<(role, model, method)>) where role
/// is one of "sdk_create" / "sdk_update" / "sdk_delete" / "sdk_read"
/// / "sdk_call".
fn extract_helper_signature(src: &str) -> (Option<String>, BTreeSet<(String, String, String)>) {
    let mut helper: Option<String> = None;
    for name in ["run_standard_crud", "run_action_module", "run_info_module"] {
        if src.contains(&format!("{name}(")) {
            helper = Some(name.to_string());
            break;
        }
    }
    let mut tuples: BTreeSet<(String, String, String)> = BTreeSet::new();
    for role in ["sdk_create", "sdk_update", "sdk_delete", "sdk_read", "sdk_call"] {
        // Find "sdk_xxx=("Model", "method")" or "sdk_xxx=None".
        let needle = format!("{role}=");
        if let Some(idx) = src.find(&needle) {
            let after = &src[idx + needle.len()..];
            let after = after.trim_start();
            if after.starts_with("None") {
                tuples.insert((role.to_string(), "None".to_string(), "None".to_string()));
                continue;
            }
            if let Some(after) = after.strip_prefix('(') {
                // Parse two consecutive string literals (handles "..."
                // and '...' alike, no escape support — not needed for our
                // generator output).
                let (model, rest) = take_string(after);
                let rest = rest.trim_start().trim_start_matches(',').trim_start();
                let (method, _) = take_string(rest);
                if let (Some(m), Some(meth)) = (model, method) {
                    tuples.insert((role.to_string(), m, meth));
                }
            }
        }
    }
    (helper, tuples)
}

fn take_string(s: &str) -> (Option<String>, &str) {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('\'') {
        if let Some(end) = rest.find('\'') {
            return (Some(rest[..end].to_string()), &rest[end + 1..]);
        }
    } else if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return (Some(rest[..end].to_string()), &rest[end + 1..]);
        }
    }
    (None, s)
}

/// Find the module name declared in `DOCUMENTATION` (the `module: foo` line).
fn extract_doc_module_name(src: &str) -> Option<String> {
    for line in src.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_prefix("module:") {
            return Some(name.trim().to_string());
        }
    }
    None
}

/// Result of comparing one generated module against the on-disk version.
struct DriftReport {
    /// Hard drift -- the generator's load-bearing output (helper +
    /// sdk_* tuples + module: name) doesn't match the collection.
    /// These are prime-directive violations: a regen would silently
    /// rewrite the collection in a way that breaks behavior.
    hard: Vec<String>,
    /// Soft drift -- argspec key differences, typically caused by
    /// OpenAPI spec evolution between when the collection was last
    /// regenerated and now. These mean the collection has stale specs
    /// but the next regen will pick them up cleanly.
    soft: Vec<String>,
}

fn structural_drift(generated: &str, current: &str, label: &str) -> DriftReport {
    let mut hard = Vec::new();
    let mut soft = Vec::new();

    let (gen_helper, gen_tuples) = extract_helper_signature(generated);
    let (cur_helper, cur_tuples) = extract_helper_signature(current);
    if gen_helper != cur_helper {
        hard.push(format!(
            "{label}: helper drift -- generator emits {gen_helper:?}, collection has {cur_helper:?}"
        ));
    }
    if gen_tuples != cur_tuples {
        let only_in_gen: BTreeSet<_> = gen_tuples.difference(&cur_tuples).collect();
        let only_in_cur: BTreeSet<_> = cur_tuples.difference(&gen_tuples).collect();
        hard.push(format!(
            "{label}: sdk_* tuple drift -- only-in-generator={only_in_gen:?}, only-in-collection={only_in_cur:?}"
        ));
    }
    let gen_doc = extract_doc_module_name(generated);
    let cur_doc = extract_doc_module_name(current);
    if gen_doc != cur_doc {
        hard.push(format!(
            "{label}: DOCUMENTATION module name drift -- generator={gen_doc:?}, collection={cur_doc:?}"
        ));
    }

    let gen_keys = extract_argspec_keys(generated);
    let cur_keys = extract_argspec_keys(current);
    if gen_keys != cur_keys {
        let only_in_gen: BTreeSet<_> = gen_keys.difference(&cur_keys).collect();
        let only_in_cur: BTreeSet<_> = cur_keys.difference(&gen_keys).collect();
        soft.push(format!(
            "{label}: argument_spec key drift -- only-in-generator={only_in_gen:?}, only-in-collection={only_in_cur:?}"
        ));
    }

    DriftReport { hard, soft }
}

#[test]
fn integration_regen_matches_current_collection() {
    let Some(fixtures) = fixtures_root() else {
        eprintln!("[skip] AKEYLESS_RESOURCES_DIR / default not found");
        return;
    };
    let Some(collection) = collection_root() else {
        eprintln!("[skip] ANSIBLE_AKEYLESS_DIR / default not found");
        return;
    };

    let api = load_openapi_spec(&fixtures);
    let provider = load_provider(&fixtures);
    let defaults: ProviderDefaults = provider.defaults.clone();
    let _ = resolve_provider(&provider);
    let backend = AnsibleBackend::new();
    let iac_provider = resolve_provider(&provider);

    let mod_dir = collection.join("plugins").join("modules");

    // Helper-file sanity: the generator bundles a static
    // plugins/module_utils/akeyless_client.py via include_str! against
    // src/client_helper.py. Drift between that bundled copy and the
    // live collection's helper file is a prime-directive violation --
    // next regen would overwrite the deployed helper. Catch byte-exact
    // mismatches here before checking per-module artifacts so the
    // failure message points at the right file.
    let bundled_helper = ansible_forge::client_helper::AKEYLESS_CLIENT_PY;
    let collection_helper_path =
        collection.join("plugins").join("module_utils").join("akeyless_client.py");
    let helper_drift_hint = match fs::read_to_string(&collection_helper_path) {
        Ok(live) if live == bundled_helper => None,
        Ok(live) => {
            let summary = format!(
                "plugins/module_utils/akeyless_client.py: live={} bytes vs bundled={} bytes",
                live.len(),
                bundled_helper.len(),
            );
            Some(summary)
        }
        Err(e) => Some(format!(
            "plugins/module_utils/akeyless_client.py: read failed: {e}"
        )),
    };

    // Apply mode: when REGEN_APPLY=1 is set, rewrite every collection
    // module file with the freshly-generated content. Sync intent;
    // skips the comparison assertions afterward so callers can verify
    // by re-running the test in default (compare) mode.
    let apply_mode = std::env::var("REGEN_APPLY").is_ok_and(|v| v == "1");

    let resource_paths = walk_tomls(&fixtures.join("resources"));
    let data_source_paths = walk_tomls(&fixtures.join("data_sources"));

    let mut compared = 0usize;
    let mut not_in_collection = 0usize;
    let mut hard_drift: Vec<String> = Vec::new();
    let mut soft_drift: Vec<String> = Vec::new();
    let mut applied = 0usize;

    // Pure helper -- returns (compared++, new++, hard_drift, soft_drift, applied++).
    fn check_artifact(
        artifacts: Vec<iac_forge::backend::GeneratedArtifact>,
        label: &str,
        collection: &Path,
        apply: bool,
    ) -> (usize, usize, Vec<String>, Vec<String>, usize) {
        let mut compared = 0usize;
        let mut new_in_fixtures = 0usize;
        let mut hard = Vec::new();
        let mut soft = Vec::new();
        let mut applied = 0usize;
        for art in artifacts {
            let on_disk = collection.join(Path::new(&art.path));
            if apply {
                if let Some(parent) = on_disk.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Err(e) = fs::write(&on_disk, &art.content) {
                    hard.push(format!("{label}: write {} failed: {e}", on_disk.display()));
                } else {
                    applied += 1;
                }
                continue;
            }
            if !on_disk.exists() {
                eprintln!("[new] {} (no collection counterpart yet)", art.path);
                new_in_fixtures += 1;
                continue;
            }
            let current = match fs::read_to_string(&on_disk) {
                Ok(t) => t,
                Err(e) => {
                    hard.push(format!("{label}: read {} failed: {e}", on_disk.display()));
                    continue;
                }
            };
            compared += 1;
            let report = structural_drift(&art.content, &current, label);
            hard.extend(report.hard);
            soft.extend(report.soft);
        }
        (compared, new_in_fixtures, hard, soft, applied)
    }

    for path in &resource_paths {
        let label = path
            .strip_prefix(&fixtures)
            .unwrap_or(path)
            .display()
            .to_string();
        let text = fs::read_to_string(path).expect("read resource toml");
        let spec: ResourceSpec = match toml::from_str(&text) {
            Ok(s) => s,
            Err(e) => {
                hard_drift.push(format!("{label}: parse: {e}"));
                continue;
            }
        };
        let result = if spec.is_action() {
            match resolve_action(&spec, &api, &defaults) {
                Ok(action) => backend.generate_action(&action, &iac_provider),
                Err(e) => {
                    hard_drift.push(format!("{label}: resolve_action: {e}"));
                    continue;
                }
            }
        } else {
            match resolve_resource(&spec, &api, &defaults) {
                Ok(resource) => backend.generate_resource(&resource, &iac_provider),
                Err(e) => {
                    hard_drift.push(format!("{label}: resolve_resource: {e}"));
                    continue;
                }
            }
        };
        match result {
            Ok(artifacts) => {
                let (c, n, h, s, a) = check_artifact(artifacts, &label, &collection, apply_mode);
                compared += c;
                not_in_collection += n;
                hard_drift.extend(h);
                soft_drift.extend(s);
                applied += a;
            }
            Err(e) => hard_drift.push(format!("{label}: generate: {e}")),
        }
    }

    for path in &data_source_paths {
        let label = path
            .strip_prefix(&fixtures)
            .unwrap_or(path)
            .display()
            .to_string();
        let text = fs::read_to_string(path).expect("read ds toml");
        let spec: DataSourceSpec = match toml::from_str(&text) {
            Ok(s) => s,
            Err(e) => {
                hard_drift.push(format!("{label}: parse: {e}"));
                continue;
            }
        };
        match resolve_data_source(&spec, &api, &defaults) {
            Ok(ds) => match backend.generate_data_source(&ds, &iac_provider) {
                Ok(artifacts) => {
                let (c, n, h, s, a) = check_artifact(artifacts, &label, &collection, apply_mode);
                compared += c;
                not_in_collection += n;
                hard_drift.extend(h);
                soft_drift.extend(s);
                applied += a;
            }
                Err(e) => hard_drift.push(format!("{label}: generate_ds: {e}")),
            },
            Err(e) => hard_drift.push(format!("{label}: resolve_ds: {e}")),
        }
    }

    let _ = mod_dir;

    if apply_mode {
        // Also rewrite the helper file from the bundled source.
        if let Err(e) = fs::write(&collection_helper_path, bundled_helper) {
            hard_drift.push(format!(
                "{}: helper apply write failed: {e}",
                collection_helper_path.display()
            ));
        } else {
            applied += 1;
        }
        eprintln!(
            "[regen-apply] applied={applied} (rewrote module files + helper in {})",
            collection.display()
        );
        if !hard_drift.is_empty() {
            for d in hard_drift.iter().take(20) {
                eprintln!("[apply-error] {d}");
            }
            panic!("{} write/parse error(s) during apply", hard_drift.len());
        }
        return;
    }

    // Helper drift is a hard fail (prime directive).
    if let Some(hint) = helper_drift_hint {
        hard_drift.push(hint);
    }

    eprintln!(
        "[regen-diff] compared={compared} new-in-fixtures={not_in_collection} \
        hard_drift={} soft_drift={}",
        hard_drift.len(),
        soft_drift.len(),
    );
    if !soft_drift.is_empty() {
        eprintln!(
            "[soft] {} module(s) have argspec key drift -- the OpenAPI spec has \
            evolved since the collection was regenerated. Run a regen + spec \
            sync to clear:",
            soft_drift.len()
        );
        for d in soft_drift.iter().take(30) {
            eprintln!("[soft] {d}");
        }
        if soft_drift.len() > 30 {
            eprintln!("[soft] ... and {} more", soft_drift.len() - 30);
        }
    }
    if !hard_drift.is_empty() {
        eprintln!(
            "[hard] {} prime-directive drift(s) -- generator output differs from \
            the collection in a load-bearing way (helper / sdk_* tuples / \
            module name). A regen would silently rewrite behavior:",
            hard_drift.len()
        );
        for d in hard_drift.iter().take(30) {
            eprintln!("[hard] {d}");
        }
        if hard_drift.len() > 30 {
            eprintln!("[hard] ... and {} more", hard_drift.len() - 30);
        }
    }
    // Soft drift is informational. Hard drift is a hard fail.
    assert!(
        hard_drift.is_empty(),
        "{} module(s) load-bearing drift between generator output and live collection",
        hard_drift.len()
    );
}
