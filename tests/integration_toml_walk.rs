//! End-to-end TOML walk: parse every spec under
//! `akeyless-terraform-resources/{resources,data_sources}/`, resolve it
//! against the bundled OpenAPI spec, generate the Python module, and
//! sanity-check the output.
//!
//! The fixture path is set via `AKEYLESS_RESOURCES_DIR` (defaults to the
//! sibling `pleme-io/akeyless-terraform-resources` checkout). The test is
//! skipped cleanly when the directory isn't present, so this is safe for
//! restricted CI environments.

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
/// Hard floor for pass count -- if we drop below this, something regressed.
const MIN_GENERATED_OK: usize = 150;

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

fn load_openapi_spec(root: &Path) -> Spec {
    // Pick the lexically-largest .yaml file under specs/ -- our checkouts
    // accumulate timestamped snapshots over time.
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
    let chosen = entries
        .last()
        .unwrap_or_else(|| panic!("no .yaml specs in {}", spec_dir.display()))
        .clone();
    let text = fs::read_to_string(&chosen)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", chosen.display()));
    Spec::from_str(&text)
        .unwrap_or_else(|e| panic!("failed to parse OpenAPI spec {}: {e}", chosen.display()))
}

fn load_provider(root: &Path) -> ProviderSpec {
    let provider_path = root.join("provider.toml");
    let text = fs::read_to_string(&provider_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", provider_path.display()));
    toml::from_str(&text)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", provider_path.display()))
}

fn walk_tomls(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn visit(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
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

fn sanity_check_python(content: &str, label: &str) {
    assert!(
        content.contains("def main():"),
        "{label}: emitted module missing def main():"
    );
    assert!(
        content.contains("from ansible_collections.akeyless"),
        "{label}: emitted module missing ansible_collections.akeyless import"
    );
    assert!(
        !content.contains("TODO: implement API call"),
        "{label}: emitted module contains placeholder TODO"
    );
}

#[test]
fn integration_toml_walk_resolves_and_generates_all_specs() {
    let Some(root) = fixtures_root() else {
        eprintln!(
            "[skip] AKEYLESS_RESOURCES_DIR not set / {} not found",
            DEFAULT_FIXTURES
        );
        return;
    };

    let api = load_openapi_spec(&root);
    let provider = load_provider(&root);
    let defaults: ProviderDefaults = provider.defaults.clone();
    let _iac_provider = resolve_provider(&provider);
    let backend = AnsibleBackend::new();
    // Re-build IacProvider for backend calls.
    let iac_provider = resolve_provider(&provider);

    let resource_paths = walk_tomls(&root.join("resources"));
    let data_source_paths = walk_tomls(&root.join("data_sources"));

    assert!(
        !resource_paths.is_empty(),
        "no resource TOMLs found under {}/resources",
        root.display()
    );
    assert!(
        !data_source_paths.is_empty(),
        "no data source TOMLs found under {}/data_sources",
        root.display()
    );

    let mut ok = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for path in &resource_paths {
        let label = path.strip_prefix(&root).unwrap_or(path).display().to_string();
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                failures.push(format!("{label}: read error: {e}"));
                continue;
            }
        };
        let spec: ResourceSpec = match toml::from_str(&text) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("{label}: parse error: {e}"));
                continue;
            }
        };
        let result = if spec.is_action() {
            match resolve_action(&spec, &api, &defaults) {
                Ok(action) => backend.generate_action(&action, &iac_provider),
                Err(e) => {
                    failures.push(format!("{label}: resolve_action: {e}"));
                    continue;
                }
            }
        } else {
            match resolve_resource(&spec, &api, &defaults) {
                Ok(resource) => backend.generate_resource(&resource, &iac_provider),
                Err(e) => {
                    failures.push(format!("{label}: resolve_resource: {e}"));
                    continue;
                }
            }
        };
        match result {
            Ok(artifacts) => {
                for artifact in &artifacts {
                    sanity_check_python(&artifact.content, &label);
                }
                ok += 1;
            }
            Err(e) => failures.push(format!("{label}: generate: {e}")),
        }
    }

    for path in &data_source_paths {
        let label = path.strip_prefix(&root).unwrap_or(path).display().to_string();
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                failures.push(format!("{label}: read error: {e}"));
                continue;
            }
        };
        let spec: DataSourceSpec = match toml::from_str(&text) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("{label}: parse error: {e}"));
                continue;
            }
        };
        match resolve_data_source(&spec, &api, &defaults) {
            Ok(ds) => match backend.generate_data_source(&ds, &iac_provider) {
                Ok(artifacts) => {
                    for artifact in &artifacts {
                        sanity_check_python(&artifact.content, &label);
                    }
                    ok += 1;
                }
                Err(e) => failures.push(format!("{label}: generate_data_source: {e}")),
            },
            Err(e) => failures.push(format!("{label}: resolve_data_source: {e}")),
        }
    }

    let total = resource_paths.len() + data_source_paths.len();
    eprintln!(
        "[toml-walk] {ok}/{total} specs generated successfully (failures: {})",
        failures.len()
    );
    if !failures.is_empty() {
        for f in failures.iter().take(20) {
            eprintln!("[fail] {f}");
        }
        if failures.len() > 20 {
            eprintln!("[fail] ... and {} more", failures.len() - 20);
        }
    }

    assert!(
        ok >= MIN_GENERATED_OK,
        "expected at least {MIN_GENERATED_OK} successful generations, got {ok}/{total}"
    );
}
