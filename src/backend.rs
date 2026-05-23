//! Ansible backend implementing the `iac-forge` `Backend` trait.
//!
//! Generates Python module files and integration test playbooks.

use iac_forge::{
    ArtifactKind, Backend, GeneratedArtifact, IacAction, IacDataSource, IacForgeError, IacProvider,
    IacResource, NamingConvention, strip_provider_prefix, to_snake_case,
};

use crate::module_gen;

/// Resolve the Galaxy namespace from provider config, falling back to the
/// provider name when no override is set.
///
/// Reads `[platforms.ansible] galaxy_namespace = "..."` from the provider's
/// `platform_config`. This lets `provider.toml` ship Ansible-specific
/// publication metadata without polluting the IR.
fn galaxy_namespace(provider: &IacProvider) -> &str {
    provider
        .platform_config
        .get("ansible")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("galaxy_namespace"))
        .and_then(|v| v.as_str())
        .unwrap_or(&provider.name)
}

/// Build the `galaxy.yml` collection manifest for a `<namespace>/<name>`
/// publishing target.
fn galaxy_yml(namespace: &str, name: &str) -> String {
    // Galaxy rejects collections whose manifest is missing repository/
    // documentation/homepage/issues — the import task fails with
    // "Invalid collection metadata. 'repository' is required". Pointing
    // these at the GitHub repo for ansible-<name> is a safe default;
    // generated collections override on a per-fork basis by editing
    // galaxy.yml post-generation (or this default in the generator).
    format!(
        "namespace: {namespace}\n\
         name: {name}\n\
         version: 0.1.0\n\
         readme: README.md\n\
         authors: [pleme-io]\n\
         description: \"Auto-generated Ansible modules for Akeyless Vault — managed by iac-forge.\"\n\
         license: [MIT]\n\
         repository: https://github.com/pleme-io/ansible-{name}\n\
         documentation: https://github.com/pleme-io/ansible-{name}\n\
         homepage: https://github.com/pleme-io/ansible-{name}\n\
         issues: https://github.com/pleme-io/ansible-{name}/issues\n\
         dependencies: {{}}\n\
         tags: [security, secrets, akeyless]\n"
    )
}

/// Static `meta/runtime.yml` requiring a recent Ansible.
const RUNTIME_YML: &str = "requires_ansible: '>=2.14.0'\n";

/// Static `requirements.txt` listing the Akeyless Python SDK.
const REQUIREMENTS_TXT: &str = "akeyless>=5.0.22\n";

/// Build the `README.md` stub for a `<namespace>/<name>` collection.
fn readme_md(namespace: &str, name: &str) -> String {
    format!(
        "# {namespace}.{name}\n\n\
         Auto-generated Ansible collection wrapping the Akeyless Python SDK.\n\
         Each module proxies one Akeyless V2 API endpoint with create/read/update/delete\n\
         semantics derived from the upstream OpenAPI specification.\n\
         Do not edit generated modules — they will be overwritten.\n\n\
         Regenerate with: `iac-forge-cli generate --backend ansible`.\n"
    )
}

/// Ansible backend for `iac-forge`.
///
/// Generates Python Ansible module files from `IaC` IR types.
#[derive(Debug, Default)]
pub struct AnsibleBackend {
    naming: AnsibleNaming,
}

impl AnsibleBackend {
    /// Create a new `AnsibleBackend`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl std::fmt::Display for AnsibleBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnsibleBackend({})", self.platform())
    }
}

/// Naming convention for Ansible modules.
///
/// Uses `snake_case` for type names, field names, and file names.
/// Strips the provider prefix from resource names.
#[derive(Debug, Default)]
pub(crate) struct AnsibleNaming;

impl NamingConvention for AnsibleNaming {
    fn resource_type_name(&self, resource_name: &str, provider_name: &str) -> String {
        to_snake_case(strip_provider_prefix(resource_name, provider_name))
    }

    fn file_name(&self, resource_name: &str, kind: &ArtifactKind) -> String {
        let base = to_snake_case(resource_name);
        match kind {
            ArtifactKind::DataSource => format!("{base}_info.py"),
            ArtifactKind::Test => format!("test_{base}.yml"),
            _ => format!("{base}.py"),
        }
    }

    fn field_name(&self, api_name: &str) -> String {
        to_snake_case(api_name)
    }
}

impl Backend for AnsibleBackend {
    #[allow(clippy::unnecessary_literal_bound)]
    fn platform(&self) -> &str {
        "ansible"
    }

    fn generate_resource(
        &self,
        resource: &IacResource,
        provider: &IacProvider,
    ) -> Result<Vec<GeneratedArtifact>, IacForgeError> {
        let module_name = strip_provider_prefix(&resource.name, &provider.name);
        let namespace = galaxy_namespace(provider);
        let content = module_gen::generate_resource_module(resource, &provider.name, namespace);
        let path = format!("plugins/modules/{}.py", to_snake_case(module_name));

        Ok(vec![GeneratedArtifact::new(
            path,
            content,
            ArtifactKind::Resource,
        )])
    }

    fn generate_data_source(
        &self,
        ds: &IacDataSource,
        provider: &IacProvider,
    ) -> Result<Vec<GeneratedArtifact>, IacForgeError> {
        let module_name = strip_provider_prefix(&ds.name, &provider.name);
        let namespace = galaxy_namespace(provider);
        let content = module_gen::generate_data_source_module(ds, &provider.name, namespace);
        let path = format!("plugins/modules/{}_info.py", to_snake_case(module_name));

        Ok(vec![GeneratedArtifact::new(
            path,
            content,
            ArtifactKind::DataSource,
        )])
    }

    fn generate_provider(
        &self,
        provider: &IacProvider,
        _resources: &[IacResource],
        _data_sources: &[IacDataSource],
    ) -> Result<Vec<GeneratedArtifact>, IacForgeError> {
        // Collection-level files: bundled Python helper, galaxy metadata,
        // runtime manifest, requirements, and a stub README. These are
        // provider-scoped (one per generation), so this is the idiomatic hook.
        let namespace = galaxy_namespace(provider);
        let collection_name = provider.name.as_str();
        Ok(vec![
            GeneratedArtifact::new(
                "plugins/module_utils/akeyless_client.py",
                crate::client_helper::AKEYLESS_CLIENT_PY,
                ArtifactKind::Metadata,
            ),
            GeneratedArtifact::new(
                "galaxy.yml",
                galaxy_yml(namespace, collection_name),
                ArtifactKind::Metadata,
            ),
            GeneratedArtifact::new("meta/runtime.yml", RUNTIME_YML, ArtifactKind::Metadata),
            GeneratedArtifact::new("requirements.txt", REQUIREMENTS_TXT, ArtifactKind::Metadata),
            GeneratedArtifact::new(
                "README.md",
                readme_md(namespace, collection_name),
                ArtifactKind::Metadata,
            ),
        ])
    }

    fn generate_test(
        &self,
        resource: &IacResource,
        provider: &IacProvider,
    ) -> Result<Vec<GeneratedArtifact>, IacForgeError> {
        let module_name = strip_provider_prefix(&resource.name, &provider.name);
        let content = module_gen::generate_test_playbook(resource, &provider.name);
        let path = format!(
            "tests/integration/targets/{}/tasks/main.yml",
            to_snake_case(module_name)
        );

        Ok(vec![GeneratedArtifact::new(
            path,
            content,
            ArtifactKind::Test,
        )])
    }

    fn generate_action(
        &self,
        action: &IacAction,
        provider: &IacProvider,
    ) -> Result<Vec<GeneratedArtifact>, IacForgeError> {
        let module_name = strip_provider_prefix(&action.name, &provider.name);
        let namespace = galaxy_namespace(provider);
        let content = module_gen::generate_action_module(action, &provider.name, namespace);
        let path = format!("plugins/modules/{}.py", to_snake_case(module_name));

        Ok(vec![GeneratedArtifact::new(
            path,
            content,
            ArtifactKind::Module,
        )])
    }

    fn naming(&self) -> &dyn NamingConvention {
        &self.naming
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iac_forge::{AuthInfo, CrudInfo, IacType, IdentityInfo, TestAttributeBuilder};
    use std::collections::BTreeMap;

    fn sample_provider() -> IacProvider {
        IacProvider {
            name: "mycloud".to_string(),
            description: "MyCloud provider".to_string(),
            version: "0.1.0".to_string(),
            auth: AuthInfo::default(),
            skip_fields: vec![],
            platform_config: BTreeMap::new(),
        }
    }

    fn sample_resource() -> IacResource {
        IacResource {
            name: "mycloud_instance".to_string(),
            description: "Manage a compute instance".to_string(),
            category: "compute".to_string(),
            crud: CrudInfo {
                create_endpoint: "/instances".to_string(),
                create_schema: "CreateInstance".to_string(),
                update_endpoint: Some("/instances".to_string()),
                update_schema: Some("UpdateInstance".to_string()),
                read_endpoint: "/instances".to_string(),
                read_schema: "ReadInstance".to_string(),
                read_response_schema: None,
                delete_endpoint: "/instances".to_string(),
                delete_schema: "DeleteInstance".to_string(),
            },
            attributes: vec![
                TestAttributeBuilder::new("instance-name", IacType::String)
                    .required()
                    .description("Name of the instance")
                    .build(),
                TestAttributeBuilder::new("instance-id", IacType::String)
                    .computed()
                    .description("ID of the instance")
                    .build(),
            ],
            identity: IdentityInfo {
                id_field: "instance_id".to_string(),
                import_field: "instance_name".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn platform_name() {
        let backend = AnsibleBackend::new();
        assert_eq!(backend.platform(), "ansible");
    }

    #[test]
    fn generate_resource_produces_python() {
        // The generated module no longer constructs AnsibleModule(...)
        // inline — that responsibility moved into run_standard_crud in
        // akeyless_client.py. Pin instead that the generated module
        // dispatches via the shared helper (the strongest signal that
        // the module is valid Python wired to the helper contract).
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let resource = sample_resource();
        let artifacts = backend.generate_resource(&resource, &provider).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].path, "plugins/modules/instance.py");
        assert_eq!(artifacts[0].kind, ArtifactKind::Resource);
        assert!(
            artifacts[0].content.contains("run_standard_crud("),
            "generated resource module must dispatch via run_standard_crud"
        );
    }

    #[test]
    fn generate_data_source_produces_info_module() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let ds = IacDataSource {
            name: "mycloud_instance".to_string(),
            description: "Get instance info".to_string(),
            read_endpoint: "/instances".to_string(),
            read_schema: "ReadInstance".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let artifacts = backend.generate_data_source(&ds, &provider).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].path, "plugins/modules/instance_info.py");
        assert_eq!(artifacts[0].kind, ArtifactKind::DataSource);
    }

    #[test]
    fn generate_provider_emits_collection_metadata() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let artifacts = backend.generate_provider(&provider, &[], &[]).unwrap();
        // Collection-level files: client helper, galaxy.yml, runtime, requirements, README.
        assert_eq!(artifacts.len(), 5);
        let paths: Vec<&str> = artifacts.iter().map(|a| a.path.as_str()).collect();
        assert!(paths.contains(&"plugins/module_utils/akeyless_client.py"));
        assert!(paths.contains(&"galaxy.yml"));
        assert!(paths.contains(&"meta/runtime.yml"));
        assert!(paths.contains(&"requirements.txt"));
        assert!(paths.contains(&"README.md"));
    }

    #[test]
    fn generate_test_produces_yaml() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let resource = sample_resource();
        let artifacts = backend.generate_test(&resource, &provider).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].path,
            "tests/integration/targets/instance/tasks/main.yml"
        );
        assert_eq!(artifacts[0].kind, ArtifactKind::Test);
        assert!(artifacts[0].content.contains("state: present"));
    }

    #[test]
    fn naming_convention_resource_type() {
        let naming = AnsibleNaming;
        assert_eq!(
            naming.resource_type_name("mycloud_instance", "mycloud"),
            "instance"
        );
    }

    #[test]
    fn naming_convention_file_name() {
        let naming = AnsibleNaming;
        assert_eq!(
            naming.file_name("instance", &ArtifactKind::Resource),
            "instance.py"
        );
        assert_eq!(
            naming.file_name("instance", &ArtifactKind::DataSource),
            "instance_info.py"
        );
        assert_eq!(
            naming.file_name("instance", &ArtifactKind::Test),
            "test_instance.yml"
        );
    }

    #[test]
    fn naming_convention_field_name() {
        let naming = AnsibleNaming;
        assert_eq!(naming.field_name("bound-aws-account-id"), "bound_aws_account_id");
    }

    #[test]
    fn file_name_module_kind_matches_resource() {
        let naming = AnsibleNaming;
        assert_eq!(
            naming.file_name("instance", &ArtifactKind::Module),
            "instance.py"
        );
        assert_eq!(
            naming.file_name("instance", &ArtifactKind::Module),
            naming.file_name("instance", &ArtifactKind::Resource),
        );
    }

    #[test]
    fn file_name_wildcard_arms_produce_py() {
        let naming = AnsibleNaming;
        assert_eq!(
            naming.file_name("instance", &ArtifactKind::Schema),
            "instance.py"
        );
        assert_eq!(
            naming.file_name("instance", &ArtifactKind::Provider),
            "instance.py"
        );
        assert_eq!(
            naming.file_name("instance", &ArtifactKind::Metadata),
            "instance.py"
        );
    }

    #[test]
    fn file_name_normalizes_hyphens_to_underscores() {
        let naming = AnsibleNaming;
        assert_eq!(
            naming.file_name("my-resource", &ArtifactKind::Resource),
            "my_resource.py"
        );
        assert_eq!(
            naming.file_name("my-resource", &ArtifactKind::DataSource),
            "my_resource_info.py"
        );
        assert_eq!(
            naming.file_name("my-resource", &ArtifactKind::Test),
            "test_my_resource.yml"
        );
    }

    #[test]
    fn naming_returns_usable_convention() {
        let backend = AnsibleBackend::new();
        let naming = backend.naming();
        assert_eq!(
            naming.resource_type_name("mycloud_instance", "mycloud"),
            "instance"
        );
        assert_eq!(naming.field_name("some-field"), "some_field");
        assert_eq!(
            naming.file_name("instance", &ArtifactKind::Resource),
            "instance.py"
        );
    }

    #[test]
    fn data_source_type_name_default_delegates() {
        let naming = AnsibleNaming;
        assert_eq!(
            naming.data_source_type_name("mycloud_secret", "mycloud"),
            naming.resource_type_name("mycloud_secret", "mycloud"),
        );
    }

    #[test]
    fn validate_resource_default_is_empty() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let resource = sample_resource();
        let errors = backend.validate_resource(&resource, &provider);
        assert!(errors.is_empty());
    }

    #[test]
    fn generate_resource_strips_provider_prefix_from_path() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let resource = sample_resource();
        let artifacts = backend.generate_resource(&resource, &provider).unwrap();
        assert_eq!(artifacts[0].path, "plugins/modules/instance.py");
        assert!(artifacts[0].content.contains("module: instance"));
    }

    #[test]
    fn generate_test_path_uses_snake_case() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let mut resource = sample_resource();
        resource.name = "mycloud_complex-name".to_string();
        let artifacts = backend.generate_test(&resource, &provider).unwrap();
        assert_eq!(
            artifacts[0].path,
            "tests/integration/targets/complex_name/tasks/main.yml"
        );
    }

    #[test]
    fn generate_data_source_strips_prefix_and_appends_info() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let ds = IacDataSource {
            name: "mycloud_volume".to_string(),
            description: "Get volume info".to_string(),
            read_endpoint: "/volumes".to_string(),
            read_schema: "ReadVolume".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let artifacts = backend.generate_data_source(&ds, &provider).unwrap();
        assert_eq!(artifacts[0].path, "plugins/modules/volume_info.py");
        assert_eq!(artifacts[0].kind, ArtifactKind::DataSource);
        assert!(artifacts[0].content.contains("module: volume_info"));
    }

    #[test]
    fn generate_resource_no_matching_prefix_keeps_full_name() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let mut resource = sample_resource();
        resource.name = "other_instance".to_string();
        let artifacts = backend.generate_resource(&resource, &provider).unwrap();
        assert_eq!(artifacts[0].path, "plugins/modules/other_instance.py");
    }

    #[test]
    fn backend_default_matches_new() {
        let from_default = AnsibleBackend::default();
        let from_new = AnsibleBackend::new();
        assert_eq!(from_default.platform(), from_new.platform());
    }

    #[test]
    fn backend_display() {
        let backend = AnsibleBackend::new();
        assert_eq!(backend.to_string(), "AnsibleBackend(ansible)");
    }

    #[test]
    fn naming_convention_hyphenated_resource_type() {
        let naming = AnsibleNaming;
        assert_eq!(
            naming.resource_type_name("mycloud_my-resource", "mycloud"),
            "my_resource"
        );
    }

    #[test]
    fn naming_convention_empty_field_name() {
        let naming = AnsibleNaming;
        assert_eq!(naming.field_name(""), "");
    }

    #[test]
    fn naming_convention_field_name_already_snake_case() {
        let naming = AnsibleNaming;
        assert_eq!(naming.field_name("already_snake"), "already_snake");
    }

    #[test]
    fn generate_resource_content_has_module_name() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let resource = sample_resource();
        let artifacts = backend.generate_resource(&resource, &provider).unwrap();
        let content = &artifacts[0].content;
        assert!(content.contains("module: instance"));
        assert!(content.contains("DOCUMENTATION"));
        assert!(content.contains("EXAMPLES"));
        assert!(content.contains("RETURN"));
        assert!(content.contains("def main():"));
    }

    #[test]
    fn generate_data_source_content_has_info_module() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let ds = IacDataSource {
            name: "mycloud_secret".to_string(),
            description: "Get secret info".to_string(),
            read_endpoint: "/secrets".to_string(),
            read_schema: "ReadSecret".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let artifacts = backend.generate_data_source(&ds, &provider).unwrap();
        let content = &artifacts[0].content;
        assert!(content.contains("module: secret_info"));
        assert!(!content.contains("state"));
    }

    #[test]
    fn generate_test_content_has_playbook_structure() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let resource = sample_resource();
        let artifacts = backend.generate_test(&resource, &provider).unwrap();
        let content = &artifacts[0].content;
        assert!(content.starts_with("---"));
        assert!(content.contains("hosts: localhost"));
        assert!(content.contains("tasks:"));
    }

    #[test]
    fn file_name_data_source_normalizes() {
        let naming = AnsibleNaming;
        assert_eq!(
            naming.file_name("my-data", &ArtifactKind::DataSource),
            "my_data_info.py"
        );
    }

    #[test]
    fn generate_resource_with_hyphenated_name() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let mut resource = sample_resource();
        resource.name = "mycloud_my-resource".to_string();
        let artifacts = backend.generate_resource(&resource, &provider).unwrap();
        assert_eq!(artifacts[0].path, "plugins/modules/my_resource.py");
    }

    fn sample_action() -> iac_forge::IacAction {
        iac_forge::IacAction {
            name: "mycloud_uid_generate_token".to_string(),
            description: "Generate a UID token".to_string(),
            category: "uid".to_string(),
            endpoint: "/uid-generate-token".to_string(),
            schema: "uidGenerateToken".to_string(),
            response_schema: Some("uidGenerateTokenOutput".to_string()),
            mutating: true,
            sensitive_response_fields: vec!["token".to_string()],
            attributes: vec![
                TestAttributeBuilder::new("auth-method-name", IacType::String)
                    .required()
                    .description("Auth method name")
                    .build(),
            ],
            sdk_method: None,
        }
    }

    #[test]
    fn generate_action_writes_to_plugins_modules_path() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let action = sample_action();
        let artifacts = backend.generate_action(&action, &provider).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].path, "plugins/modules/uid_generate_token.py");
        assert_eq!(artifacts[0].kind, ArtifactKind::Module);
    }

    #[test]
    fn generate_action_content_has_run_action_helper() {
        // Old shape: the generated module declared a `def run_action`
        // wrapper, then called call_api(...) directly and built its own
        // AnsibleModule(supports_check_mode=False, ...).
        // New shape: the generated module just delegates to
        // run_action_module from akeyless_client.py, which owns the
        // check-mode policy and the call_api invocation. Pin the
        // delegation and the SDK call tuple wiring.
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let action = sample_action();
        let artifacts = backend.generate_action(&action, &provider).unwrap();
        let content = &artifacts[0].content;
        assert!(
            content.contains("run_action_module("),
            "action module must dispatch via the shared run_action_module helper"
        );
        // sample_action.schema = "uidGenerateToken" with no sdk_method
        // override → derived model class UidGenerateToken / method
        // uid_generate_token.
        assert!(
            content.contains("sdk_call=(\"UidGenerateToken\", \"uid_generate_token\")"),
            "action module must wire its SDK call via sdk_call=(Model, method) tuple, got:\n{content}"
        );
        // The old per-module check-mode opt-out is gone — the helper
        // owns supports_check_mode=False internally.
        assert!(
            !content.contains("supports_check_mode=True"),
            "actions must not enable check_mode"
        );
    }

    // ── Galaxy namespace resolution ────────────────────────────────────

    fn provider_with_namespace(ns: &str) -> IacProvider {
        let mut p = sample_provider();
        let mut ansible_table = toml::value::Table::new();
        ansible_table.insert(
            "galaxy_namespace".to_string(),
            toml::Value::String(ns.to_string()),
        );
        p.platform_config
            .insert("ansible".to_string(), toml::Value::Table(ansible_table));
        p
    }

    #[test]
    fn galaxy_namespace_falls_back_to_provider_name() {
        let provider = sample_provider();
        assert_eq!(galaxy_namespace(&provider), "mycloud");
    }

    #[test]
    fn galaxy_namespace_honors_platform_config_override() {
        let provider = provider_with_namespace("drzln0");
        assert_eq!(galaxy_namespace(&provider), "drzln0");
    }

    #[test]
    fn galaxy_namespace_ignores_non_table_value() {
        let mut provider = sample_provider();
        provider.platform_config.insert(
            "ansible".to_string(),
            toml::Value::String("not-a-table".to_string()),
        );
        // Non-table values cannot carry a namespace key — fall back to provider name.
        assert_eq!(galaxy_namespace(&provider), "mycloud");
    }

    #[test]
    fn galaxy_yml_uses_resolved_namespace() {
        let backend = AnsibleBackend::new();
        let provider = provider_with_namespace("drzln0");
        let artifacts = backend.generate_provider(&provider, &[], &[]).unwrap();
        let galaxy = artifacts
            .iter()
            .find(|a| a.path == "galaxy.yml")
            .expect("galaxy.yml must be generated");
        assert!(
            galaxy.content.starts_with("namespace: drzln0\n"),
            "galaxy.yml must declare the overridden namespace: {}",
            galaxy.content
        );
        assert!(galaxy.content.contains("name: mycloud\n"));
    }

    #[test]
    fn galaxy_yml_defaults_to_provider_name_when_unset() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let artifacts = backend.generate_provider(&provider, &[], &[]).unwrap();
        let galaxy = artifacts
            .iter()
            .find(|a| a.path == "galaxy.yml")
            .expect("galaxy.yml must be generated");
        assert!(galaxy.content.starts_with("namespace: mycloud\n"));
    }

    #[test]
    fn readme_uses_resolved_namespace() {
        let backend = AnsibleBackend::new();
        let provider = provider_with_namespace("drzln0");
        let artifacts = backend.generate_provider(&provider, &[], &[]).unwrap();
        let readme = artifacts
            .iter()
            .find(|a| a.path == "README.md")
            .expect("README.md must be generated");
        assert!(
            readme.content.starts_with("# drzln0.mycloud\n"),
            "README.md must reference the namespaced collection: {}",
            readme.content
        );
    }

    #[test]
    fn generate_resource_uses_resolved_namespace_in_import_path() {
        let backend = AnsibleBackend::new();
        let provider = provider_with_namespace("drzln0");
        let resource = sample_resource();
        let artifacts = backend.generate_resource(&resource, &provider).unwrap();
        assert!(artifacts[0].content.contains(
            "from ansible_collections.drzln0.mycloud.plugins.module_utils.akeyless_client import"
        ));
        assert!(
            !artifacts[0]
                .content
                .contains("ansible_collections.akeyless.akeyless"),
            "old hardcoded namespace must not leak"
        );
    }

    #[test]
    fn generate_data_source_uses_resolved_namespace_in_import_path() {
        let backend = AnsibleBackend::new();
        let provider = provider_with_namespace("drzln0");
        let ds = IacDataSource {
            name: "mycloud_volume".to_string(),
            description: "Get volume info".to_string(),
            read_endpoint: "/volumes".to_string(),
            read_schema: "ReadVolume".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let artifacts = backend.generate_data_source(&ds, &provider).unwrap();
        assert!(artifacts[0].content.contains(
            "from ansible_collections.drzln0.mycloud.plugins.module_utils.akeyless_client import"
        ));
    }

    #[test]
    fn generate_action_uses_resolved_namespace_in_import_path() {
        let backend = AnsibleBackend::new();
        let provider = provider_with_namespace("drzln0");
        let action = sample_action();
        let artifacts = backend.generate_action(&action, &provider).unwrap();
        assert!(artifacts[0].content.contains(
            "from ansible_collections.drzln0.mycloud.plugins.module_utils.akeyless_client import"
        ));
    }
}
