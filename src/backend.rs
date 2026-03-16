//! Ansible backend implementing the `iac-forge` `Backend` trait.
//!
//! Generates Python module files and integration test playbooks.

use iac_forge::{
    ArtifactKind, Backend, GeneratedArtifact, IacDataSource, IacForgeError, IacProvider,
    IacResource, NamingConvention, strip_provider_prefix, to_snake_case,
};

use crate::module_gen;

/// Ansible backend for `iac-forge`.
///
/// Generates Python Ansible module files from IaC IR types.
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

/// Naming convention for Ansible modules.
#[derive(Debug, Default)]
pub struct AnsibleNaming;

impl NamingConvention for AnsibleNaming {
    fn resource_type_name(&self, resource_name: &str, provider_name: &str) -> String {
        to_snake_case(strip_provider_prefix(resource_name, provider_name))
    }

    fn file_name(&self, resource_name: &str, kind: &ArtifactKind) -> String {
        let base = to_snake_case(resource_name);
        match kind {
            ArtifactKind::Resource | ArtifactKind::Module => format!("{base}.py"),
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
    fn platform(&self) -> &str {
        "ansible"
    }

    fn generate_resource(
        &self,
        resource: &IacResource,
        provider: &IacProvider,
    ) -> Result<Vec<GeneratedArtifact>, IacForgeError> {
        let module_name = strip_provider_prefix(&resource.name, &provider.name);
        let content = module_gen::generate_resource_module(resource, &provider.name);
        let path = format!("plugins/modules/{}.py", to_snake_case(module_name));

        Ok(vec![GeneratedArtifact {
            path,
            content,
            kind: ArtifactKind::Resource,
        }])
    }

    fn generate_data_source(
        &self,
        ds: &IacDataSource,
        provider: &IacProvider,
    ) -> Result<Vec<GeneratedArtifact>, IacForgeError> {
        let module_name = strip_provider_prefix(&ds.name, &provider.name);
        let content = module_gen::generate_data_source_module(ds, &provider.name);
        let path = format!("plugins/modules/{}_info.py", to_snake_case(module_name));

        Ok(vec![GeneratedArtifact {
            path,
            content,
            kind: ArtifactKind::DataSource,
        }])
    }

    fn generate_provider(
        &self,
        _provider: &IacProvider,
        _resources: &[IacResource],
        _data_sources: &[IacDataSource],
    ) -> Result<Vec<GeneratedArtifact>, IacForgeError> {
        // Ansible doesn't have a provider concept — no-op.
        Ok(vec![])
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

        Ok(vec![GeneratedArtifact {
            path,
            content,
            kind: ArtifactKind::Test,
        }])
    }

    fn naming(&self) -> &dyn NamingConvention {
        &self.naming
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iac_forge::{AuthInfo, CrudInfo, IacAttribute, IacType, IdentityInfo};
    use std::collections::HashMap;

    fn sample_provider() -> IacProvider {
        IacProvider {
            name: "mycloud".to_string(),
            description: "MyCloud provider".to_string(),
            version: "0.1.0".to_string(),
            auth: AuthInfo::default(),
            skip_fields: vec![],
            platform_config: HashMap::new(),
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
                IacAttribute {
                    api_name: "instance-name".to_string(),
                    canonical_name: "instance_name".to_string(),
                    description: "Name of the instance".to_string(),
                    iac_type: IacType::String,
                    required: true,
                    computed: false,
                    sensitive: false,
                    immutable: false,
                    default_value: None,
                    enum_values: None,
                    read_path: None,
                },
                IacAttribute {
                    api_name: "instance-id".to_string(),
                    canonical_name: "instance_id".to_string(),
                    description: "ID of the instance".to_string(),
                    iac_type: IacType::String,
                    required: false,
                    computed: true,
                    sensitive: false,
                    immutable: false,
                    default_value: None,
                    enum_values: None,
                    read_path: None,
                },
            ],
            identity: IdentityInfo {
                id_field: "instance_id".to_string(),
                import_field: "instance_name".to_string(),
                force_replace_fields: vec![],
            },
        }
    }

    #[test]
    fn platform_name() {
        let backend = AnsibleBackend::new();
        assert_eq!(backend.platform(), "ansible");
    }

    #[test]
    fn generate_resource_produces_python() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let resource = sample_resource();
        let artifacts = backend.generate_resource(&resource, &provider).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].path, "plugins/modules/instance.py");
        assert_eq!(artifacts[0].kind, ArtifactKind::Resource);
        assert!(artifacts[0].content.contains("AnsibleModule"));
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
        };
        let artifacts = backend.generate_data_source(&ds, &provider).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].path, "plugins/modules/instance_info.py");
        assert_eq!(artifacts[0].kind, ArtifactKind::DataSource);
    }

    #[test]
    fn generate_provider_is_noop() {
        let backend = AnsibleBackend::new();
        let provider = sample_provider();
        let artifacts = backend
            .generate_provider(&provider, &[], &[])
            .unwrap();
        assert!(artifacts.is_empty());
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
}
