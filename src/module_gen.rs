//! Python module generation for Ansible.
//!
//! Generates Ansible module Python files from platform-independent IR types.
//! Each generated module follows the standard Ansible module layout with
//! `DOCUMENTATION`, `EXAMPLES`, `RETURN` docstrings, and a `main()` function.

use iac_forge::{IacAttribute, IacDataSource, IacResource, IacType, strip_provider_prefix};

/// Extension trait mapping [`IacType`] to Ansible `argument_spec` type strings.
///
/// Provides method-syntax access to type mapping instead of free functions,
/// keeping the conversions co-located and discoverable.
pub trait AnsibleTypeExt {
    /// Ansible `argument_spec` type string for this IR type.
    ///
    /// For `Enum` types the underlying type is inspected, so an enum over
    /// integers maps to `"int"`, not `"str"`.
    fn ansible_type(&self) -> &'static str;

    /// Element type string for list/set types (e.g. `"str"` for `List(String)`).
    ///
    /// Returns `None` for non-collection types.
    fn ansible_elements(&self) -> Option<&'static str>;
}

impl AnsibleTypeExt for IacType {
    fn ansible_type(&self) -> &'static str {
        match self {
            Self::String | Self::Any => "str",
            Self::Integer => "int",
            Self::Float => "float",
            Self::Boolean => "bool",
            Self::List(_) | Self::Set(_) => "list",
            Self::Map(_) | Self::Object { .. } => "dict",
            Self::Enum { underlying, .. } => underlying.ansible_type(),
        }
    }

    fn ansible_elements(&self) -> Option<&'static str> {
        match self {
            Self::List(inner) | Self::Set(inner) => Some(inner.ansible_type()),
            _ => None,
        }
    }
}

/// Map an `IacType` to the Ansible `argument_spec` type string.
///
/// For `Enum` types, the underlying type is checked: if the underlying type
/// is `Integer`, the Ansible type will be `'int'`, not `'str'`.
#[must_use]
pub fn iac_type_to_ansible(ty: &IacType) -> &'static str {
    ty.ansible_type()
}

/// Get the `elements` type for list/set types, if applicable.
#[must_use]
pub fn list_elements_type(ty: &IacType) -> Option<&'static str> {
    ty.ansible_elements()
}

/// Build a YAML `options:` block from attributes.
fn build_options_yaml(attrs: &[IacAttribute]) -> String {
    let mut lines = Vec::new();
    for attr in attrs {
        if attr.computed && !attr.required {
            continue;
        }
        lines.push(format!("    {}:", attr.canonical_name));
        lines.push(format!(
            "      description: \"{}\"",
            attr.description.replace('"', "'")
        ));
        lines.push(format!("      type: {}", attr.iac_type.ansible_type()));
        if attr.required {
            lines.push("      required: true".to_string());
        }
        if attr.sensitive {
            lines.push("      no_log: true".to_string());
        }
        if let Some(elems) = attr.iac_type.ansible_elements() {
            lines.push(format!("      elements: {elems}"));
        }
        if let IacType::Enum { values, .. } = &attr.iac_type {
            let choices: Vec<String> = values.iter().map(|v| format!("\"{v}\"")).collect();
            lines.push(format!("      choices: [{}]", choices.join(", ")));
        }
        if let Some(ref ev) = attr.enum_values
            && !matches!(&attr.iac_type, IacType::Enum { .. })
        {
            let choices: Vec<String> = ev.iter().map(|v| format!("\"{v}\"")).collect();
            lines.push(format!("      choices: [{}]", choices.join(", ")));
        }
    }
    lines.join("\n")
}

/// Build a YAML `RETURN` block from computed attributes.
fn build_return_yaml(attrs: &[IacAttribute]) -> String {
    let mut lines = Vec::new();
    for attr in attrs {
        if !attr.computed {
            continue;
        }
        lines.push(format!("{}:", attr.canonical_name));
        lines.push(format!(
            "  description: \"{}\"",
            attr.description.replace('"', "'")
        ));
        lines.push(format!("  type: {}", attr.iac_type.ansible_type()));
        lines.push("  returned: success".to_string());
    }
    if lines.is_empty() {
        lines.push("# No computed fields".to_string());
    }
    lines.join("\n")
}

/// Build the Python `argument_spec` dict from attributes.
fn build_argument_spec(attrs: &[IacAttribute]) -> String {
    let mut entries = Vec::new();
    for attr in attrs {
        if attr.computed && !attr.required {
            continue;
        }
        let mut parts = Vec::new();
        parts.push(format!(
            "'type': '{}'",
            attr.iac_type.ansible_type()
        ));
        if attr.required {
            parts.push("'required': True".to_string());
        }
        if attr.sensitive {
            parts.push("'no_log': True".to_string());
        }
        if let Some(elems) = attr.iac_type.ansible_elements() {
            parts.push(format!("'elements': '{elems}'"));
        }
        if let IacType::Enum { values, .. } = &attr.iac_type {
            let choices: Vec<String> = values.iter().map(|v| format!("'{v}'")).collect();
            parts.push(format!("'choices': [{}]", choices.join(", ")));
        }
        if let Some(ref ev) = attr.enum_values
            && !matches!(&attr.iac_type, IacType::Enum { .. })
        {
            let choices: Vec<String> = ev.iter().map(|v| format!("'{v}'")).collect();
            parts.push(format!("'choices': [{}]", choices.join(", ")));
        }
        entries.push(format!(
            "        '{}': {{{}}},",
            attr.canonical_name,
            parts.join(", ")
        ));
    }
    entries.join("\n")
}

/// Build a state parameter entry for resource modules (present/absent).
fn state_spec_entry() -> &'static str {
    "        'state': {'type': 'str', 'choices': ['present', 'absent'], 'default': 'present'},"
}

/// Build a Python comment block listing immutable fields for `update_resource`.
fn immutable_fields_comment(resource: &IacResource) -> String {
    let names = resource.immutable_attribute_names();
    if names.is_empty() {
        return String::new();
    }
    let field_list = names
        .iter()
        .map(|n| format!("    #   - {n}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "\n    # WARNING: The following fields are immutable after creation.\n\
         {field_list}\n\
         \x20   # Changing them requires destroy + recreate.\n"
    )
}

/// Format the Python source for a resource module from pre-built fragments.
fn format_resource_python(
    module_name: &str,
    description: &str,
    options_yaml: &str,
    return_yaml: &str,
    argument_spec: &str,
    immutable_comment: &str,
) -> String {
    let state_spec = state_spec_entry();
    format!(
        r#"#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, pleme-io
# MIT License

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: {module_name}
short_description: {description}
description:
  - Manage {module_name} resources.
options:
    state:
      description: Whether the resource should be present or absent.
      type: str
      choices: ["present", "absent"]
      default: present
{options_yaml}
'''

EXAMPLES = r'''
- name: Create {module_name}
  {module_name}:
    state: present

- name: Delete {module_name}
  {module_name}:
    state: absent
'''

RETURN = r'''
{return_yaml}
'''

from ansible.module_utils.basic import AnsibleModule


def create_resource(module):
    """Create the resource."""
    try:
        # TODO: implement API call
        module.exit_json(changed=True, msg="{module_name} created")
    except Exception as e:
        module.fail_json(msg="Failed to create {module_name}: %s" % str(e))


def update_resource(module):
    """Update the resource."""{immutable_comment}
    try:
        # TODO: implement API call
        module.exit_json(changed=True, msg="{module_name} updated")
    except Exception as e:
        module.fail_json(msg="Failed to update {module_name}: %s" % str(e))


def delete_resource(module):
    """Delete the resource."""
    try:
        # TODO: implement API call
        module.exit_json(changed=True, msg="{module_name} deleted")
    except Exception as e:
        module.fail_json(msg="Failed to delete {module_name}: %s" % str(e))


def read_resource(module):
    """Read the current state of the resource."""
    try:
        # TODO: implement API call
        return None
    except Exception as e:
        module.fail_json(msg="Failed to read {module_name}: %s" % str(e))


def main():
    argument_spec = {{
{state_spec}
{argument_spec}
    }}

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    state = module.params.get('state', 'present')
    current = read_resource(module)

    if module.check_mode:
        module.exit_json(changed=(current is None and state == 'present')
                         or (current is not None and state == 'absent'))

    if state == 'absent':
        if current is not None:
            delete_resource(module)
        else:
            module.exit_json(changed=False, msg="{module_name} already absent")
    else:
        if current is None:
            create_resource(module)
        else:
            update_resource(module)


if __name__ == '__main__':
    main()
"#
    )
}

/// Generate a complete Python module for a resource.
#[must_use]
pub fn generate_resource_module(resource: &IacResource, provider_name: &str) -> String {
    let module_name = strip_provider_prefix(&resource.name, provider_name);
    let description = resource.description.replace('"', "'");
    let options_yaml = build_options_yaml(&resource.attributes);
    let return_yaml = build_return_yaml(&resource.attributes);
    let argument_spec = build_argument_spec(&resource.attributes);
    let immutable_comment = immutable_fields_comment(resource);

    format_resource_python(
        module_name,
        &description,
        &options_yaml,
        &return_yaml,
        &argument_spec,
        &immutable_comment,
    )
}

/// Generate a complete Python module for a data source (read-only).
#[must_use]
pub fn generate_data_source_module(ds: &IacDataSource, provider_name: &str) -> String {
    let module_name = format!(
        "{}_info",
        strip_provider_prefix(&ds.name, provider_name)
    );
    let options_yaml = build_options_yaml(&ds.attributes);
    let return_yaml = build_return_yaml(&ds.attributes);
    let argument_spec = build_argument_spec(&ds.attributes);

    format!(
        r#"#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, pleme-io
# MIT License

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: {module_name}
short_description: {description}
description:
  - Retrieve information about {module_name}.
options:
{options_yaml}
'''

EXAMPLES = r'''
- name: Get {module_name}
  {module_name}:
    register: result
'''

RETURN = r'''
{return_yaml}
'''

from ansible.module_utils.basic import AnsibleModule


def read_resource(module):
    """Read the data source."""
    try:
        # TODO: implement API call
        return {{}}
    except Exception as e:
        module.fail_json(msg="Failed to read {module_name}: %s" % str(e))


def main():
    argument_spec = {{
{argument_spec}
    }}

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        result = read_resource(module)
        module.exit_json(changed=False, **result)
    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
"#,
        module_name = module_name,
        description = ds.description.replace('"', "'"),
        options_yaml = options_yaml,
        return_yaml = return_yaml,
        argument_spec = argument_spec,
    )
}

/// Generate a YAML integration test for a resource.
#[must_use]
pub fn generate_test_playbook(resource: &IacResource, provider_name: &str) -> String {
    let module_name = strip_provider_prefix(&resource.name, provider_name);

    let mut task_params = Vec::new();
    for attr in &resource.attributes {
        if attr.required {
            let value = match &attr.iac_type {
                IacType::Integer => "1".to_string(),
                IacType::Float => "1.0".to_string(),
                IacType::Boolean => "true".to_string(),
                IacType::Enum { values, .. } => {
                    if let Some(first) = values.first() {
                        format!("\"{first}\"")
                    } else {
                        "\"\"".to_string()
                    }
                }
                _ => "\"test_value\"".to_string(),
            };
            task_params.push(format!("        {}: {}", attr.canonical_name, value));
        }
    }

    let params_block = if task_params.is_empty() {
        String::new()
    } else {
        format!("\n{}", task_params.join("\n"))
    };

    format!(
        r"---
# Integration test for {module_name}

- name: Test {module_name} module
  hosts: localhost
  connection: local
  gather_facts: false

  tasks:
    - name: Create {module_name}
      {module_name}:
        state: present{params_block}
      register: create_result

    - name: Verify creation
      ansible.builtin.assert:
        that:
          - create_result.changed

    - name: Create {module_name} (idempotent)
      {module_name}:
        state: present{params_block}
      register: idempotent_result

    - name: Delete {module_name}
      {module_name}:
        state: absent{params_block}
      register: delete_result

    - name: Verify deletion
      ansible.builtin.assert:
        that:
          - delete_result.changed
"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use iac_forge::{CrudInfo, IdentityInfo};

    fn sample_resource() -> IacResource {
        IacResource {
            name: "test_static_secret".to_string(),
            description: "Manage a static secret".to_string(),
            category: "secrets".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "CreateBody".to_string(),
                update_endpoint: Some("/update".to_string()),
                update_schema: Some("UpdateBody".to_string()),
                read_endpoint: "/read".to_string(),
                read_schema: "ReadBody".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "DeleteBody".to_string(),
            },
            attributes: vec![
                IacAttribute {
                    api_name: "name".to_string(),
                    canonical_name: "name".to_string(),
                    description: "The name of the secret".to_string(),
                    iac_type: IacType::String,
                    required: true,
                    computed: false,
                    sensitive: false,
                    immutable: false,
                    default_value: None,
                    enum_values: None,
                    read_path: None,
                    update_only: false,
                },
                IacAttribute {
                    api_name: "value".to_string(),
                    canonical_name: "value".to_string(),
                    description: "The secret value".to_string(),
                    iac_type: IacType::String,
                    required: true,
                    computed: false,
                    sensitive: true,
                    immutable: false,
                    default_value: None,
                    enum_values: None,
                    read_path: None,
                    update_only: false,
                },
                IacAttribute {
                    api_name: "tags".to_string(),
                    canonical_name: "tags".to_string(),
                    description: "Resource tags".to_string(),
                    iac_type: IacType::List(Box::new(IacType::String)),
                    required: false,
                    computed: false,
                    sensitive: false,
                    immutable: false,
                    default_value: None,
                    enum_values: None,
                    read_path: None,
                    update_only: false,
                },
                IacAttribute {
                    api_name: "secret_id".to_string(),
                    canonical_name: "secret_id".to_string(),
                    description: "The ID of the secret".to_string(),
                    iac_type: IacType::String,
                    required: false,
                    computed: true,
                    sensitive: false,
                    immutable: false,
                    default_value: None,
                    enum_values: None,
                    read_path: None,
                    update_only: false,
                },
                IacAttribute {
                    api_name: "protection_type".to_string(),
                    canonical_name: "protection_type".to_string(),
                    description: "The type of protection".to_string(),
                    iac_type: IacType::Enum {
                        values: vec!["aes128".to_string(), "aes256".to_string(), "rsa2048".to_string()],
                        underlying: Box::new(IacType::String),
                    },
                    required: false,
                    computed: false,
                    sensitive: false,
                    immutable: false,
                    default_value: None,
                    enum_values: None,
                    read_path: None,
                    update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "secret_id".to_string(),
                import_field: "name".to_string(),
                force_replace_fields: vec![],
            },
        }
    }

    /// Helper to build a resource with an immutable field.
    fn sample_resource_with_immutable() -> IacResource {
        let mut resource = sample_resource();
        resource.attributes.push(IacAttribute {
            api_name: "region".to_string(),
            canonical_name: "region".to_string(),
            description: "The region for the secret".to_string(),
            iac_type: IacType::String,
            required: true,
            computed: false,
            sensitive: false,
            immutable: true,
            default_value: None,
            enum_values: None,
            read_path: None,
            update_only: false,
        });
        resource
    }

    #[test]
    fn type_mappings() {
        assert_eq!(iac_type_to_ansible(&IacType::String), "str");
        assert_eq!(iac_type_to_ansible(&IacType::Integer), "int");
        assert_eq!(iac_type_to_ansible(&IacType::Float), "float");
        assert_eq!(iac_type_to_ansible(&IacType::Boolean), "bool");
        assert_eq!(
            iac_type_to_ansible(&IacType::List(Box::new(IacType::String))),
            "list"
        );
        assert_eq!(
            iac_type_to_ansible(&IacType::Map(Box::new(IacType::String))),
            "dict"
        );
        assert_eq!(
            iac_type_to_ansible(&IacType::Enum {
                values: vec!["a".into()],
                underlying: Box::new(IacType::String),
            }),
            "str"
        );
    }

    #[test]
    fn enum_with_integer_underlying_maps_to_int() {
        assert_eq!(
            iac_type_to_ansible(&IacType::Enum {
                values: vec!["1".into(), "2".into()],
                underlying: Box::new(IacType::Integer),
            }),
            "int"
        );
    }

    #[test]
    fn list_elements() {
        assert_eq!(
            list_elements_type(&IacType::List(Box::new(IacType::String))),
            Some("str")
        );
        assert_eq!(
            list_elements_type(&IacType::Set(Box::new(IacType::Integer))),
            Some("int")
        );
        assert_eq!(list_elements_type(&IacType::String), None);
    }

    #[test]
    fn ansible_type_ext_matches_free_fn() {
        let types = [
            IacType::String,
            IacType::Integer,
            IacType::Float,
            IacType::Boolean,
            IacType::Any,
            IacType::List(Box::new(IacType::String)),
            IacType::Set(Box::new(IacType::Integer)),
            IacType::Map(Box::new(IacType::String)),
            IacType::Object {
                name: "T".into(),
                fields: vec![],
            },
            IacType::Enum {
                values: vec!["a".into()],
                underlying: Box::new(IacType::Integer),
            },
        ];
        for ty in &types {
            assert_eq!(ty.ansible_type(), iac_type_to_ansible(ty));
            assert_eq!(ty.ansible_elements(), list_elements_type(ty));
        }
    }

    #[test]
    fn resource_module_contains_documentation() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("DOCUMENTATION = r'''"));
        assert!(output.contains("module: static_secret"));
        assert!(output.contains("short_description: Manage a static secret"));
    }

    #[test]
    fn resource_module_uses_dict_literal_not_dict_call() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        // Must use dict literal `{...}`, not `dict(...)`.
        assert!(
            output.contains("argument_spec = {"),
            "argument_spec must use dict literal syntax, got:\n{output}"
        );
        assert!(
            !output.contains("argument_spec = dict("),
            "argument_spec must NOT use dict() call syntax"
        );
    }

    #[test]
    fn data_source_module_uses_dict_literal_not_dict_call() {
        let ds = IacDataSource {
            name: "test_secret_info".to_string(),
            description: "Get secret information".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadBody".to_string(),
            read_response_schema: None,
            attributes: vec![IacAttribute {
                api_name: "name".to_string(),
                canonical_name: "name".to_string(),
                description: "Secret name".to_string(),
                iac_type: IacType::String,
                required: true,
                computed: false,
                sensitive: false,
                immutable: false,
                default_value: None,
                enum_values: None,
                read_path: None,
                update_only: false,
            }],
        };
        let output = generate_data_source_module(&ds, "test");
        assert!(
            output.contains("argument_spec = {"),
            "data source argument_spec must use dict literal syntax"
        );
        assert!(
            !output.contains("argument_spec = dict("),
            "data source argument_spec must NOT use dict() call syntax"
        );
    }

    #[test]
    fn resource_module_argument_spec_types() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("'name': {'type': 'str', 'required': True}"));
        assert!(output.contains("'tags': {'type': 'list', 'elements': 'str'}"));
    }

    #[test]
    fn resource_module_required_fields() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("'name': {'type': 'str', 'required': True}"));
        assert!(output.contains("'value': {'type': 'str', 'required': True, 'no_log': True}"));
    }

    #[test]
    fn resource_module_sensitive_no_log() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("'no_log': True"));
        let doc_section = &output[output.find("DOCUMENTATION").unwrap()..output.find("EXAMPLES").unwrap()];
        assert!(doc_section.contains("no_log: true"));
    }

    #[test]
    fn resource_module_enum_choices() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("'choices': ['aes128', 'aes256', 'rsa2048']"));
        let doc_section = &output[output.find("DOCUMENTATION").unwrap()..output.find("EXAMPLES").unwrap()];
        assert!(doc_section.contains("choices: [\"aes128\", \"aes256\", \"rsa2048\"]"));
    }

    #[test]
    fn module_name_snake_case() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("module: static_secret"));
        assert!(!output.contains("module: test_static_secret"));
    }

    #[test]
    fn data_source_module_read_only() {
        let ds = IacDataSource {
            name: "test_secret_info".to_string(),
            description: "Get secret information".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadBody".to_string(),
            read_response_schema: None,
            attributes: vec![IacAttribute {
                api_name: "name".to_string(),
                canonical_name: "name".to_string(),
                description: "Secret name".to_string(),
                iac_type: IacType::String,
                required: true,
                computed: false,
                sensitive: false,
                immutable: false,
                default_value: None,
                enum_values: None,
                read_path: None,
                update_only: false,
            }],
        };
        let output = generate_data_source_module(&ds, "test");
        assert!(output.contains("module: secret_info_info"));
        assert!(!output.contains("state"));
        assert!(!output.contains("create_resource"));
        assert!(!output.contains("delete_resource"));
    }

    #[test]
    fn test_playbook_generation() {
        let resource = sample_resource();
        let output = generate_test_playbook(&resource, "test");
        assert!(output.contains("Test static_secret module"));
        assert!(output.contains("state: present"));
        assert!(output.contains("state: absent"));
        assert!(output.contains("name: \"test_value\""));
    }

    #[test]
    fn computed_fields_excluded_from_argument_spec() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(!output.contains("'secret_id':"));
        let return_section = &output[output.find("RETURN").unwrap()..];
        assert!(return_section.contains("secret_id"));
    }

    #[test]
    fn resource_module_has_error_handling() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        // All CRUD functions should have try/except with module.fail_json
        assert!(
            output.contains("module.fail_json(msg=\"Failed to create"),
            "create_resource must have fail_json error handling"
        );
        assert!(
            output.contains("module.fail_json(msg=\"Failed to update"),
            "update_resource must have fail_json error handling"
        );
        assert!(
            output.contains("module.fail_json(msg=\"Failed to delete"),
            "delete_resource must have fail_json error handling"
        );
        assert!(
            output.contains("module.fail_json(msg=\"Failed to read"),
            "read_resource must have fail_json error handling"
        );
    }

    #[test]
    fn data_source_module_has_error_handling() {
        let ds = IacDataSource {
            name: "test_secret_info".to_string(),
            description: "Get secret information".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadBody".to_string(),
            read_response_schema: None,
            attributes: vec![],
        };
        let output = generate_data_source_module(&ds, "test");
        assert!(
            output.contains("module.fail_json("),
            "data source must have fail_json error handling"
        );
    }

    #[test]
    fn immutable_fields_generate_update_comment() {
        let resource = sample_resource_with_immutable();
        let output = generate_resource_module(&resource, "test");
        assert!(
            output.contains("immutable after creation"),
            "update_resource should warn about immutable fields"
        );
        assert!(
            output.contains("- region"),
            "update_resource should list immutable field 'region'"
        );
    }

    #[test]
    fn no_immutable_fields_no_comment() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(
            !output.contains("immutable after creation"),
            "should not have immutable comment when no fields are immutable"
        );
    }

    #[test]
    fn generated_python_has_valid_dict_syntax() {
        // Regression test: generated Python must never use dict('key': ...)
        // syntax, which is invalid. It must use dict literal {}.
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");

        // Check that argument_spec uses { ... } literal
        let spec_start = output.find("argument_spec = {").expect("must have argument_spec = {");
        let after_spec = &output[spec_start..];
        // The closing brace should come before the next `module = AnsibleModule` line
        assert!(
            after_spec.contains("}"),
            "argument_spec dict literal must have closing brace"
        );

        // Ensure no `dict(` anywhere in the main() function area
        let main_fn = &output[output.find("def main():").unwrap()..];
        assert!(
            !main_fn.contains("dict("),
            "main() must not contain dict() call syntax"
        );
    }

    #[test]
    fn data_source_returns_empty_dict() {
        let ds = IacDataSource {
            name: "test_info".to_string(),
            description: "Test data source".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadBody".to_string(),
            read_response_schema: None,
            attributes: vec![],
        };
        let output = generate_data_source_module(&ds, "test");
        // The data source read_resource should return {} (empty dict)
        assert!(
            output.contains("return {}"),
            "data source read_resource must return empty dict {{}}, got:\n{output}"
        );
    }

    /// Resource with ALL IacType variants.
    fn resource_with_all_types() -> IacResource {
        IacResource {
            name: "test_all_types".to_string(),
            description: "All types".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: Some("/update".to_string()),
                update_schema: Some("Update".to_string()),
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![
                IacAttribute {
                    api_name: "str_field".to_string(),
                    canonical_name: "str_field".to_string(),
                    description: "A string".to_string(),
                    iac_type: IacType::String,
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "int_field".to_string(),
                    canonical_name: "int_field".to_string(),
                    description: "An int".to_string(),
                    iac_type: IacType::Integer,
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "float_field".to_string(),
                    canonical_name: "float_field".to_string(),
                    description: "A float".to_string(),
                    iac_type: IacType::Float,
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "bool_field".to_string(),
                    canonical_name: "bool_field".to_string(),
                    description: "A bool".to_string(),
                    iac_type: IacType::Boolean,
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "list_field".to_string(),
                    canonical_name: "list_field".to_string(),
                    description: "A list".to_string(),
                    iac_type: IacType::List(Box::new(IacType::String)),
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "set_field".to_string(),
                    canonical_name: "set_field".to_string(),
                    description: "A set".to_string(),
                    iac_type: IacType::Set(Box::new(IacType::Integer)),
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "map_field".to_string(),
                    canonical_name: "map_field".to_string(),
                    description: "A map".to_string(),
                    iac_type: IacType::Map(Box::new(IacType::String)),
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "obj_field".to_string(),
                    canonical_name: "obj_field".to_string(),
                    description: "An object".to_string(),
                    iac_type: IacType::Object { name: "Obj".to_string(), fields: vec![] },
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "enum_field".to_string(),
                    canonical_name: "enum_field".to_string(),
                    description: "An enum".to_string(),
                    iac_type: IacType::Enum {
                        values: vec!["x".into(), "y".into()],
                        underlying: Box::new(IacType::String),
                    },
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "any_field".to_string(),
                    canonical_name: "any_field".to_string(),
                    description: "An any".to_string(),
                    iac_type: IacType::Any,
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "str_field".to_string(),
                import_field: "str_field".to_string(),
                force_replace_fields: vec![],
            },
        }
    }

    #[test]
    fn resource_with_all_iac_type_variants_in_argument_spec() {
        let resource = resource_with_all_types();
        let output = generate_resource_module(&resource, "test");

        assert!(output.contains("'str_field': {'type': 'str'}"), "str missing");
        assert!(output.contains("'int_field': {'type': 'int'}"), "int missing");
        assert!(output.contains("'float_field': {'type': 'float'}"), "float missing");
        assert!(output.contains("'bool_field': {'type': 'bool'}"), "bool missing");
        assert!(output.contains("'list_field': {'type': 'list', 'elements': 'str'}"), "list missing");
        assert!(output.contains("'set_field': {'type': 'list', 'elements': 'int'}"), "set missing");
        assert!(output.contains("'map_field': {'type': 'dict'}"), "map missing");
        assert!(output.contains("'obj_field': {'type': 'dict'}"), "object missing");
        assert!(output.contains("'enum_field': {'type': 'str', 'choices': ['x', 'y']}"), "enum missing");
        assert!(output.contains("'any_field': {'type': 'str'}"), "any missing");
    }

    #[test]
    fn resource_with_all_iac_type_variants_in_documentation() {
        let resource = resource_with_all_types();
        let output = generate_resource_module(&resource, "test");
        let doc_section = &output[output.find("DOCUMENTATION").unwrap()..output.find("EXAMPLES").unwrap()];

        assert!(doc_section.contains("type: str"), "str doc missing");
        assert!(doc_section.contains("type: int"), "int doc missing");
        assert!(doc_section.contains("type: float"), "float doc missing");
        assert!(doc_section.contains("type: bool"), "bool doc missing");
        assert!(doc_section.contains("type: list"), "list doc missing");
        assert!(doc_section.contains("type: dict"), "dict doc missing");
    }

    #[test]
    fn module_with_no_attributes() {
        let resource = IacResource {
            name: "test_empty".to_string(),
            description: "Empty resource".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![],
            identity: IdentityInfo {
                id_field: "id".to_string(),
                import_field: "id".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_resource_module(&resource, "test");

        // Should still have valid Python with state parameter
        assert!(output.contains("AnsibleModule"));
        assert!(output.contains("'state':"));
        assert!(output.contains("module: empty"));
        // RETURN should indicate no computed fields
        let return_section = &output[output.find("RETURN").unwrap()..];
        assert!(return_section.contains("# No computed fields"));
    }

    #[test]
    fn data_source_module_structure() {
        let ds = IacDataSource {
            name: "test_role".to_string(),
            description: "Get role info".to_string(),
            read_endpoint: "/read-role".to_string(),
            read_schema: "ReadRole".to_string(),
            read_response_schema: None,
            attributes: vec![
                IacAttribute {
                    api_name: "name".to_string(),
                    canonical_name: "name".to_string(),
                    description: "Role name".to_string(),
                    iac_type: IacType::String,
                    required: true, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "permissions".to_string(),
                    canonical_name: "permissions".to_string(),
                    description: "Permissions".to_string(),
                    iac_type: IacType::List(Box::new(IacType::String)),
                    required: false, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
        };

        let output = generate_data_source_module(&ds, "test");

        // Should contain the info suffix module name
        assert!(output.contains("module: role_info"));
        // Should NOT have state/create/delete/update
        assert!(!output.contains("'state'"));
        assert!(!output.contains("def create_resource"));
        assert!(!output.contains("def delete_resource"));
        assert!(!output.contains("def update_resource"));
        // Input field should be in argument_spec
        assert!(output.contains("'name': {'type': 'str', 'required': True}"));
        // Computed field should NOT be in argument_spec
        assert!(!output.contains("'permissions':"));
        // Computed field should be in RETURN
        let return_section = &output[output.find("RETURN").unwrap()..];
        assert!(return_section.contains("permissions:"));
    }

    #[test]
    fn test_playbook_yaml_structure() {
        let resource = sample_resource();
        let output = generate_test_playbook(&resource, "test");

        // Should be valid YAML-like structure
        assert!(output.starts_with("---"));
        assert!(output.contains("hosts: localhost"));
        assert!(output.contains("connection: local"));
        assert!(output.contains("gather_facts: false"));
        assert!(output.contains("tasks:"));
        // Should have create, idempotent, delete tasks
        assert!(output.contains("Create static_secret"));
        assert!(output.contains("Create static_secret (idempotent)"));
        assert!(output.contains("Delete static_secret"));
        // Should have assertions
        assert!(output.contains("ansible.builtin.assert"));
        assert!(output.contains("create_result.changed"));
        assert!(output.contains("delete_result.changed"));
    }

    #[test]
    fn generate_all_produces_module_files() {
        use iac_forge::{AuthInfo, Backend, IacProvider};
        use std::collections::HashMap;

        let backend = super::super::backend::AnsibleBackend::new();
        let provider = IacProvider {
            name: "mycloud".to_string(),
            description: "Provider".to_string(),
            version: "0.1.0".to_string(),
            auth: AuthInfo::default(),
            skip_fields: vec![],
            platform_config: HashMap::new(),
        };

        let resources = vec![sample_resource()];
        let data_sources: Vec<IacDataSource> = vec![];

        let artifacts = backend
            .generate_all(&provider, &resources, &data_sources)
            .expect("generate_all should succeed");

        // 1 resource + 0 data sources + 0 provider + 1 test = 2
        assert_eq!(artifacts.len(), 2);
        assert!(artifacts.iter().any(|a| a.path.contains("plugins/modules/")));
        assert!(artifacts.iter().any(|a| a.path.contains("tests/integration/")));

        // Verify module content is valid
        for artifact in &artifacts {
            if artifact.path.ends_with(".py") {
                assert!(artifact.content.contains("AnsibleModule"));
            }
            if artifact.path.ends_with(".yml") {
                assert!(artifact.content.contains("state: present"));
            }
        }
    }

    #[test]
    fn module_name_follows_snake_case_from_resource_name() {
        let resource = IacResource {
            name: "test_my_complex_resource".to_string(),
            description: "Complex".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![],
            identity: IdentityInfo {
                id_field: "id".to_string(),
                import_field: "id".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_resource_module(&resource, "test");
        // Module name should be snake_case with provider prefix stripped
        assert!(output.contains("module: my_complex_resource"));
    }

    #[test]
    fn set_type_maps_to_list() {
        assert_eq!(iac_type_to_ansible(&IacType::Set(Box::new(IacType::String))), "list");
        assert_eq!(
            list_elements_type(&IacType::Set(Box::new(IacType::String))),
            Some("str")
        );
    }

    #[test]
    fn any_type_maps_to_str() {
        assert_eq!(iac_type_to_ansible(&IacType::Any), "str");
    }

    #[test]
    fn object_type_maps_to_dict() {
        assert_eq!(
            iac_type_to_ansible(&IacType::Object {
                name: "Obj".to_string(),
                fields: vec![],
            }),
            "dict"
        );
    }

    #[test]
    fn test_playbook_with_enum_required_field() {
        let resource = IacResource {
            name: "test_thing".to_string(),
            description: "Thing".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "mode".to_string(),
                canonical_name: "mode".to_string(),
                description: "Mode".to_string(),
                iac_type: IacType::Enum {
                    values: vec!["fast".into(), "slow".into()],
                    underlying: Box::new(IacType::String),
                },
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "mode".to_string(),
                import_field: "mode".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_test_playbook(&resource, "test");
        // Enum required field should use first enum value in the test playbook
        assert!(output.contains("mode: \"fast\""));
    }

    #[test]
    fn test_playbook_with_int_required_field() {
        let resource = IacResource {
            name: "test_item".to_string(),
            description: "Item".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![
                IacAttribute {
                    api_name: "count".to_string(),
                    canonical_name: "count".to_string(),
                    description: "Count".to_string(),
                    iac_type: IacType::Integer,
                    required: true, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "rate".to_string(),
                    canonical_name: "rate".to_string(),
                    description: "Rate".to_string(),
                    iac_type: IacType::Float,
                    required: true, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "enabled".to_string(),
                    canonical_name: "enabled".to_string(),
                    description: "Enabled".to_string(),
                    iac_type: IacType::Boolean,
                    required: true, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "count".to_string(),
                import_field: "count".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_test_playbook(&resource, "test");
        assert!(output.contains("count: 1"));
        assert!(output.contains("rate: 1.0"));
        assert!(output.contains("enabled: true"));
    }

    #[test]
    fn multiple_immutable_fields_listed_in_comment() {
        let mut resource = sample_resource();
        resource.attributes.push(IacAttribute {
            api_name: "region".to_string(),
            canonical_name: "region".to_string(),
            description: "Region".to_string(),
            iac_type: IacType::String,
            required: true, computed: false, sensitive: false, immutable: true,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        });
        resource.attributes.push(IacAttribute {
            api_name: "zone".to_string(),
            canonical_name: "zone".to_string(),
            description: "Zone".to_string(),
            iac_type: IacType::String,
            required: false, computed: false, sensitive: false, immutable: true,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        });

        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("- region"));
        assert!(output.contains("- zone"));
        assert!(output.contains("immutable after creation"));
    }

    #[test]
    fn test_playbook_enum_with_empty_values_uses_empty_string() {
        let resource = IacResource {
            name: "test_widget".to_string(),
            description: "Widget".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "status".to_string(),
                canonical_name: "status".to_string(),
                description: "Status".to_string(),
                iac_type: IacType::Enum {
                    values: vec![],
                    underlying: Box::new(IacType::String),
                },
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "status".to_string(),
                import_field: "status".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_test_playbook(&resource, "test");
        assert!(
            output.contains("status: \"\""),
            "empty enum values should produce empty string, got:\n{output}"
        );
    }

    #[test]
    fn test_playbook_list_required_field_uses_test_value() {
        let resource = IacResource {
            name: "test_thing".to_string(),
            description: "Thing".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "tags".to_string(),
                canonical_name: "tags".to_string(),
                description: "Tags".to_string(),
                iac_type: IacType::List(Box::new(IacType::String)),
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "tags".to_string(),
                import_field: "tags".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_test_playbook(&resource, "test");
        assert!(
            output.contains("tags: \"test_value\""),
            "wildcard arm should use test_value for list type, got:\n{output}"
        );
    }

    #[test]
    fn test_playbook_map_required_field_uses_test_value() {
        let resource = IacResource {
            name: "test_thing".to_string(),
            description: "Thing".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "metadata".to_string(),
                canonical_name: "metadata".to_string(),
                description: "Metadata".to_string(),
                iac_type: IacType::Map(Box::new(IacType::String)),
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "metadata".to_string(),
                import_field: "metadata".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_test_playbook(&resource, "test");
        assert!(
            output.contains("metadata: \"test_value\""),
            "wildcard arm should use test_value for map type, got:\n{output}"
        );
    }

    #[test]
    fn test_playbook_with_no_required_fields() {
        let resource = IacResource {
            name: "test_optional_only".to_string(),
            description: "All optional".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "label".to_string(),
                canonical_name: "label".to_string(),
                description: "A label".to_string(),
                iac_type: IacType::String,
                required: false, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "label".to_string(),
                import_field: "label".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_test_playbook(&resource, "test");
        assert!(output.contains("state: present"));
        assert!(!output.contains("label:"), "optional fields should not appear in test playbook params");
    }

    #[test]
    fn enum_values_on_non_enum_type_produces_choices() {
        let resource = IacResource {
            name: "test_constrained".to_string(),
            description: "Constrained string".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "tier".to_string(),
                canonical_name: "tier".to_string(),
                description: "The service tier".to_string(),
                iac_type: IacType::String,
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None,
                enum_values: Some(vec!["free".to_string(), "pro".to_string(), "enterprise".to_string()]),
                read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "tier".to_string(),
                import_field: "tier".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_resource_module(&resource, "test");

        let doc_section = &output[output.find("DOCUMENTATION").unwrap()..output.find("EXAMPLES").unwrap()];
        assert!(
            doc_section.contains("choices: [\"free\", \"pro\", \"enterprise\"]"),
            "DOCUMENTATION should contain choices from enum_values on non-Enum type, got:\n{doc_section}"
        );
        assert!(
            output.contains("'choices': ['free', 'pro', 'enterprise']"),
            "argument_spec should contain choices from enum_values on non-Enum type, got:\n{output}"
        );
    }

    #[test]
    fn enum_values_not_duplicated_on_enum_type() {
        let resource = IacResource {
            name: "test_enum_dup".to_string(),
            description: "Enum with enum_values".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "level".to_string(),
                canonical_name: "level".to_string(),
                description: "Level".to_string(),
                iac_type: IacType::Enum {
                    values: vec!["low".to_string(), "high".to_string()],
                    underlying: Box::new(IacType::String),
                },
                required: false, computed: false, sensitive: false, immutable: false,
                default_value: None,
                enum_values: Some(vec!["low".to_string(), "high".to_string()]),
                read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "level".to_string(),
                import_field: "level".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_resource_module(&resource, "test");
        let choices_count = output.matches("'choices': ['low', 'high']").count();
        assert_eq!(
            choices_count, 1,
            "choices for the enum field should appear only once (from IacType::Enum), not duplicated by enum_values"
        );
    }

    #[test]
    fn computed_and_required_field_in_argument_spec() {
        let resource = IacResource {
            name: "test_comp_req".to_string(),
            description: "Has computed+required".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![
                IacAttribute {
                    api_name: "name".to_string(),
                    canonical_name: "name".to_string(),
                    description: "The name".to_string(),
                    iac_type: IacType::String,
                    required: true, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "gen_id".to_string(),
                    canonical_name: "gen_id".to_string(),
                    description: "Server-generated ID".to_string(),
                    iac_type: IacType::String,
                    required: false, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "gen_id".to_string(),
                import_field: "name".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_resource_module(&resource, "test");
        assert!(
            output.contains("'name': {'type': 'str', 'required': True}"),
            "computed+required field should be in argument_spec"
        );
        assert!(
            !output.contains("'gen_id':"),
            "computed-only field should NOT be in argument_spec"
        );

        let return_section = &output[output.find("RETURN").unwrap()..];
        assert!(return_section.contains("name:"), "computed+required should appear in RETURN");
        assert!(return_section.contains("gen_id:"), "computed-only should appear in RETURN");
    }

    #[test]
    fn description_with_double_quotes_escaped() {
        let resource = IacResource {
            name: "test_quotes".to_string(),
            description: "A \"quoted\" description".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "field".to_string(),
                canonical_name: "field".to_string(),
                description: "Field with \"quotes\" inside".to_string(),
                iac_type: IacType::String,
                required: false, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "field".to_string(),
                import_field: "field".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_resource_module(&resource, "test");
        assert!(
            output.contains("A 'quoted' description"),
            "resource description double quotes should be replaced with single quotes"
        );
        assert!(
            output.contains("Field with 'quotes' inside"),
            "attribute description double quotes should be replaced with single quotes"
        );
    }

    #[test]
    fn nested_list_type_elements() {
        let resource = IacResource {
            name: "test_nested".to_string(),
            description: "Nested types".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![
                IacAttribute {
                    api_name: "int_list".to_string(),
                    canonical_name: "int_list".to_string(),
                    description: "List of ints".to_string(),
                    iac_type: IacType::List(Box::new(IacType::Integer)),
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "bool_set".to_string(),
                    canonical_name: "bool_set".to_string(),
                    description: "Set of bools".to_string(),
                    iac_type: IacType::Set(Box::new(IacType::Boolean)),
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "dict_list".to_string(),
                    canonical_name: "dict_list".to_string(),
                    description: "List of dicts".to_string(),
                    iac_type: IacType::List(Box::new(IacType::Map(Box::new(IacType::String)))),
                    required: false, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "int_list".to_string(),
                import_field: "int_list".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("'int_list': {'type': 'list', 'elements': 'int'}"));
        assert!(output.contains("'bool_set': {'type': 'list', 'elements': 'bool'}"));
        assert!(output.contains("'dict_list': {'type': 'list', 'elements': 'dict'}"));
    }

    #[test]
    fn data_source_with_sensitive_field() {
        let ds = IacDataSource {
            name: "test_secret_ds".to_string(),
            description: "Secret data source".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadBody".to_string(),
            read_response_schema: None,
            attributes: vec![
                IacAttribute {
                    api_name: "name".to_string(),
                    canonical_name: "name".to_string(),
                    description: "Name".to_string(),
                    iac_type: IacType::String,
                    required: true, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "password".to_string(),
                    canonical_name: "password".to_string(),
                    description: "Secret password".to_string(),
                    iac_type: IacType::String,
                    required: true, computed: false, sensitive: true, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
        };

        let output = generate_data_source_module(&ds, "test");
        assert!(
            output.contains("'password': {'type': 'str', 'required': True, 'no_log': True}"),
            "data source sensitive field should have no_log"
        );
        let doc_section = &output[output.find("DOCUMENTATION").unwrap()..output.find("EXAMPLES").unwrap()];
        assert!(
            doc_section.contains("no_log: true"),
            "DOCUMENTATION should list no_log for sensitive data source field"
        );
    }

    #[test]
    fn data_source_with_computed_return_fields() {
        let ds = IacDataSource {
            name: "test_info_ds".to_string(),
            description: "Info data source".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadBody".to_string(),
            read_response_schema: None,
            attributes: vec![
                IacAttribute {
                    api_name: "name".to_string(),
                    canonical_name: "name".to_string(),
                    description: "Name input".to_string(),
                    iac_type: IacType::String,
                    required: true, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "size".to_string(),
                    canonical_name: "size".to_string(),
                    description: "Size".to_string(),
                    iac_type: IacType::Integer,
                    required: false, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "enabled".to_string(),
                    canonical_name: "enabled".to_string(),
                    description: "Is enabled".to_string(),
                    iac_type: IacType::Boolean,
                    required: false, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
        };

        let output = generate_data_source_module(&ds, "test");
        assert!(!output.contains("'size':"), "computed field should not be in data source argument_spec");
        assert!(!output.contains("'enabled':"), "computed field should not be in data source argument_spec");

        let return_section = &output[output.find("RETURN").unwrap()..];
        assert!(return_section.contains("size:"), "computed field should be in RETURN");
        assert!(return_section.contains("type: int"), "int computed field should show correct type in RETURN");
        assert!(return_section.contains("enabled:"), "computed field should be in RETURN");
        assert!(return_section.contains("type: bool"), "bool computed field should show correct type in RETURN");
    }

    #[test]
    fn generate_all_with_resources_and_data_sources() {
        use iac_forge::{ArtifactKind, AuthInfo, Backend, IacProvider};
        use std::collections::HashMap;

        let backend = super::super::backend::AnsibleBackend::new();
        let provider = IacProvider {
            name: "mycloud".to_string(),
            description: "Provider".to_string(),
            version: "0.1.0".to_string(),
            auth: AuthInfo::default(),
            skip_fields: vec![],
            platform_config: HashMap::new(),
        };

        let mut resource = sample_resource();
        resource.name = "mycloud_static_secret".to_string();

        let data_sources = vec![IacDataSource {
            name: "mycloud_secret_info".to_string(),
            description: "Get secret info".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "Read".to_string(),
            read_response_schema: None,
            attributes: vec![],
        }];

        let artifacts = backend
            .generate_all(&provider, &[resource], &data_sources)
            .expect("generate_all should succeed");

        assert_eq!(artifacts.len(), 3, "1 resource + 1 data source + 0 provider + 1 test = 3");
        assert!(artifacts.iter().any(|a| a.kind == ArtifactKind::Resource));
        assert!(artifacts.iter().any(|a| a.kind == ArtifactKind::DataSource));
        assert!(artifacts.iter().any(|a| a.kind == ArtifactKind::Test));

        let ds_artifact = artifacts.iter().find(|a| a.kind == ArtifactKind::DataSource).unwrap();
        assert!(ds_artifact.path.ends_with("_info.py"));
    }

    #[test]
    fn resource_with_only_computed_attributes() {
        let resource = IacResource {
            name: "test_readonly".to_string(),
            description: "Read-only resource".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![
                IacAttribute {
                    api_name: "auto_id".to_string(),
                    canonical_name: "auto_id".to_string(),
                    description: "Auto-generated ID".to_string(),
                    iac_type: IacType::String,
                    required: false, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "created_at".to_string(),
                    canonical_name: "created_at".to_string(),
                    description: "Creation timestamp".to_string(),
                    iac_type: IacType::String,
                    required: false, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "auto_id".to_string(),
                import_field: "auto_id".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("'state':"), "state param should still exist");
        assert!(!output.contains("'auto_id':"), "computed-only should not be in argument_spec");
        assert!(!output.contains("'created_at':"), "computed-only should not be in argument_spec");

        let return_section = &output[output.find("RETURN").unwrap()..];
        assert!(return_section.contains("auto_id:"), "computed field should be in RETURN");
        assert!(return_section.contains("created_at:"), "computed field should be in RETURN");
    }

    #[test]
    fn resource_module_check_mode_support() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(
            output.contains("supports_check_mode=True"),
            "generated module should support check_mode"
        );
        assert!(
            output.contains("module.check_mode"),
            "generated module should handle check_mode"
        );
    }

    #[test]
    fn resource_module_state_choices() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(
            output.contains("'state': {'type': 'str', 'choices': ['present', 'absent'], 'default': 'present'}"),
            "state param should have correct choices and default"
        );
    }

    #[test]
    fn data_source_with_enum_attribute() {
        let ds = IacDataSource {
            name: "test_enum_ds".to_string(),
            description: "Data source with enum".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "Read".to_string(),
            read_response_schema: None,
            attributes: vec![IacAttribute {
                api_name: "category".to_string(),
                canonical_name: "category".to_string(),
                description: "Category".to_string(),
                iac_type: IacType::Enum {
                    values: vec!["web".to_string(), "api".to_string(), "worker".to_string()],
                    underlying: Box::new(IacType::String),
                },
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
        };

        let output = generate_data_source_module(&ds, "test");
        assert!(
            output.contains("'choices': ['web', 'api', 'worker']"),
            "data source enum should have choices in argument_spec"
        );
        let doc_section = &output[output.find("DOCUMENTATION").unwrap()..output.find("EXAMPLES").unwrap()];
        assert!(
            doc_section.contains("choices: [\"web\", \"api\", \"worker\"]"),
            "data source DOCUMENTATION should have enum choices"
        );
    }

    #[test]
    fn data_source_with_no_attributes() {
        let ds = IacDataSource {
            name: "test_bare".to_string(),
            description: "Bare data source".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "Read".to_string(),
            read_response_schema: None,
            attributes: vec![],
        };

        let output = generate_data_source_module(&ds, "test");
        assert!(output.contains("module: bare_info"));
        assert!(output.contains("argument_spec = {"));
        let return_section = &output[output.find("RETURN").unwrap()..];
        assert!(return_section.contains("# No computed fields"));
    }

    #[test]
    fn data_source_description_with_quotes() {
        let ds = IacDataSource {
            name: "test_quoted_ds".to_string(),
            description: "A \"special\" data source".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "Read".to_string(),
            read_response_schema: None,
            attributes: vec![],
        };

        let output = generate_data_source_module(&ds, "test");
        assert!(
            output.contains("A 'special' data source"),
            "data source description should escape double quotes to single quotes"
        );
    }

    #[test]
    fn resource_module_contains_python_shebang_and_copyright() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.starts_with("#!/usr/bin/python"));
        assert!(output.contains("# -*- coding: utf-8 -*-"));
        assert!(output.contains("Copyright"));
        assert!(output.contains("from __future__ import absolute_import"));
    }

    #[test]
    fn data_source_module_contains_python_shebang_and_copyright() {
        let ds = IacDataSource {
            name: "test_ds".to_string(),
            description: "DS".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "Read".to_string(),
            read_response_schema: None,
            attributes: vec![],
        };
        let output = generate_data_source_module(&ds, "test");
        assert!(output.starts_with("#!/usr/bin/python"));
        assert!(output.contains("# -*- coding: utf-8 -*-"));
        assert!(output.contains("from __future__ import absolute_import"));
    }

    #[test]
    fn enum_with_boolean_underlying_maps_to_bool() {
        assert_eq!(
            iac_type_to_ansible(&IacType::Enum {
                values: vec!["true".into(), "false".into()],
                underlying: Box::new(IacType::Boolean),
            }),
            "bool"
        );
    }

    #[test]
    fn enum_with_float_underlying_maps_to_float() {
        assert_eq!(
            iac_type_to_ansible(&IacType::Enum {
                values: vec!["1.0".into()],
                underlying: Box::new(IacType::Float),
            }),
            "float"
        );
    }

    #[test]
    fn list_elements_type_returns_none_for_non_collection() {
        assert_eq!(list_elements_type(&IacType::Integer), None);
        assert_eq!(list_elements_type(&IacType::Boolean), None);
        assert_eq!(list_elements_type(&IacType::Float), None);
        assert_eq!(list_elements_type(&IacType::Map(Box::new(IacType::String))), None);
        assert_eq!(list_elements_type(&IacType::Any), None);
        assert_eq!(
            list_elements_type(&IacType::Object { name: "O".into(), fields: vec![] }),
            None
        );
        assert_eq!(
            list_elements_type(&IacType::Enum { values: vec![], underlying: Box::new(IacType::String) }),
            None
        );
    }

    #[test]
    fn test_playbook_sensitive_required_field_still_included() {
        let resource = IacResource {
            name: "test_sensitive_req".to_string(),
            description: "Sensitive required".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "api_key".to_string(),
                canonical_name: "api_key".to_string(),
                description: "API Key".to_string(),
                iac_type: IacType::String,
                required: true, computed: false, sensitive: true, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "api_key".to_string(),
                import_field: "api_key".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_test_playbook(&resource, "test");
        assert!(
            output.contains("api_key: \"test_value\""),
            "sensitive+required fields should still appear in test playbook"
        );
    }

    #[test]
    fn resource_module_return_section_types() {
        let resource = IacResource {
            name: "test_returns".to_string(),
            description: "Return types".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![
                IacAttribute {
                    api_name: "count".to_string(),
                    canonical_name: "count".to_string(),
                    description: "Count".to_string(),
                    iac_type: IacType::Integer,
                    required: false, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "active".to_string(),
                    canonical_name: "active".to_string(),
                    description: "Active".to_string(),
                    iac_type: IacType::Boolean,
                    required: false, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "tags".to_string(),
                    canonical_name: "tags".to_string(),
                    description: "Tags".to_string(),
                    iac_type: IacType::List(Box::new(IacType::String)),
                    required: false, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "count".to_string(),
                import_field: "count".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_resource_module(&resource, "test");
        let return_section = &output[output.find("RETURN").unwrap()..];
        assert!(return_section.contains("count:\n  description:"));
        assert!(return_section.contains("type: int"));
        assert!(return_section.contains("type: bool"));
        assert!(return_section.contains("type: list"));
        assert!(return_section.contains("returned: success"));
    }

    #[test]
    fn resource_module_options_exclude_computed_optional() {
        let resource = IacResource {
            name: "test_opts".to_string(),
            description: "Options test".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![
                IacAttribute {
                    api_name: "input".to_string(),
                    canonical_name: "input".to_string(),
                    description: "User input".to_string(),
                    iac_type: IacType::String,
                    required: true, computed: false, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "server_set".to_string(),
                    canonical_name: "server_set".to_string(),
                    description: "Server set".to_string(),
                    iac_type: IacType::String,
                    required: false, computed: true, sensitive: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "server_set".to_string(),
                import_field: "input".to_string(),
                force_replace_fields: vec![],
            },
        };

        let output = generate_resource_module(&resource, "test");
        let doc_section = &output[output.find("DOCUMENTATION").unwrap()..output.find("EXAMPLES").unwrap()];
        assert!(doc_section.contains("input:"), "required non-computed field should be in DOCUMENTATION options");
        assert!(!doc_section.contains("server_set:"), "computed optional field should NOT be in DOCUMENTATION options");
    }

    #[test]
    fn build_options_yaml_includes_required_excludes_computed() {
        let attrs = vec![
            IacAttribute {
                api_name: "name".to_string(),
                canonical_name: "name".to_string(),
                description: "A name".to_string(),
                iac_type: IacType::String,
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "auto_id".to_string(),
                canonical_name: "auto_id".to_string(),
                description: "Generated ID".to_string(),
                iac_type: IacType::String,
                required: false, computed: true, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
        ];
        let yaml = build_options_yaml(&attrs);
        assert!(yaml.contains("name:"), "required field should appear in options");
        assert!(yaml.contains("required: true"));
        assert!(!yaml.contains("auto_id:"), "computed-only field should be excluded from options");
    }

    #[test]
    fn build_options_yaml_sensitive_field_has_no_log() {
        let attrs = vec![IacAttribute {
            api_name: "secret".to_string(),
            canonical_name: "secret".to_string(),
            description: "A secret".to_string(),
            iac_type: IacType::String,
            required: true, computed: false, sensitive: true, immutable: false,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        }];
        let yaml = build_options_yaml(&attrs);
        assert!(yaml.contains("no_log: true"));
    }

    #[test]
    fn build_options_yaml_list_includes_elements() {
        let attrs = vec![IacAttribute {
            api_name: "items".to_string(),
            canonical_name: "items".to_string(),
            description: "Items list".to_string(),
            iac_type: IacType::List(Box::new(IacType::Integer)),
            required: false, computed: false, sensitive: false, immutable: false,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        }];
        let yaml = build_options_yaml(&attrs);
        assert!(yaml.contains("type: list"));
        assert!(yaml.contains("elements: int"));
    }

    #[test]
    fn build_options_yaml_empty_attrs() {
        let yaml = build_options_yaml(&[]);
        assert!(yaml.is_empty());
    }

    #[test]
    fn build_return_yaml_includes_computed_fields() {
        let attrs = vec![
            IacAttribute {
                api_name: "id".to_string(),
                canonical_name: "id".to_string(),
                description: "The ID".to_string(),
                iac_type: IacType::String,
                required: false, computed: true, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "name".to_string(),
                canonical_name: "name".to_string(),
                description: "The name".to_string(),
                iac_type: IacType::String,
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
        ];
        let yaml = build_return_yaml(&attrs);
        assert!(yaml.contains("id:"), "computed field should be in RETURN");
        assert!(yaml.contains("type: str"));
        assert!(yaml.contains("returned: success"));
        assert!(!yaml.contains("name:"), "non-computed field should not be in RETURN");
    }

    #[test]
    fn build_return_yaml_empty_when_no_computed() {
        let attrs = vec![IacAttribute {
            api_name: "name".to_string(),
            canonical_name: "name".to_string(),
            description: "A name".to_string(),
            iac_type: IacType::String,
            required: true, computed: false, sensitive: false, immutable: false,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        }];
        let yaml = build_return_yaml(&attrs);
        assert!(yaml.contains("# No computed fields"));
    }

    #[test]
    fn build_return_yaml_escapes_double_quotes() {
        let attrs = vec![IacAttribute {
            api_name: "note".to_string(),
            canonical_name: "note".to_string(),
            description: "A \"special\" note".to_string(),
            iac_type: IacType::String,
            required: false, computed: true, sensitive: false, immutable: false,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        }];
        let yaml = build_return_yaml(&attrs);
        assert!(yaml.contains("A 'special' note"), "double quotes in description should be escaped");
    }

    #[test]
    fn build_argument_spec_types_and_flags() {
        let attrs = vec![
            IacAttribute {
                api_name: "host".to_string(),
                canonical_name: "host".to_string(),
                description: "Host".to_string(),
                iac_type: IacType::String,
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "port".to_string(),
                canonical_name: "port".to_string(),
                description: "Port".to_string(),
                iac_type: IacType::Integer,
                required: false, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "token".to_string(),
                canonical_name: "token".to_string(),
                description: "Token".to_string(),
                iac_type: IacType::String,
                required: true, computed: false, sensitive: true, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
        ];
        let spec = build_argument_spec(&attrs);
        assert!(spec.contains("'host': {'type': 'str', 'required': True}"));
        assert!(spec.contains("'port': {'type': 'int'}"));
        assert!(spec.contains("'token': {'type': 'str', 'required': True, 'no_log': True}"));
    }

    #[test]
    fn build_argument_spec_excludes_computed_optional() {
        let attrs = vec![IacAttribute {
            api_name: "gen_id".to_string(),
            canonical_name: "gen_id".to_string(),
            description: "Generated".to_string(),
            iac_type: IacType::String,
            required: false, computed: true, sensitive: false, immutable: false,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        }];
        let spec = build_argument_spec(&attrs);
        assert!(spec.is_empty(), "computed-only field should not appear in argument_spec");
    }

    #[test]
    fn build_argument_spec_enum_choices() {
        let attrs = vec![IacAttribute {
            api_name: "mode".to_string(),
            canonical_name: "mode".to_string(),
            description: "Mode".to_string(),
            iac_type: IacType::Enum {
                values: vec!["fast".into(), "slow".into()],
                underlying: Box::new(IacType::String),
            },
            required: false, computed: false, sensitive: false, immutable: false,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        }];
        let spec = build_argument_spec(&attrs);
        assert!(spec.contains("'choices': ['fast', 'slow']"));
    }

    #[test]
    fn build_argument_spec_empty_attrs() {
        let spec = build_argument_spec(&[]);
        assert!(spec.is_empty());
    }

    #[test]
    fn state_spec_entry_contains_present_absent() {
        let entry = state_spec_entry();
        assert!(entry.contains("'state'"));
        assert!(entry.contains("'present'"));
        assert!(entry.contains("'absent'"));
        assert!(entry.contains("'default': 'present'"));
    }

    #[test]
    fn immutable_field_names_collects_only_immutable() {
        let mut resource = sample_resource();
        resource.attributes = vec![
            IacAttribute {
                api_name: "region".to_string(),
                canonical_name: "region".to_string(),
                description: "Region".to_string(),
                iac_type: IacType::String,
                required: true, computed: false, sensitive: false, immutable: true,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "name".to_string(),
                canonical_name: "name".to_string(),
                description: "Name".to_string(),
                iac_type: IacType::String,
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
        ];
        let names = resource.immutable_attribute_names();
        assert_eq!(names, vec!["region"]);
    }

    #[test]
    fn immutable_field_names_empty_when_none_immutable() {
        let mut resource = sample_resource();
        resource.attributes = vec![IacAttribute {
            api_name: "name".to_string(),
            canonical_name: "name".to_string(),
            description: "Name".to_string(),
            iac_type: IacType::String,
            required: true, computed: false, sensitive: false, immutable: false,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        }];
        let names = resource.immutable_attribute_names();
        assert!(names.is_empty());
    }

    #[test]
    fn immutable_fields_comment_empty_when_no_immutable() {
        let mut resource = sample_resource();
        resource.attributes = vec![IacAttribute {
            api_name: "name".to_string(),
            canonical_name: "name".to_string(),
            description: "Name".to_string(),
            iac_type: IacType::String,
            required: true, computed: false, sensitive: false, immutable: false,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        }];
        let comment = immutable_fields_comment(&resource);
        assert!(comment.is_empty());
    }

    #[test]
    fn immutable_fields_comment_lists_fields() {
        let mut resource = sample_resource();
        resource.attributes = vec![
            IacAttribute {
                api_name: "region".to_string(),
                canonical_name: "region".to_string(),
                description: "Region".to_string(),
                iac_type: IacType::String,
                required: true, computed: false, sensitive: false, immutable: true,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "zone".to_string(),
                canonical_name: "zone".to_string(),
                description: "Zone".to_string(),
                iac_type: IacType::String,
                required: false, computed: false, sensitive: false, immutable: true,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
        ];
        let comment = immutable_fields_comment(&resource);
        assert!(comment.contains("immutable after creation"));
        assert!(comment.contains("- region"));
        assert!(comment.contains("- zone"));
        assert!(comment.contains("destroy + recreate"));
    }

    #[test]
    fn test_playbook_object_type_required_field() {
        let resource = IacResource {
            name: "test_config".to_string(),
            description: "Config resource".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None,
                update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "config".to_string(),
                canonical_name: "config".to_string(),
                description: "Configuration object".to_string(),
                iac_type: IacType::Object { name: "Config".into(), fields: vec![] },
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "config".to_string(),
                import_field: "config".to_string(),
                force_replace_fields: vec![],
            },
        };
        let output = generate_test_playbook(&resource, "test");
        assert!(output.contains("config: \"test_value\""));
    }

    #[test]
    fn data_source_list_elements_in_argument_spec() {
        let ds = IacDataSource {
            name: "test_items".to_string(),
            description: "Items data source".to_string(),
            read_endpoint: "/items".to_string(),
            read_schema: "ReadItems".to_string(),
            read_response_schema: None,
            attributes: vec![IacAttribute {
                api_name: "ids".to_string(),
                canonical_name: "ids".to_string(),
                description: "List of IDs".to_string(),
                iac_type: IacType::List(Box::new(IacType::Integer)),
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
        };
        let output = generate_data_source_module(&ds, "test");
        assert!(output.contains("'ids': {'type': 'list', 'required': True, 'elements': 'int'}"));
    }

    #[test]
    fn resource_module_crud_functions_present() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("def create_resource(module):"));
        assert!(output.contains("def update_resource(module):"));
        assert!(output.contains("def delete_resource(module):"));
        assert!(output.contains("def read_resource(module):"));
        assert!(output.contains("def main():"));
    }

    #[test]
    fn resource_module_state_dispatch_logic() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("state = module.params.get('state', 'present')"));
        assert!(output.contains("current = read_resource(module)"));
        assert!(output.contains("if state == 'absent':"));
        assert!(output.contains("create_resource(module)"));
        assert!(output.contains("update_resource(module)"));
        assert!(output.contains("delete_resource(module)"));
    }

    #[test]
    fn data_source_module_has_ansible_module_import() {
        let ds = IacDataSource {
            name: "test_ds".to_string(),
            description: "DS".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "Read".to_string(),
            read_response_schema: None,
            attributes: vec![],
        };
        let output = generate_data_source_module(&ds, "test");
        assert!(output.contains("from ansible.module_utils.basic import AnsibleModule"));
        assert!(output.contains("module = AnsibleModule("));
        assert!(output.contains("supports_check_mode=True"));
    }

    #[test]
    fn build_options_yaml_enum_values_on_non_enum_type() {
        let attrs = vec![IacAttribute {
            api_name: "tier".to_string(),
            canonical_name: "tier".to_string(),
            description: "Service tier".to_string(),
            iac_type: IacType::String,
            required: false, computed: false, sensitive: false, immutable: false,
            default_value: None,
            enum_values: Some(vec!["free".into(), "pro".into()]),
            read_path: None, update_only: false,
        }];
        let yaml = build_options_yaml(&attrs);
        assert!(yaml.contains("choices: [\"free\", \"pro\"]"));
    }

    #[test]
    fn build_argument_spec_enum_values_on_non_enum_type() {
        let attrs = vec![IacAttribute {
            api_name: "tier".to_string(),
            canonical_name: "tier".to_string(),
            description: "Service tier".to_string(),
            iac_type: IacType::String,
            required: false, computed: false, sensitive: false, immutable: false,
            default_value: None,
            enum_values: Some(vec!["free".into(), "pro".into()]),
            read_path: None, update_only: false,
        }];
        let spec = build_argument_spec(&attrs);
        assert!(spec.contains("'choices': ['free', 'pro']"));
    }

    #[test]
    fn build_options_yaml_enum_type_not_duplicated_with_enum_values() {
        let attrs = vec![IacAttribute {
            api_name: "level".to_string(),
            canonical_name: "level".to_string(),
            description: "Level".to_string(),
            iac_type: IacType::Enum {
                values: vec!["a".into(), "b".into()],
                underlying: Box::new(IacType::String),
            },
            required: false, computed: false, sensitive: false, immutable: false,
            default_value: None,
            enum_values: Some(vec!["a".into(), "b".into()]),
            read_path: None, update_only: false,
        }];
        let yaml = build_options_yaml(&attrs);
        let choices_count = yaml.matches("choices:").count();
        assert_eq!(choices_count, 1, "choices should appear only once even with both IacType::Enum and enum_values");
    }

    #[test]
    fn resource_module_examples_section() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        let examples = &output[output.find("EXAMPLES").unwrap()..output.find("RETURN").unwrap()];
        assert!(examples.contains("Create static_secret"));
        assert!(examples.contains("Delete static_secret"));
        assert!(examples.contains("state: present"));
        assert!(examples.contains("state: absent"));
    }

    #[test]
    fn data_source_examples_section() {
        let ds = IacDataSource {
            name: "test_items".to_string(),
            description: "Items".to_string(),
            read_endpoint: "/items".to_string(),
            read_schema: "Read".to_string(),
            read_response_schema: None,
            attributes: vec![],
        };
        let output = generate_data_source_module(&ds, "test");
        let examples = &output[output.find("EXAMPLES").unwrap()..output.find("RETURN").unwrap()];
        assert!(examples.contains("Get items_info"));
        assert!(examples.contains("register: result"));
    }

    #[test]
    fn test_playbook_any_type_required_field() {
        let resource = IacResource {
            name: "test_flexible".to_string(),
            description: "Flexible".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None, update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "data".to_string(),
                canonical_name: "data".to_string(),
                description: "Any data".to_string(),
                iac_type: IacType::Any,
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "data".to_string(),
                import_field: "data".to_string(),
                force_replace_fields: vec![],
            },
        };
        let output = generate_test_playbook(&resource, "test");
        assert!(output.contains("data: \"test_value\""));
    }

    #[test]
    fn test_playbook_set_type_required_field() {
        let resource = IacResource {
            name: "test_sets".to_string(),
            description: "Sets".to_string(),
            category: "test".to_string(),
            crud: CrudInfo {
                create_endpoint: "/create".to_string(),
                create_schema: "Create".to_string(),
                update_endpoint: None, update_schema: None,
                read_endpoint: "/read".to_string(),
                read_schema: "Read".to_string(),
                read_response_schema: None,
                delete_endpoint: "/delete".to_string(),
                delete_schema: "Delete".to_string(),
            },
            attributes: vec![IacAttribute {
                api_name: "labels".to_string(),
                canonical_name: "labels".to_string(),
                description: "Labels".to_string(),
                iac_type: IacType::Set(Box::new(IacType::String)),
                required: true, computed: false, sensitive: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "labels".to_string(),
                import_field: "labels".to_string(),
                force_replace_fields: vec![],
            },
        };
        let output = generate_test_playbook(&resource, "test");
        assert!(output.contains("labels: \"test_value\""));
    }
}
