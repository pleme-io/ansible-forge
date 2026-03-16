//! Python module generation for Ansible.
//!
//! Generates Ansible module Python files from platform-independent IR types.
//! Each generated module follows the standard Ansible module layout with
//! `DOCUMENTATION`, `EXAMPLES`, `RETURN` docstrings, and a `main()` function.

use iac_forge::{IacAttribute, IacDataSource, IacResource, IacType, strip_provider_prefix};

/// Map an `IacType` to the Ansible argument_spec type string.
///
/// For `Enum` types, the underlying type is checked: if the underlying type
/// is `Integer`, the Ansible type will be `'int'`, not `'str'`.
#[must_use]
pub fn iac_type_to_ansible(ty: &IacType) -> &'static str {
    match ty {
        IacType::String => "str",
        IacType::Integer => "int",
        IacType::Float => "float",
        IacType::Boolean => "bool",
        IacType::List(_) | IacType::Set(_) => "list",
        IacType::Map(_) | IacType::Object { .. } => "dict",
        IacType::Enum { underlying, .. } => iac_type_to_ansible(underlying),
        IacType::Any => "str",
    }
}

/// Get the `elements` type for list/set types, if applicable.
#[must_use]
pub fn list_elements_type(ty: &IacType) -> Option<&'static str> {
    match ty {
        IacType::List(inner) | IacType::Set(inner) => Some(iac_type_to_ansible(inner)),
        _ => None,
    }
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
        lines.push(format!("      type: {}", iac_type_to_ansible(&attr.iac_type)));
        if attr.required {
            lines.push("      required: true".to_string());
        }
        if attr.sensitive {
            lines.push("      no_log: true".to_string());
        }
        if let Some(elems) = list_elements_type(&attr.iac_type) {
            lines.push(format!("      elements: {elems}"));
        }
        if let IacType::Enum { values, .. } = &attr.iac_type {
            let choices: Vec<String> = values.iter().map(|v| format!("\"{v}\"")).collect();
            lines.push(format!("      choices: [{}]", choices.join(", ")));
        }
        if let Some(ref ev) = attr.enum_values {
            if !matches!(&attr.iac_type, IacType::Enum { .. }) {
                let choices: Vec<String> = ev.iter().map(|v| format!("\"{v}\"")).collect();
                lines.push(format!("      choices: [{}]", choices.join(", ")));
            }
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
        lines.push(format!("  type: {}", iac_type_to_ansible(&attr.iac_type)));
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
            iac_type_to_ansible(&attr.iac_type)
        ));
        if attr.required {
            parts.push("'required': True".to_string());
        }
        if attr.sensitive {
            parts.push("'no_log': True".to_string());
        }
        if let Some(elems) = list_elements_type(&attr.iac_type) {
            parts.push(format!("'elements': '{elems}'"));
        }
        if let IacType::Enum { values, .. } = &attr.iac_type {
            let choices: Vec<String> = values.iter().map(|v| format!("'{v}'")).collect();
            parts.push(format!("'choices': [{}]", choices.join(", ")));
        }
        if let Some(ref ev) = attr.enum_values {
            if !matches!(&attr.iac_type, IacType::Enum { .. }) {
                let choices: Vec<String> = ev.iter().map(|v| format!("'{v}'")).collect();
                parts.push(format!("'choices': [{}]", choices.join(", ")));
            }
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

/// Collect the names of immutable fields from attributes.
fn immutable_field_names(attrs: &[IacAttribute]) -> Vec<&str> {
    attrs
        .iter()
        .filter(|a| a.immutable)
        .map(|a| a.canonical_name.as_str())
        .collect()
}

/// Build a Python comment block listing immutable fields for `update_resource`.
fn immutable_fields_comment(attrs: &[IacAttribute]) -> String {
    let names = immutable_field_names(attrs);
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

/// Generate a complete Python module for a resource.
#[must_use]
pub fn generate_resource_module(resource: &IacResource, provider_name: &str) -> String {
    let module_name = strip_provider_prefix(&resource.name, provider_name);
    let options_yaml = build_options_yaml(&resource.attributes);
    let return_yaml = build_return_yaml(&resource.attributes);
    let argument_spec = build_argument_spec(&resource.attributes);
    let immutable_comment = immutable_fields_comment(&resource.attributes);

    format!(
        r##"#!/usr/bin/python
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
"##,
        module_name = module_name,
        description = resource.description.replace('"', "'"),
        options_yaml = options_yaml,
        return_yaml = return_yaml,
        state_spec = state_spec_entry(),
        argument_spec = argument_spec,
        immutable_comment = immutable_comment,
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
        r##"#!/usr/bin/python
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
"##,
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
                IacType::String => "\"test_value\"".to_string(),
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
        r#"---
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
"#,
        module_name = module_name,
        params_block = params_block,
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
}
