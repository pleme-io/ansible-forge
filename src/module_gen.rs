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
}
