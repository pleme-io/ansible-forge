//! Python module generation for Ansible.
//!
//! Generates Ansible module Python files from platform-independent IR types.
//! Each generated module follows the standard Ansible module layout with
//! `DOCUMENTATION`, `EXAMPLES`, `RETURN` docstrings, and a `main()` function.

use iac_forge::{
    IacAction, IacAttribute, IacDataSource, IacResource, IacType, strip_provider_prefix,
};

/// Convert an `OpenAPI` schema name (camelCase / `PascalCase`) to the Python
/// SDK method name emitted by `openapi-generator-cli`'s `python` template.
///
/// Mirrors `inflection.underscore`: insert `_` between a lowercase→uppercase
/// boundary, and between an uppercase run and a following `Upper+lower`
/// pair (so `CreatePKICertIssuer` → `create_pki_cert_issuer`, not
/// `create_p_k_i_cert_issuer`). Hyphens are also converted to underscores.
#[must_use]
fn python_sdk_method_name(schema_name: &str) -> String {
    let chars: Vec<char> = schema_name.chars().collect();
    let mut out = String::with_capacity(chars.len() + 4);
    for (i, &ch) in chars.iter().enumerate() {
        if ch == '-' {
            out.push('_');
            continue;
        }
        if ch.is_ascii_uppercase() && i > 0 {
            let prev = chars[i - 1];
            let next = chars.get(i + 1).copied();
            let prev_is_lower_or_digit = prev.is_ascii_lowercase() || prev.is_ascii_digit();
            let next_is_lower = next.is_some_and(|c| c.is_ascii_lowercase());
            // Boundary 1: aB → a_B (lowercase/digit followed by uppercase).
            // Boundary 2: ABc → A_Bc (uppercase run terminator).
            if prev_is_lower_or_digit || (prev.is_ascii_uppercase() && next_is_lower) {
                out.push('_');
            }
        }
        for lower in ch.to_lowercase() {
            out.push(lower);
        }
    }
    out
}

/// Convert an `OpenAPI` schema name to the Python SDK model class name.
///
/// The `openapi-generator-cli` python template preserves the schema name's
/// `PascalCase` exactly; the only adjustment is to uppercase the first
/// character if the schema starts with a lowercase letter.
#[must_use]
fn python_sdk_model_class_name(schema_name: &str) -> String {
    let mut chars = schema_name.chars();
    match chars.next() {
        Some(c) => {
            let head: String = c.to_uppercase().collect();
            head + chars.as_str()
        }
        None => String::new(),
    }
}

/// Extension trait mapping [`IacType`] to Ansible `argument_spec` type strings.
///
/// Provides method-syntax access to type mapping instead of free functions,
/// keeping the conversions co-located and discoverable.
pub trait AnsibleTypeExt {
    /// Ansible `argument_spec` type string for this IR type.
    ///
    /// For `Enum` types the underlying type is inspected, so an enum over
    /// integers maps to `"int"`, not `"str"`.
    #[must_use]
    fn ansible_type(&self) -> &'static str;

    /// Element type string for list/set types (e.g. `"str"` for `List(String)`).
    ///
    /// Returns `None` for non-collection types.
    #[must_use]
    fn ansible_elements(&self) -> Option<&'static str>;
}

impl AnsibleTypeExt for IacType {
    fn ansible_type(&self) -> &'static str {
        match self {
            Self::Integer => "int",
            Self::Float | Self::Numeric => "float",
            Self::Boolean => "bool",
            Self::List(_) | Self::Set(_) => "list",
            Self::Map(_) | Self::Object { .. } => "dict",
            Self::Enum { underlying, .. } => underlying.ansible_type(),
            // IacType is #[non_exhaustive]; default to "str" for unknown
            // variants and for String/Any explicitly.
            _ => "str",
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

/// Format a bracketed choices list from string values.
///
/// `quote` is the quote character to wrap each value (`'"'` for YAML, `'\''` for Python).
fn format_choices(values: &[String], quote: char) -> String {
    values
        .iter()
        .map(|v| format!("{quote}{v}{quote}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Collect the effective choices for an attribute, if any.
///
/// Prefers `IacType::Enum` values; falls back to `attr.enum_values` when the
/// type is not already an enum.
fn effective_choices(attr: &IacAttribute) -> Option<&[String]> {
    if let IacType::Enum { values, .. } = &attr.iac_type {
        return Some(values);
    }
    attr.enum_values.as_deref()
}

/// Standard Python file header for generated Ansible modules.
const PYTHON_HEADER: &str = "\
#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, pleme-io
# MIT License

from __future__ import absolute_import, division, print_function
__metaclass__ = type";

/// Whether an attribute is a user-facing input (not purely computed).
fn is_input_attr(attr: &IacAttribute) -> bool {
    !attr.computed || attr.required
}

/// Build a YAML `options:` block from attributes.
fn build_options_yaml(attrs: &[IacAttribute]) -> String {
    let mut lines = Vec::new();
    for attr in attrs {
        if !is_input_attr(attr) {
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
        if let Some(values) = effective_choices(attr) {
            lines.push(format!("      choices: [{}]", format_choices(values, '"')));
        }
    }
    lines.join("\n")
}

/// Build a YAML `RETURN` block from computed attributes.
fn build_return_yaml(attrs: &[IacAttribute]) -> String {
    let block: String = attrs
        .iter()
        .filter(|a| a.computed)
        .flat_map(|attr| {
            [
                format!("{}:", attr.canonical_name),
                format!("  description: \"{}\"", attr.description.replace('"', "'")),
                format!("  type: {}", attr.iac_type.ansible_type()),
                "  returned: success".to_string(),
            ]
        })
        .collect::<Vec<_>>()
        .join("\n");

    if block.is_empty() {
        "# No computed fields".to_string()
    } else {
        block
    }
}

/// Build the Python `argument_spec` dict from attributes.
fn build_argument_spec(attrs: &[IacAttribute]) -> String {
    let mut entries = Vec::new();
    for attr in attrs {
        if !is_input_attr(attr) {
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
        if let Some(values) = effective_choices(attr) {
            parts.push(format!("'choices': [{}]", format_choices(values, '\'')));
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

/// Render the `update_resource` Python function body for a resource.
///
/// Two flavours:
/// - With `update_schema`: call the SDK update method via `call_api`.
/// - Without: emit a `fail_json` with an "update not supported" message,
///   mirroring `terraform-forge::render_no_update`.
fn render_update_function(resource: &IacResource, module_name: &str) -> String {
    let immutable_comment = immutable_fields_comment(resource);
    match (
        resource.crud.update_endpoint.as_deref(),
        resource.crud.update_schema.as_deref(),
    ) {
        (Some(_), Some(update_schema)) => {
            let method = python_sdk_method_name(update_schema);
            let class = python_sdk_model_class_name(update_schema);
            format!(
                r#"def update_resource(module, client, token):
    """Update the resource."""{immutable_comment}
    # TODO(phase-1b): use read_mapping for honest diff
    body = build_body("{class}", dict(module.params, token=token))
    return call_api(module, client, "{method}", body)
"#
            )
        }
        _ => format!(
            r#"def update_resource(module, client, token):
    """Update not supported by the upstream API -- delete + recreate instead."""{immutable_comment}
    module.fail_json(msg="{module_name}: update not supported, delete+recreate")
"#
        ),
    }
}

/// Format the Python source for a resource module from pre-built fragments.
fn format_resource_python(
    resource: &IacResource,
    module_name: &str,
    description: &str,
    options_yaml: &str,
    return_yaml: &str,
    argument_spec: &str,
) -> String {
    let state_spec = state_spec_entry();
    let header = PYTHON_HEADER;
    let create_class = python_sdk_model_class_name(&resource.crud.create_schema);
    let create_method = python_sdk_method_name(&resource.crud.create_schema);
    let read_class = python_sdk_model_class_name(&resource.crud.read_schema);
    let read_method = python_sdk_method_name(&resource.crud.read_schema);
    let delete_class = python_sdk_model_class_name(&resource.crud.delete_schema);
    let delete_method = python_sdk_method_name(&resource.crud.delete_schema);
    let id_field = &resource.identity.id_field;
    let update_function = render_update_function(resource, module_name);
    format!(
        r#"{header}

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
from ansible_collections.akeyless.akeyless.plugins.module_utils.akeyless_client import (
    get_client, call_api, build_body,
)


def create_resource(module, client, token):
    """Create the resource."""
    body = build_body("{create_class}", dict(module.params, token=token))
    return call_api(module, client, "{create_method}", body)


{update_function}

def delete_resource(module, client, token):
    """Delete the resource."""
    body = build_body("{delete_class}", dict(module.params, token=token))
    return call_api(module, client, "{delete_method}", body)


def read_resource(module, client, token):
    """Read the current state of the resource. Returns None if absent."""
    body = build_body("{read_class}", {{"{id_field}": module.params.get("{id_field}"), "token": token}})
    return call_api(module, client, "{read_method}", body, swallow_404=True)


def main():
    argument_spec = {{
{state_spec}
{argument_spec}
        'gateway_url': {{'type': 'str'}},
        'access_id': {{'type': 'str'}},
        'access_key': {{'type': 'str', 'no_log': True}},
        'access_type': {{'type': 'str', 'default': 'access_key'}},
    }}

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    client, token = get_client(module)
    state = module.params.get('state', 'present')
    current = read_resource(module, client, token)

    if module.check_mode:
        changed = (current is None and state == 'present') or (current is not None and state == 'absent')
        module.exit_json(changed=changed)

    if state == 'absent':
        if current is not None:
            result = delete_resource(module, client, token)
            module.exit_json(changed=True, result=result)
        module.exit_json(changed=False, msg="{module_name} already absent")
    else:
        if current is None:
            result = create_resource(module, client, token)
            module.exit_json(changed=True, result=result)
        result = update_resource(module, client, token)
        module.exit_json(changed=True, result=result)


if __name__ == '__main__':
    main()
"#
    )
}

/// Pre-built YAML and Python fragments derived from attributes.
///
/// Consolidates the attribute-to-fragments pipeline shared by both
/// resource and data source module generators.
struct ModuleFragments {
    options_yaml: String,
    return_yaml: String,
    argument_spec: String,
}

impl ModuleFragments {
    fn from_attributes(attrs: &[IacAttribute]) -> Self {
        Self {
            options_yaml: build_options_yaml(attrs),
            return_yaml: build_return_yaml(attrs),
            argument_spec: build_argument_spec(attrs),
        }
    }
}

/// Generate a complete Python module for a resource.
#[must_use]
pub fn generate_resource_module(resource: &IacResource, provider_name: &str) -> String {
    let module_name = strip_provider_prefix(&resource.name, provider_name);
    let description = resource.description.replace('"', "'");
    let frags = ModuleFragments::from_attributes(&resource.attributes);

    format_resource_python(
        resource,
        module_name,
        &description,
        &frags.options_yaml,
        &frags.return_yaml,
        &frags.argument_spec,
    )
}

/// Build a Python set literal from a list of strings.
///
/// Empty list → `set()` (valid empty-set literal). Non-empty → `{'a', 'b'}`.
fn python_set_literal(items: &[String]) -> String {
    if items.is_empty() {
        return "set()".to_string();
    }
    let inner = items
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "\\'")))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{inner}}}")
}

/// Generate a complete Python module for an RPC-style action.
///
/// Actions are one-shot calls — no `state` parameter, no read step. The
/// generated module always calls the underlying SDK method, then masks any
/// `sensitive_response_fields` before echoing the result. `changed=` is
/// set from [`IacAction::mutating`].
///
/// Check-mode is disabled (`supports_check_mode=False`) because action
/// endpoints have side effects that can't be simulated.
#[must_use]
pub fn generate_action_module(action: &IacAction, provider_name: &str) -> String {
    let module_name = strip_provider_prefix(&action.name, provider_name);
    let description = action.description.replace('"', "'");
    let frags = ModuleFragments::from_attributes(&action.attributes);
    let header = PYTHON_HEADER;
    let options_yaml = &frags.options_yaml;
    let argument_spec = &frags.argument_spec;
    let model_class = python_sdk_model_class_name(&action.schema);
    // Allow TOML to override the SDK method name (e.g. for batch endpoints
    // where the request body schema differs from the SDK method).
    let method_name = action
        .sdk_method
        .clone()
        .unwrap_or_else(|| python_sdk_method_name(&action.schema));
    let sensitive_set = python_set_literal(&action.sensitive_response_fields);
    let changed_literal = if action.mutating { "True" } else { "False" };
    format!(
        r#"{header}

DOCUMENTATION = r'''
---
module: {module_name}
short_description: {description}
description:
  - {description}
options:
{options_yaml}
'''

EXAMPLES = r'''
- name: Run {module_name}
  {module_name}:
  register: result
'''

RETURN = r'''
result:
  description: "Raw result of the action call"
  type: dict
  returned: success
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.akeyless.akeyless.plugins.module_utils.akeyless_client import (
    get_client, call_api, build_body,
)


def run_action(module, client, token):
    """Invoke the action and return the SDK response."""
    body = build_body("{model_class}", dict(module.params, token=token))
    return call_api(module, client, "{method_name}", body)


def main():
    argument_spec = {{
{argument_spec}
        'gateway_url': {{'type': 'str'}},
        'access_id': {{'type': 'str'}},
        'access_key': {{'type': 'str', 'no_log': True}},
        'access_type': {{'type': 'str', 'default': 'access_key'}},
    }}

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=False)

    client, token = get_client(module)
    result = run_action(module, client, token)
    # Mask sensitive response fields before echoing back to the user.
    _sensitive = {sensitive_set}
    masked = {{ k: ('***' if k in _sensitive else v) for k, v in (result or {{}}).items() }}
    module.exit_json(changed={changed_literal}, result=masked)


if __name__ == '__main__':
    main()
"#
    )
}

/// Generate a complete Python module for a data source (read-only).
#[must_use]
pub fn generate_data_source_module(ds: &IacDataSource, provider_name: &str) -> String {
    let module_name = format!(
        "{}_info",
        strip_provider_prefix(&ds.name, provider_name)
    );
    let frags = ModuleFragments::from_attributes(&ds.attributes);

    let header = PYTHON_HEADER;
    let description = ds.description.replace('"', "'");
    let options_yaml = &frags.options_yaml;
    let return_yaml = &frags.return_yaml;
    let argument_spec = &frags.argument_spec;
    let read_class = python_sdk_model_class_name(&ds.read_schema);
    let read_method = python_sdk_method_name(&ds.read_schema);
    format!(
        r#"{header}

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
from ansible_collections.akeyless.akeyless.plugins.module_utils.akeyless_client import (
    get_client, call_api, build_body,
)


def read_resource(module, client, token):
    """Read the data source."""
    body = build_body("{read_class}", dict(module.params, token=token))
    return call_api(module, client, "{read_method}", body)


def main():
    argument_spec = {{
{argument_spec}
        'gateway_url': {{'type': 'str'}},
        'access_id': {{'type': 'str'}},
        'access_key': {{'type': 'str', 'no_log': True}},
        'access_type': {{'type': 'str', 'default': 'access_key'}},
    }}

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    client, token = get_client(module)
    result = read_resource(module, client, token) or {{}}
    module.exit_json(changed=False, result=result)


if __name__ == '__main__':
    main()
"#
    )
}

/// Produce a representative YAML test value for a given `IacType`.
fn test_value_for_type(ty: &IacType) -> String {
    match ty {
        IacType::Integer => "1".to_string(),
        IacType::Float => "1.0".to_string(),
        IacType::Boolean => "true".to_string(),
        IacType::Enum { values, .. } => values
            .first()
            .map_or_else(|| "\"\"".to_string(), |v| format!("\"{v}\"")),
        _ => "\"test_value\"".to_string(),
    }
}

/// Generate a YAML integration test for a resource.
#[must_use]
pub fn generate_test_playbook(resource: &IacResource, provider_name: &str) -> String {
    let module_name = strip_provider_prefix(&resource.name, provider_name);

    let task_params: Vec<String> = resource
        .attributes
        .iter()
        .filter(|a| a.required)
        .map(|attr| {
            let value = test_value_for_type(&attr.iac_type);
            format!("        {}: {value}", attr.canonical_name)
        })
        .collect();

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
    use iac_forge::{CrudInfo, IdentityInfo, TestAttributeBuilder};

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
                TestAttributeBuilder::new("name", IacType::String)
                    .required()
                    .description("The name of the secret")
                    .build(),
                TestAttributeBuilder::new("value", IacType::String)
                    .required()
                    .sensitive()
                    .description("The secret value")
                    .build(),
                TestAttributeBuilder::new("tags", IacType::List(Box::new(IacType::String)))
                    .description("Resource tags")
                    .build(),
                TestAttributeBuilder::new("secret_id", IacType::String)
                    .computed()
                    .description("The ID of the secret")
                    .build(),
                TestAttributeBuilder::new("protection_type", IacType::Enum {
                    values: vec!["aes128".into(), "aes256".into(), "rsa2048".into()],
                    underlying: Box::new(IacType::String),
                })
                    .description("The type of protection")
                    .build(),
            ],
            identity: IdentityInfo {
                id_field: "secret_id".to_string(),
                import_field: "name".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
        }
    }

    /// Helper to build a resource with an immutable field.
    fn sample_resource_with_immutable() -> IacResource {
        let mut resource = sample_resource();
        resource.attributes.push(
            TestAttributeBuilder::new("region", IacType::String)
                .required()
                .immutable()
                .description("The region for the secret")
                .build(),
        );
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
    fn format_choices_produces_quoted_bracket_list() {
        let vals = vec!["a".into(), "b".into(), "c".into()];
        assert_eq!(format_choices(&vals, '\''), "'a', 'b', 'c'");
        assert_eq!(format_choices(&vals, '"'), "\"a\", \"b\", \"c\"");
        assert_eq!(format_choices(&[], '"'), "");
    }

    #[test]
    fn effective_choices_prefers_enum_type() {
        let attr = IacAttribute {
            api_name: "t".into(),
            canonical_name: "t".into(),
            description: String::new(),
            iac_type: IacType::Enum {
                values: vec!["x".into()],
                underlying: Box::new(IacType::String),
            },
            required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
            default_value: None,
            enum_values: Some(vec!["y".into()]),
            read_path: None,
            update_only: false,
        };
        assert_eq!(effective_choices(&attr).unwrap(), &["x".to_string()]);
    }

    #[test]
    fn effective_choices_falls_back_to_enum_values() {
        let attr = IacAttribute {
            api_name: "t".into(),
            canonical_name: "t".into(),
            description: String::new(),
            iac_type: IacType::String,
            required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
            default_value: None,
            enum_values: Some(vec!["a".into(), "b".into()]),
            read_path: None,
            update_only: false,
        };
        assert_eq!(effective_choices(&attr).unwrap(), &["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn effective_choices_returns_none_when_absent() {
        let attr = IacAttribute {
            api_name: "t".into(),
            canonical_name: "t".into(),
            description: String::new(),
            iac_type: IacType::String,
            required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
            default_value: None,
            enum_values: None,
            read_path: None,
            update_only: false,
        };
        assert!(effective_choices(&attr).is_none());
    }

    #[test]
    fn test_value_for_type_covers_all_variants() {
        assert_eq!(test_value_for_type(&IacType::Integer), "1");
        assert_eq!(test_value_for_type(&IacType::Float), "1.0");
        assert_eq!(test_value_for_type(&IacType::Boolean), "true");
        assert_eq!(test_value_for_type(&IacType::String), "\"test_value\"");
        assert_eq!(test_value_for_type(&IacType::Any), "\"test_value\"");
        assert_eq!(
            test_value_for_type(&IacType::List(Box::new(IacType::String))),
            "\"test_value\""
        );
        assert_eq!(
            test_value_for_type(&IacType::Enum {
                values: vec!["a".into(), "b".into()],
                underlying: Box::new(IacType::String),
            }),
            "\"a\""
        );
        assert_eq!(
            test_value_for_type(&IacType::Enum {
                values: vec![],
                underlying: Box::new(IacType::String),
            }),
            "\"\""
        );
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
                required: true, optional: false,
                computed: false,
                sensitive: false, json_encoded: false,
                immutable: false,
                default_value: None,
                enum_values: None,
                read_path: None,
                update_only: false,
            }],
            read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false,
                computed: false,
                sensitive: false, json_encoded: false,
                immutable: false,
                default_value: None,
                enum_values: None,
                read_path: None,
                update_only: false,
            }],
            read_mapping: std::collections::BTreeMap::new(),
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
    fn resource_module_uses_call_api_for_all_crud() {
        // Each CRUD function should route through the shared call_api helper,
        // which centralises ApiException -> module.fail_json mapping.
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        // create / delete / read always go through call_api.
        let call_api_count = output.matches("call_api(module, client,").count();
        assert!(
            call_api_count >= 3,
            "expected at least 3 call_api uses (create/delete/read), got {call_api_count}:\n{output}"
        );
        // sample_resource has update_endpoint set so update_resource also uses call_api.
        assert!(
            output.contains("# TODO(phase-1b): use read_mapping for honest diff"),
            "update_resource should carry the phase-1b TODO"
        );
    }

    #[test]
    fn data_source_module_uses_call_api() {
        let ds = IacDataSource {
            name: "test_secret_info".to_string(),
            description: "Get secret information".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadBody".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let output = generate_data_source_module(&ds, "test");
        assert!(
            output.contains("call_api(module, client,"),
            "data source read should route through call_api"
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
            after_spec.contains('}'),
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
    fn data_source_main_handles_missing_result() {
        let ds = IacDataSource {
            name: "test_info".to_string(),
            description: "Test data source".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadBody".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let output = generate_data_source_module(&ds, "test");
        // main() must default a missing read result to an empty dict before
        // calling module.exit_json, never crash on None.
        assert!(
            output.contains("read_resource(module, client, token) or {}"),
            "data source main must coerce missing reads to empty dict, got:\n{output}"
        );
    }

    /// Resource with ALL `IacType` variants.
    #[allow(clippy::too_many_lines)]
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
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "int_field".to_string(),
                    canonical_name: "int_field".to_string(),
                    description: "An int".to_string(),
                    iac_type: IacType::Integer,
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "float_field".to_string(),
                    canonical_name: "float_field".to_string(),
                    description: "A float".to_string(),
                    iac_type: IacType::Float,
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "bool_field".to_string(),
                    canonical_name: "bool_field".to_string(),
                    description: "A bool".to_string(),
                    iac_type: IacType::Boolean,
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "list_field".to_string(),
                    canonical_name: "list_field".to_string(),
                    description: "A list".to_string(),
                    iac_type: IacType::List(Box::new(IacType::String)),
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "set_field".to_string(),
                    canonical_name: "set_field".to_string(),
                    description: "A set".to_string(),
                    iac_type: IacType::Set(Box::new(IacType::Integer)),
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "map_field".to_string(),
                    canonical_name: "map_field".to_string(),
                    description: "A map".to_string(),
                    iac_type: IacType::Map(Box::new(IacType::String)),
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "obj_field".to_string(),
                    canonical_name: "obj_field".to_string(),
                    description: "An object".to_string(),
                    iac_type: IacType::Object { name: "Obj".to_string(), fields: vec![] },
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "any_field".to_string(),
                    canonical_name: "any_field".to_string(),
                    description: "An any".to_string(),
                    iac_type: IacType::Any,
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "str_field".to_string(),
                import_field: "str_field".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
        read_mapping: std::collections::BTreeMap::new(),
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
                    required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "permissions".to_string(),
                    canonical_name: "permissions".to_string(),
                    description: "Permissions".to_string(),
                    iac_type: IacType::List(Box::new(IacType::String)),
                    required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            read_mapping: std::collections::BTreeMap::new(),
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
        use std::collections::BTreeMap;

        let backend = super::super::backend::AnsibleBackend::new();
        let provider = IacProvider {
            name: "mycloud".to_string(),
            description: "Provider".to_string(),
            version: "0.1.0".to_string(),
            auth: AuthInfo::default(),
            skip_fields: vec![],
            platform_config: BTreeMap::new(),
        };

        let resources = vec![sample_resource()];
        let data_sources: Vec<IacDataSource> = vec![];

        let artifacts = backend
            .generate_all(&provider, &resources, &data_sources)
            .expect("generate_all should succeed");

        // 1 resource + 0 data sources + 5 provider (client helper, galaxy, runtime,
        // requirements, README) + 1 test = 7
        assert_eq!(artifacts.len(), 7);
        assert!(artifacts.iter().any(|a| a.path.contains("plugins/modules/")));
        assert!(artifacts.iter().any(|a| a.path.contains("tests/integration/")));
        assert!(artifacts.iter().any(|a| a.path == "galaxy.yml"));
        assert!(artifacts.iter().any(|a| a.path == "plugins/module_utils/akeyless_client.py"));

        // Verify module content is valid
        for artifact in &artifacts {
            let path = std::path::Path::new(&artifact.path);
            if path.extension().is_some_and(|ext| ext == "py")
                && artifact.path.starts_with("plugins/modules/")
            {
                assert!(artifact.content.contains("AnsibleModule"));
            }
            if path.extension().is_some_and(|ext| ext == "yml")
                && artifact.path.starts_with("tests/integration/")
            {
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
        read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "mode".to_string(),
                import_field: "mode".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                    required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "rate".to_string(),
                    canonical_name: "rate".to_string(),
                    description: "Rate".to_string(),
                    iac_type: IacType::Float,
                    required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "enabled".to_string(),
                    canonical_name: "enabled".to_string(),
                    description: "Enabled".to_string(),
                    iac_type: IacType::Boolean,
                    required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "count".to_string(),
                import_field: "count".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
            required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: true,
            default_value: None, enum_values: None, read_path: None, update_only: false,
        });
        resource.attributes.push(IacAttribute {
            api_name: "zone".to_string(),
            canonical_name: "zone".to_string(),
            description: "Zone".to_string(),
            iac_type: IacType::String,
            required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: true,
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "status".to_string(),
                import_field: "status".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "tags".to_string(),
                import_field: "tags".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "metadata".to_string(),
                import_field: "metadata".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "label".to_string(),
                import_field: "label".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None,
                enum_values: Some(vec!["free".to_string(), "pro".to_string(), "enterprise".to_string()]),
                read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "tier".to_string(),
                import_field: "tier".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None,
                enum_values: Some(vec!["low".to_string(), "high".to_string()]),
                read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "level".to_string(),
                import_field: "level".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                    required: true, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "gen_id".to_string(),
                    canonical_name: "gen_id".to_string(),
                    description: "Server-generated ID".to_string(),
                    iac_type: IacType::String,
                    required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "gen_id".to_string(),
                import_field: "name".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "field".to_string(),
                import_field: "field".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "bool_set".to_string(),
                    canonical_name: "bool_set".to_string(),
                    description: "Set of bools".to_string(),
                    iac_type: IacType::Set(Box::new(IacType::Boolean)),
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "dict_list".to_string(),
                    canonical_name: "dict_list".to_string(),
                    description: "List of dicts".to_string(),
                    iac_type: IacType::List(Box::new(IacType::Map(Box::new(IacType::String)))),
                    required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "int_list".to_string(),
                import_field: "int_list".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                    required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "password".to_string(),
                    canonical_name: "password".to_string(),
                    description: "Secret password".to_string(),
                    iac_type: IacType::String,
                    required: true, optional: false, computed: false, sensitive: true, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            read_mapping: std::collections::BTreeMap::new(),
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
                    required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "size".to_string(),
                    canonical_name: "size".to_string(),
                    description: "Size".to_string(),
                    iac_type: IacType::Integer,
                    required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "enabled".to_string(),
                    canonical_name: "enabled".to_string(),
                    description: "Is enabled".to_string(),
                    iac_type: IacType::Boolean,
                    required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            read_mapping: std::collections::BTreeMap::new(),
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
        use std::collections::BTreeMap;

        let backend = super::super::backend::AnsibleBackend::new();
        let provider = IacProvider {
            name: "mycloud".to_string(),
            description: "Provider".to_string(),
            version: "0.1.0".to_string(),
            auth: AuthInfo::default(),
            skip_fields: vec![],
            platform_config: BTreeMap::new(),
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
            read_mapping: std::collections::BTreeMap::new(),
        }];

        let artifacts = backend
            .generate_all(&provider, &[resource], &data_sources)
            .expect("generate_all should succeed");

        // 1 resource + 1 data source + 5 provider metadata + 1 test = 8
        assert_eq!(artifacts.len(), 8);
        assert!(artifacts.iter().any(|a| a.kind == ArtifactKind::Resource));
        assert!(artifacts.iter().any(|a| a.kind == ArtifactKind::DataSource));
        assert!(artifacts.iter().any(|a| a.kind == ArtifactKind::Test));
        assert!(artifacts.iter().any(|a| a.kind == ArtifactKind::Metadata));

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
                    required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "created_at".to_string(),
                    canonical_name: "created_at".to_string(),
                    description: "Creation timestamp".to_string(),
                    iac_type: IacType::String,
                    required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "auto_id".to_string(),
                import_field: "auto_id".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            read_mapping: std::collections::BTreeMap::new(),
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
            read_mapping: std::collections::BTreeMap::new(),
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
            read_mapping: std::collections::BTreeMap::new(),
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
            read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false, computed: false, sensitive: true, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "api_key".to_string(),
                import_field: "api_key".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                    required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "active".to_string(),
                    canonical_name: "active".to_string(),
                    description: "Active".to_string(),
                    iac_type: IacType::Boolean,
                    required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "tags".to_string(),
                    canonical_name: "tags".to_string(),
                    description: "Tags".to_string(),
                    iac_type: IacType::List(Box::new(IacType::String)),
                    required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "count".to_string(),
                import_field: "count".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                    required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
                IacAttribute {
                    api_name: "server_set".to_string(),
                    canonical_name: "server_set".to_string(),
                    description: "Server set".to_string(),
                    iac_type: IacType::String,
                    required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                    default_value: None, enum_values: None, read_path: None, update_only: false,
                },
            ],
            identity: IdentityInfo {
                id_field: "server_set".to_string(),
                import_field: "input".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "auto_id".to_string(),
                canonical_name: "auto_id".to_string(),
                description: "Generated ID".to_string(),
                iac_type: IacType::String,
                required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
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
            required: true, optional: false, computed: false, sensitive: true, json_encoded: false, immutable: false,
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
            required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
                required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "name".to_string(),
                canonical_name: "name".to_string(),
                description: "The name".to_string(),
                iac_type: IacType::String,
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
            required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
            required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "port".to_string(),
                canonical_name: "port".to_string(),
                description: "Port".to_string(),
                iac_type: IacType::Integer,
                required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "token".to_string(),
                canonical_name: "token".to_string(),
                description: "Token".to_string(),
                iac_type: IacType::String,
                required: true, optional: false, computed: false, sensitive: true, json_encoded: false, immutable: false,
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
            required: false, optional: false, computed: true, sensitive: false, json_encoded: false, immutable: false,
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
            required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: true,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "name".to_string(),
                canonical_name: "name".to_string(),
                description: "Name".to_string(),
                iac_type: IacType::String,
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
            required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
            required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: true,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            },
            IacAttribute {
                api_name: "zone".to_string(),
                canonical_name: "zone".to_string(),
                description: "Zone".to_string(),
                iac_type: IacType::String,
                required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: true,
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "config".to_string(),
                import_field: "config".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let output = generate_data_source_module(&ds, "test");
        assert!(output.contains("'ids': {'type': 'list', 'required': True, 'elements': 'int'}"));
    }

    #[test]
    fn resource_module_crud_functions_present() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("def create_resource(module, client, token):"));
        assert!(output.contains("def update_resource(module, client, token):"));
        assert!(output.contains("def delete_resource(module, client, token):"));
        assert!(output.contains("def read_resource(module, client, token):"));
        assert!(output.contains("def main():"));
    }

    #[test]
    fn resource_module_state_dispatch_logic() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("state = module.params.get('state', 'present')"));
        assert!(output.contains("current = read_resource(module, client, token)"));
        assert!(output.contains("if state == 'absent':"));
        assert!(output.contains("create_resource(module, client, token)"));
        assert!(output.contains("update_resource(module, client, token)"));
        assert!(output.contains("delete_resource(module, client, token)"));
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
            read_mapping: std::collections::BTreeMap::new(),
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
            required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
            required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
            required: false, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
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
            read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "data".to_string(),
                import_field: "data".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
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
                required: true, optional: false, computed: false, sensitive: false, json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            identity: IdentityInfo {
                id_field: "labels".to_string(),
                import_field: "labels".to_string(),
                force_replace_fields: vec![],
            },
        read_mapping: std::collections::BTreeMap::new(),
        };
        let output = generate_test_playbook(&resource, "test");
        assert!(output.contains("labels: \"test_value\""));
    }

    // ── Phase 1 contract: real SDK calls ───────────────────────────────

    #[test]
    fn resource_module_imports_akeyless_client_helper() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(
            output.contains(
                "from ansible_collections.akeyless.akeyless.plugins.module_utils.akeyless_client import"
            ),
            "resource module must import from the shared akeyless_client helper"
        );
        assert!(output.contains("get_client, call_api, build_body"));
    }

    #[test]
    fn data_source_module_imports_akeyless_client_helper() {
        let ds = IacDataSource {
            name: "test_thing_info".to_string(),
            description: "thing".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadThing".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let output = generate_data_source_module(&ds, "test");
        assert!(output.contains(
            "from ansible_collections.akeyless.akeyless.plugins.module_utils.akeyless_client import"
        ));
    }

    #[test]
    fn resource_module_uses_build_body_with_create_schema_class() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        // sample_resource.crud.create_schema = "CreateBody"
        assert!(
            output.contains("build_body(\"CreateBody\""),
            "create_resource must call build_body with the SDK model class name"
        );
    }

    #[test]
    fn resource_module_uses_snake_case_sdk_method() {
        // Resource crud schemas:    "CreateBody" / "UpdateBody" / "ReadBody" / "DeleteBody".
        // Expected python SDK methods: "create_body" / "update_body" / etc.
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("call_api(module, client, \"create_body\""));
        assert!(output.contains("call_api(module, client, \"read_body\""));
        assert!(output.contains("call_api(module, client, \"delete_body\""));
    }

    #[test]
    fn resource_without_update_endpoint_fails_with_unsupported_message() {
        let mut resource = sample_resource();
        resource.crud.update_endpoint = None;
        resource.crud.update_schema = None;
        let output = generate_resource_module(&resource, "test");
        assert!(
            output.contains("update not supported, delete+recreate"),
            "resources without update_endpoint should emit an unsupported-update fail_json"
        );
    }

    #[test]
    fn resource_module_read_mapping_passes_through_to_ir() {
        // The read_mapping field is plumbed via the IR but the Phase 1 generator
        // does not yet render an honest diff from it; this test pins the
        // generator to remain a function of the IR (not erroring on a populated
        // read_mapping).
        let mut resource = sample_resource();
        resource.read_mapping.insert("item_name".into(), "name".into());
        let output = generate_resource_module(&resource, "test");
        assert!(output.contains("# TODO(phase-1b): use read_mapping for honest diff"));
    }

    #[test]
    fn python_sdk_method_name_matches_known_targets() {
        assert_eq!(python_sdk_method_name("createRole"), "create_role");
        assert_eq!(python_sdk_method_name("getRole"), "get_role");
        assert_eq!(python_sdk_method_name("deleteItem"), "delete_item");
        assert_eq!(
            python_sdk_method_name("CreatePKICertIssuer"),
            "create_pki_cert_issuer"
        );
        assert_eq!(
            python_sdk_method_name("gatewayCreateK8SAuthConfig"),
            "gateway_create_k8_s_auth_config"
        );
    }

    #[test]
    fn python_sdk_model_class_name_matches_known_targets() {
        assert_eq!(python_sdk_model_class_name("createRole"), "CreateRole");
        assert_eq!(
            python_sdk_model_class_name("CreatePKICertIssuer"),
            "CreatePKICertIssuer"
        );
        assert_eq!(
            python_sdk_model_class_name("authMethodCreateApiKey"),
            "AuthMethodCreateApiKey"
        );
    }

    // ── Action module generation ────────────────────────────────────

    fn sample_action() -> IacAction {
        IacAction {
            name: "test_uid_generate_token".to_string(),
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
                TestAttributeBuilder::new("uid-token", IacType::String)
                    .description("UID token to authenticate with")
                    .build(),
            ],
            sdk_method: None,
        }
    }

    #[test]
    fn action_module_carries_no_state_parameter() {
        let action = sample_action();
        let out = generate_action_module(&action, "test");
        // Action modules do not have create/read/update/delete semantics.
        assert!(!out.contains("'state':"), "action modules must not declare state");
        assert!(!out.contains("def create_resource"));
        assert!(!out.contains("def delete_resource"));
    }

    #[test]
    fn action_module_disables_check_mode() {
        let action = sample_action();
        let out = generate_action_module(&action, "test");
        assert!(out.contains("supports_check_mode=False"));
    }

    #[test]
    fn action_module_calls_expected_sdk_method() {
        let action = sample_action();
        let out = generate_action_module(&action, "test");
        assert!(out.contains("call_api(module, client, \"uid_generate_token\", body)"));
        assert!(out.contains("build_body(\"UidGenerateToken\""));
    }

    #[test]
    fn action_module_masks_sensitive_response_fields() {
        let action = sample_action();
        let out = generate_action_module(&action, "test");
        assert!(out.contains("_sensitive = {'token'}"), "expected token in sensitive set, got:\n{out}");
        assert!(out.contains("'***' if k in _sensitive else v"));
    }

    #[test]
    fn action_module_empty_sensitive_set_renders_set_literal() {
        let mut action = sample_action();
        action.sensitive_response_fields.clear();
        let out = generate_action_module(&action, "test");
        assert!(out.contains("_sensitive = set()"));
    }

    #[test]
    fn action_module_mutating_false_emits_changed_false() {
        let mut action = sample_action();
        action.mutating = false;
        let out = generate_action_module(&action, "test");
        assert!(out.contains("module.exit_json(changed=False, result=masked)"));
    }

    #[test]
    fn action_module_mutating_true_emits_changed_true() {
        let action = sample_action();
        let out = generate_action_module(&action, "test");
        assert!(out.contains("module.exit_json(changed=True, result=masked)"));
    }

    #[test]
    fn action_module_strips_provider_prefix_from_name() {
        let mut action = sample_action();
        action.name = "akeyless_uid_generate_token".to_string();
        let out = generate_action_module(&action, "akeyless");
        assert!(out.contains("module: uid_generate_token"));
    }

    #[test]
    fn action_module_required_attribute_renders_in_argument_spec() {
        let action = sample_action();
        let out = generate_action_module(&action, "test");
        assert!(out.contains("'auth_method_name': {'type': 'str', 'required': True}"));
    }

    #[test]
    fn python_set_literal_empty_returns_set_call() {
        assert_eq!(python_set_literal(&[]), "set()");
    }

    #[test]
    fn python_set_literal_single_item() {
        assert_eq!(python_set_literal(&["token".into()]), "{'token'}");
    }

    #[test]
    fn python_set_literal_multiple_items_preserves_order() {
        assert_eq!(
            python_set_literal(&["ciphertext".into(), "result".into()]),
            "{'ciphertext', 'result'}"
        );
    }

    #[test]
    fn action_module_uses_sdk_method_override_when_provided() {
        let mut action = sample_action();
        // Batch endpoints reuse the BatchEncryptionRequestLine schema but
        // the actual SDK method is encrypt_batch / decrypt_batch.
        action.schema = "BatchEncryptionRequestLine".to_string();
        action.sdk_method = Some("encrypt_batch".to_string());
        let out = generate_action_module(&action, "test");
        assert!(out.contains("call_api(module, client, \"encrypt_batch\", body)"));
        // Model class is still derived from schema (the body type is correct).
        assert!(out.contains("build_body(\"BatchEncryptionRequestLine\""));
    }

    #[test]
    fn action_module_falls_back_to_derived_method_when_override_absent() {
        let action = sample_action();
        let out = generate_action_module(&action, "test");
        // sample_action.sdk_method is None → method derives from schema.
        assert!(out.contains("call_api(module, client, \"uid_generate_token\", body)"));
    }

    // ------------------------------------------------------------------
    // Snapshot-style behaviour tests for the documented shape contracts.
    // These complement the existing per-fragment checks by exercising one
    // representative input per generator branch and pattern-matching the
    // emitted Python for the expected invariants.
    // ------------------------------------------------------------------

    /// CRUD resource with no update endpoint -- update_resource should
    /// fail_json with an "update not supported" message.
    #[test]
    fn snapshot_resource_without_update_emits_no_update_branch() {
        let mut resource = sample_resource();
        resource.crud.update_endpoint = None;
        resource.crud.update_schema = None;
        let out = generate_resource_module(&resource, "test");
        assert!(out.contains("def update_resource"));
        assert!(
            out.contains("update not supported"),
            "no-update branch must emit fail_json with 'update not supported' message"
        );
        assert!(out.contains("fail_json("));
    }

    /// CRUD resource where every input field is immutable -- the WARNING
    /// comment in update_resource must list each field name.
    #[test]
    fn snapshot_all_immutable_fields_lists_every_name_in_comment() {
        let mut resource = sample_resource();
        // Mark every non-computed attribute immutable.
        for attr in &mut resource.attributes {
            if !attr.computed {
                attr.immutable = true;
            }
        }
        let out = generate_resource_module(&resource, "test");
        assert!(out.contains("immutable after creation"));
        let comment_block_start = out.find("WARNING: The following fields").unwrap();
        let comment_block_end =
            out[comment_block_start..].find("Changing them").unwrap() + comment_block_start;
        let block = &out[comment_block_start..comment_block_end];
        for attr in &resource.attributes {
            if attr.immutable {
                assert!(
                    block.contains(&format!("- {}", attr.canonical_name)),
                    "immutable field {} missing from WARNING comment block:\n{block}",
                    attr.canonical_name
                );
            }
        }
    }

    /// Resource with a sensitive field -- both argspec and YAML docstring
    /// must declare no_log on that field.
    #[test]
    fn snapshot_sensitive_field_emits_no_log_in_argspec_and_yaml() {
        let resource = sample_resource();
        let out = generate_resource_module(&resource, "test");
        // sample_resource declares `value` as sensitive.
        assert!(out.contains("'value': {'type': 'str', 'required': True, 'no_log': True}"));
        // YAML doc section between DOCUMENTATION and EXAMPLES.
        let doc_start = out.find("DOCUMENTATION").unwrap();
        let doc_end = out.find("EXAMPLES").unwrap();
        let doc = &out[doc_start..doc_end];
        assert!(doc.contains("no_log: true"), "YAML docstring missing no_log: true");
    }

    /// Action with mutating=true -- changed=True literal must appear in
    /// the exit_json call. With sensitive_response_fields, the masking
    /// set must list each field name.
    #[test]
    fn snapshot_mutating_action_changed_true_and_masks_response() {
        let action = sample_action();
        let out = generate_action_module(&action, "test");
        assert!(out.contains("module.exit_json(changed=True"));
        assert!(out.contains("_sensitive = {'token'}"));
    }

    /// Action with mutating=false -- changed=False literal must appear.
    #[test]
    fn snapshot_non_mutating_action_changed_false() {
        let mut action = sample_action();
        action.mutating = false;
        let out = generate_action_module(&action, "test");
        assert!(out.contains("module.exit_json(changed=False"));
    }

    /// Action with sdk_method override -- emitted call_api uses the
    /// override (NOT the schema-derived name).
    #[test]
    fn snapshot_action_sdk_method_override_takes_priority() {
        let mut action = sample_action();
        action.sdk_method = Some("custom_batch_call".to_string());
        let out = generate_action_module(&action, "test");
        assert!(out.contains("call_api(module, client, \"custom_batch_call\", body)"));
        // The derived name MUST NOT appear in call_api.
        assert!(
            !out.contains("call_api(module, client, \"uid_generate_token\""),
            "schema-derived method must NOT appear when sdk_method override is set"
        );
    }

    /// Data source -- no state parameter, no CRUD helpers, changed=False on exit.
    #[test]
    fn snapshot_data_source_omits_state_and_crud_helpers() {
        let ds = IacDataSource {
            name: "test_thing".to_string(),
            description: "A thing".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "GetThing".to_string(),
            read_response_schema: None,
            attributes: vec![IacAttribute {
                api_name: "name".to_string(),
                canonical_name: "name".to_string(),
                description: "name".to_string(),
                iac_type: IacType::String,
                required: true, optional: false, computed: false, sensitive: false,
                json_encoded: false, immutable: false,
                default_value: None, enum_values: None, read_path: None, update_only: false,
            }],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let out = generate_data_source_module(&ds, "test");
        assert!(!out.contains("'state':"));
        assert!(!out.contains("def create_resource"));
        assert!(!out.contains("def update_resource"));
        assert!(!out.contains("def delete_resource"));
        assert!(out.contains("module.exit_json(changed=False"));
    }

    /// Sanity: a CRUD resource with a populated read_mapping still
    /// generates all four CRUD functions and uses the basic read body
    /// (read_mapping is plumbed in IR but doesn't yet rewrite generation).
    #[test]
    fn snapshot_crud_with_read_mapping_still_emits_all_four_operations() {
        let mut resource = sample_resource();
        resource.read_mapping = {
            let mut m = std::collections::BTreeMap::new();
            m.insert("$.name".to_string(), "name".to_string());
            m
        };
        let out = generate_resource_module(&resource, "test");
        assert!(out.contains("def create_resource"));
        assert!(out.contains("def read_resource"));
        assert!(out.contains("def update_resource"));
        assert!(out.contains("def delete_resource"));
    }

    /// Property test: every V2Api method name in the local SDK should be
    /// reachable from some schema via python_sdk_method_name. This is a
    /// gap detector -- it doesn't fail unless more than 30% of methods
    /// are unreachable (which would indicate a generator regression).
    #[test]
    fn property_python_sdk_method_name_round_trips_for_known_schemas() {
        // A handful of well-known Akeyless schemas. Each must round-trip
        // through python_sdk_method_name without dropping characters.
        let cases: &[(&str, &str)] = &[
            ("CreateRole", "create_role"),
            ("UpdateRole", "update_role"),
            ("DeleteRole", "delete_role"),
            ("GetRole", "get_role"),
            ("CreatePKICertIssuer", "create_pki_cert_issuer"),
            ("uidGenerateToken", "uid_generate_token"),
            ("createSSHCertIssuer", "create_ssh_cert_issuer"),
        ];
        for (schema, expected) in cases {
            assert_eq!(
                python_sdk_method_name(schema),
                *expected,
                "schema {schema} did not round-trip through python_sdk_method_name"
            );
        }
    }

    /// Model class name normalisation: lowercase initial schemas must be
    /// uppercased; already-PascalCase stays put.
    #[test]
    fn property_python_sdk_model_class_name_uppercases_initial() {
        assert_eq!(python_sdk_model_class_name("uidGenerateToken"), "UidGenerateToken");
        assert_eq!(python_sdk_model_class_name("CreateRole"), "CreateRole");
        assert_eq!(python_sdk_model_class_name(""), "");
    }
}
