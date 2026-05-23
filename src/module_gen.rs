//! Python module generation for Ansible.
//!
//! Generates Ansible module Python files from platform-independent IR types.
//! Each generated module follows the standard Ansible module layout with
//! `DOCUMENTATION`, `EXAMPLES`, `RETURN` docstrings, and a `main()` function.

use iac_forge::{
    IacAction, IacAttribute, IacDataSource, IacResource, IacType, strip_provider_prefix,
    to_snake_case,
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
///
/// Ansible modules in the official ecosystem are conventionally licensed
/// GPL-3.0-or-later regardless of the collection's overall license, since
/// they are loaded into the ansible-core process at runtime. Galaxy's own
/// validate-modules sanity check expects this header (it doesn't fail on
/// alternative wording but several downstream tooling pipelines do).
const PYTHON_HEADER: &str = "\
#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, pleme-io
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)

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

/// Build the Python `argument_spec` dict from attributes. Lines are
/// indented 4 spaces because the helper-collapsed shape declares
/// argument_spec at module scope, not inside `def main()`.
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
            "    '{}': {{{}}},",
            attr.canonical_name,
            parts.join(", ")
        ));
    }
    entries.join("\n")
}

/// Build a state parameter entry for resource modules (present/absent).
/// 4-space indent: argument_spec lives at module scope post-refactor.
fn state_spec_entry() -> &'static str {
    "    'state': {'type': 'str', 'choices': ['present', 'absent'], 'default': 'present'},"
}

/// Lines that every generated module's argspec includes (auth shim).
fn auth_argspec_lines() -> &'static str {
    "    'gateway_url': {'type': 'str'},
    'access_id': {'type': 'str'},
    'access_key': {'type': 'str', 'no_log': True},
    'access_type': {'type': 'str', 'default': 'access_key'},"
}

/// Compose the inside of the `argument_spec = { ... }` dict by joining
/// the (optional) state spec, attribute lines, and auth lines with
/// single newlines -- without leaving stray blank lines when any
/// section is empty (e.g. a data-source has no state, an info module
/// may have no per-attribute inputs).
fn compose_argspec_inner(state: Option<&str>, attrs: &str) -> String {
    let mut lines: Vec<&str> = Vec::with_capacity(3);
    if let Some(s) = state {
        lines.push(s);
    }
    if !attrs.is_empty() {
        lines.push(attrs);
    }
    lines.push(auth_argspec_lines());
    lines.join("\n")
}

/// Build a Python comment block listing immutable fields. The comment
/// is interpolated inside the `run_standard_crud(...)` kwargs list at
/// 8-space indent, so every line lives at column 8 to match its
/// surrounding `sdk_update=None,\n        immutable=True,`. Returns
/// empty when no fields are immutable.
fn immutable_fields_comment(resource: &IacResource) -> String {
    let names = resource.immutable_attribute_names();
    if names.is_empty() {
        return String::new();
    }
    let field_list = names
        .iter()
        .map(|n| format!("        #   - {n}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "        # WARNING: The following fields are immutable after creation.\n\
         {field_list}\n\
         \x20       # Changing them requires destroy + recreate."
    )
}

/// Render the `sdk_update=` kwarg for the `run_standard_crud` call. When
/// the upstream API has no update endpoint, we pass `sdk_update=None,
/// immutable=True` so the helper fails on drift with a clear "delete +
/// recreate" message instead of silently no-op'ing.
///
/// Returns the rendered Python kwargs as a multi-line string slice
/// destined for interpolation directly inside the `run_standard_crud(...)`
/// call body.
fn render_sdk_update_kwargs(resource: &IacResource) -> String {
    if let (Some(_), Some(update_schema)) = (
        resource.crud.update_endpoint.as_deref(),
        resource.crud.update_schema.as_deref(),
    ) {
        let method = python_sdk_method_name(update_schema);
        let class = python_sdk_model_class_name(update_schema);
        format!("        sdk_update=({class:?}, {method:?}),")
    } else {
        // No upstream update: helper treats drift as a hard error via
        // immutable=True. The `immutable_fields_comment` (if any) lists
        // which specific fields can't be changed in-place; surface it as
        // a leading comment so users grep'ing for "immutable" find it.
        let comment = immutable_fields_comment(resource);
        if comment.is_empty() {
            "        sdk_update=None,\n        immutable=True,".to_string()
        } else {
            format!("{comment}\n        sdk_update=None,\n        immutable=True,")
        }
    }
}

/// Format the Python source for a resource module from pre-built fragments.
fn format_resource_python(
    resource: &IacResource,
    module_name: &str,
    description: &str,
    frags: &ModuleFragments,
    namespace: &str,
    provider_name: &str,
    author: &str,
) -> String {
    let state_spec = state_spec_entry();
    let header = PYTHON_HEADER;
    let create_class = python_sdk_model_class_name(&resource.crud.create_schema);
    let create_method = python_sdk_method_name(&resource.crud.create_schema);
    let read_class = python_sdk_model_class_name(&resource.crud.read_schema);
    let read_method = python_sdk_method_name(&resource.crud.read_schema);
    let delete_class = python_sdk_model_class_name(&resource.crud.delete_schema);
    let delete_method = python_sdk_method_name(&resource.crud.delete_schema);
    // Argspec field names are always snake_case (the helper assumes
    // module.params is keyed by snake_case identifiers). The IR's
    // identity.id_field is read verbatim from TOML, which conventionally
    // uses kebab-case for API-aligned attribute names (e.g. role-name);
    // normalize to snake_case before emitting read_key so the helper's
    // `module.params.get(read_key)` lookup hits the right key.
    let id_field_snake = to_snake_case(&resource.identity.id_field);
    let sdk_update_kwargs = render_sdk_update_kwargs(resource);
    // read_key only needs to be emitted when the argspec field carrying
    // the identifier isn't the default "name" (helper assumes "name"
    // unless told otherwise).
    let read_key_kwarg = if id_field_snake == "name" {
        String::new()
    } else {
        format!("\n        read_key={id_field_snake:?},")
    };
    let import_path =
        format!("ansible_collections.{namespace}.{provider_name}.plugins.module_utils.akeyless_client");
    let options_yaml = &frags.options_yaml;
    let return_yaml = &frags.return_yaml;
    let argspec_inner = compose_argspec_inner(Some(state_spec), &frags.argument_spec);
    format!(
        r#"{header}

DOCUMENTATION = r'''
---
module: {module_name}
short_description: {description}
author:
  - "{author}"
extends_documentation_fragment:
  - {namespace}.{provider_name}.auth
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

from {import_path} import (
    run_standard_crud,
)

argument_spec = {{
{argspec_inner}
}}


def main():
    run_standard_crud(
        argument_spec=argument_spec,
        resource_label={module_name:?},
        sdk_create=({create_class:?}, {create_method:?}),
{sdk_update_kwargs}
        sdk_delete=({delete_class:?}, {delete_method:?}),
        sdk_read=({read_class:?}, {read_method:?}),{read_key_kwarg}
    )


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
///
/// `namespace` is the Ansible Galaxy namespace used in the generated
/// `ansible_collections.<namespace>.<provider_name>...` import path.
#[must_use]
pub fn generate_resource_module(
    resource: &IacResource,
    provider_name: &str,
    namespace: &str,
    author: &str,
) -> String {
    let module_name = strip_provider_prefix(&resource.name, provider_name);
    let description = resource.description.replace('"', "'");
    let frags = ModuleFragments::from_attributes(&resource.attributes);

    format_resource_python(
        resource,
        module_name,
        &description,
        &frags,
        namespace,
        provider_name,
        author,
    )
}

/// Generate a complete Python module for an RPC-style action.
///
/// Actions are one-shot calls — no `state` parameter, no read step. The
/// generated module just declares its `argument_spec` and delegates the
/// SDK invocation to `run_action_module` from the shared
/// `akeyless_client` module utilities.
///
/// Note: [`IacAction::mutating`] is no longer consumed at this layer —
/// the helper hard-codes `changed=True` for every invocation. The field
/// is kept on the IR for use by other backends (e.g. Terraform), and the
/// underlying helper centralises the check-mode policy (off by default for
/// actions, since they have side effects that can't be simulated).
/// Similarly, [`IacAction::sensitive_response_fields`] is deliberately
/// NOT masked at the module layer — output redaction belongs in the
/// playbook via `no_log: true`. Masking server-side breaks legitimate
/// chained tasks that consume the token.
///
/// `namespace` is the Ansible Galaxy namespace used in the generated
/// `ansible_collections.<namespace>.<provider_name>...` import path.
#[must_use]
pub fn generate_action_module(
    action: &IacAction,
    provider_name: &str,
    namespace: &str,
    author: &str,
) -> String {
    let module_name = strip_provider_prefix(&action.name, provider_name);
    let description = action.description.replace('"', "'");
    let frags = ModuleFragments::from_attributes(&action.attributes);
    let header = PYTHON_HEADER;
    let options_yaml = &frags.options_yaml;
    let argspec_inner = compose_argspec_inner(None, &frags.argument_spec);
    let model_class = python_sdk_model_class_name(&action.schema);
    // Allow TOML to override the SDK method name (e.g. for batch endpoints
    // where the request body schema differs from the SDK method).
    let method_name = action
        .sdk_method
        .clone()
        .unwrap_or_else(|| python_sdk_method_name(&action.schema));
    // Note: sensitive_response_fields is intentionally NOT masked at the
    // module layer. Output redaction belongs in the calling playbook via
    // `no_log: true` -- masking server-side breaks legitimate chained
    // tasks that consume the token (e.g. uid_generate_token ->
    // uid_rotate_token). Input-side no_log is handled by build_argument_spec
    // emitting `'no_log': True` on the argspec entries themselves.
    let import_path =
        format!("ansible_collections.{namespace}.{provider_name}.plugins.module_utils.akeyless_client");
    format!(
        r#"{header}

DOCUMENTATION = r'''
---
module: {module_name}
short_description: {description}
author:
  - "{author}"
extends_documentation_fragment:
  - {namespace}.{provider_name}.auth
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

from {import_path} import (
    run_action_module,
)

argument_spec = {{
{argspec_inner}
}}


def main():
    run_action_module(
        argument_spec=argument_spec,
        sdk_call=({model_class:?}, {method_name:?}),
    )


if __name__ == '__main__':
    main()
"#
    )
}

/// Generate a complete Python module for a data source (read-only).
///
/// `namespace` is the Ansible Galaxy namespace used in the generated
/// `ansible_collections.<namespace>.<provider_name>...` import path.
#[must_use]
pub fn generate_data_source_module(
    ds: &IacDataSource,
    provider_name: &str,
    namespace: &str,
    author: &str,
) -> String {
    let module_name = format!(
        "{}_info",
        strip_provider_prefix(&ds.name, provider_name)
    );
    let frags = ModuleFragments::from_attributes(&ds.attributes);

    let header = PYTHON_HEADER;
    let description = ds.description.replace('"', "'");
    let options_yaml = &frags.options_yaml;
    let return_yaml = &frags.return_yaml;
    let argspec_inner = compose_argspec_inner(None, &frags.argument_spec);
    let read_class = python_sdk_model_class_name(&ds.read_schema);
    let read_method = python_sdk_method_name(&ds.read_schema);
    let import_path =
        format!("ansible_collections.{namespace}.{provider_name}.plugins.module_utils.akeyless_client");
    format!(
        r#"{header}

DOCUMENTATION = r'''
---
module: {module_name}
short_description: {description}
author:
  - "{author}"
extends_documentation_fragment:
  - {namespace}.{provider_name}.auth
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

from {import_path} import (
    run_info_module,
)

argument_spec = {{
{argspec_inner}
}}


def main():
    run_info_module(
        argument_spec=argument_spec,
        sdk_call=({read_class:?}, {read_method:?}),
    )


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
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains("DOCUMENTATION = r'''"));
        assert!(output.contains("module: static_secret"));
        assert!(output.contains("short_description: Manage a static secret"));
    }

    #[test]
    fn resource_module_uses_dict_literal_not_dict_call() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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
        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
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
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains("'name': {'type': 'str', 'required': True}"));
        assert!(output.contains("'tags': {'type': 'list', 'elements': 'str'}"));
    }

    #[test]
    fn resource_module_required_fields() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains("'name': {'type': 'str', 'required': True}"));
        assert!(output.contains("'value': {'type': 'str', 'required': True, 'no_log': True}"));
    }

    #[test]
    fn resource_module_sensitive_no_log() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains("'no_log': True"));
        let doc_section = &output[output.find("DOCUMENTATION").unwrap()..output.find("EXAMPLES").unwrap()];
        assert!(doc_section.contains("no_log: true"));
    }

    #[test]
    fn resource_module_enum_choices() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains("'choices': ['aes128', 'aes256', 'rsa2048']"));
        let doc_section = &output[output.find("DOCUMENTATION").unwrap()..output.find("EXAMPLES").unwrap()];
        assert!(doc_section.contains("choices: [\"aes128\", \"aes256\", \"rsa2048\"]"));
    }

    #[test]
    fn module_name_snake_case() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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
        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
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
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(!output.contains("'secret_id':"));
        let return_section = &output[output.find("RETURN").unwrap()..];
        assert!(return_section.contains("secret_id"));
    }

    #[test]
    fn resource_module_uses_call_api_for_all_crud() {
        // The generated module no longer inlines call_api(...) per CRUD
        // function — instead it hands four (Model, method) tuples to
        // run_standard_crud, which performs the dispatch and the
        // ApiException -> module.fail_json mapping inside the shared
        // helper. Pin that all four lifecycle hooks are wired up via
        // sdk_*=(Class, method_name).
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains("run_standard_crud("), "must dispatch via run_standard_crud");
        // sample_resource crud schemas: CreateBody / UpdateBody / ReadBody / DeleteBody.
        assert!(output.contains("sdk_create=(\"CreateBody\", \"create_body\")"));
        assert!(output.contains("sdk_update=(\"UpdateBody\", \"update_body\")"));
        assert!(output.contains("sdk_read=(\"ReadBody\", \"read_body\")"));
        assert!(output.contains("sdk_delete=(\"DeleteBody\", \"delete_body\")"));
    }

    #[test]
    fn data_source_module_uses_call_api() {
        // call_api(...) is no longer inlined per data source — the read
        // dispatch (and its ApiException -> fail_json mapping) lives
        // inside run_info_module. Pin that the generated module wires up
        // its read via sdk_call=(Class, method_name).
        let ds = IacDataSource {
            name: "test_secret_info".to_string(),
            description: "Get secret information".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadBody".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            output.contains("run_info_module("),
            "data source read should delegate to run_info_module helper"
        );
        assert!(
            output.contains("sdk_call=(\"ReadBody\", \"read_body\")"),
            "data source must pass sdk_call=(Class, method) tuple to run_info_module"
        );
    }

    #[test]
    fn immutable_fields_generate_update_comment() {
        // The immutable-fields comment is now only emitted on the
        // "no update endpoint" branch — right above
        // `sdk_update=None, immutable=True`. Drop the update endpoint so
        // that branch runs; the comment must list the immutable field
        // name `region` and explain it's immutable after creation.
        let mut resource = sample_resource_with_immutable();
        resource.crud.update_endpoint = None;
        resource.crud.update_schema = None;
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            output.contains("immutable after creation"),
            "no-update branch should warn about immutable fields, got:\n{output}"
        );
        assert!(
            output.contains("- region"),
            "no-update branch should list immutable field 'region', got:\n{output}"
        );
        // And the comment is paired with the immutable=True helper kwarg.
        assert!(
            output.contains("sdk_update=None,\n        immutable=True,"),
            "comment must immediately precede sdk_update=None/immutable=True"
        );
    }

    #[test]
    fn no_immutable_fields_no_comment() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");

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
        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
        // The "default missing-result to {}" concern now lives inside
        // `run_info_module` in akeyless_client.py — the generated module
        // just delegates to that helper via `sdk_call=(Model, method)`.
        // Pin that delegation: a missing-result crash would surface in the
        // shared helper, not in this generated module.
        assert!(
            output.contains("run_info_module("),
            "data source main must delegate the read to the shared run_info_module helper, got:\n{output}"
        );
        assert!(
            output.contains("sdk_call=(\"ReadBody\", \"read_body\")"),
            "data source must pass sdk_call=(Model, method) tuple to run_info_module, got:\n{output}"
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
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");

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
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");

        // Should still have valid Python with state parameter and dispatch
        // to the shared run_standard_crud helper.
        assert!(output.contains("run_standard_crud("));
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

        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");

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

        // Verify module content is valid: generated modules now delegate
        // CRUD to run_standard_crud rather than constructing
        // AnsibleModule(...) inline, so pin that delegation instead of
        // the (now removed) AnsibleModule literal.
        for artifact in &artifacts {
            let path = std::path::Path::new(&artifact.path);
            if path.extension().is_some_and(|ext| ext == "py")
                && artifact.path.starts_with("plugins/modules/")
            {
                assert!(
                    artifact.content.contains("run_standard_crud(")
                        || artifact.content.contains("run_action_module(")
                        || artifact.content.contains("run_info_module("),
                    "module {} must dispatch via a shared helper, got:\n{}",
                    artifact.path,
                    artifact.content
                );
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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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
        // Same shape change as immutable_fields_generate_update_comment:
        // the comment lives on the no-update branch now. Clear the update
        // endpoint so the comment is emitted, then verify every immutable
        // field name shows up as `- <name>`.
        let mut resource = sample_resource();
        resource.crud.update_endpoint = None;
        resource.crud.update_schema = None;
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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");

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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains("'state':"), "state param should still exist");
        assert!(!output.contains("'auto_id':"), "computed-only should not be in argument_spec");
        assert!(!output.contains("'created_at':"), "computed-only should not be in argument_spec");

        let return_section = &output[output.find("RETURN").unwrap()..];
        assert!(return_section.contains("auto_id:"), "computed field should be in RETURN");
        assert!(return_section.contains("created_at:"), "computed field should be in RETURN");
    }

    #[test]
    fn resource_module_check_mode_support() {
        // supports_check_mode is no longer expressed in the generated
        // module — it's the default for run_standard_crud (which always
        // supports check_mode for CRUD resources, since reads + diffs
        // are side-effect free). The generated module's job is to
        // delegate; pin that delegation and verify we are NOT explicitly
        // disabling check_mode (which would defeat the helper's default).
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            output.contains("run_standard_crud("),
            "generated module must dispatch via run_standard_crud (which enables check_mode by default)"
        );
        assert!(
            !output.contains("supports_check_mode=False"),
            "generated module must not opt out of check_mode for a CRUD resource"
        );
    }

    #[test]
    fn resource_module_state_choices() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            output.contains("A 'special' data source"),
            "data source description should escape double quotes to single quotes"
        );
    }

    #[test]
    fn resource_module_contains_python_shebang_and_copyright() {
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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
        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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

        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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
        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains("'ids': {'type': 'list', 'required': True, 'elements': 'int'}"));
    }

    #[test]
    fn resource_module_crud_functions_present() {
        // The four CRUD functions are no longer emitted at the module
        // level — they collapsed into run_standard_crud which receives
        // each lifecycle hook as `sdk_<op>=(Model, method)`. Pin that all
        // four hooks are wired up, and that the module still has a
        // `def main()` entry point for `python -m`.
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains("def main():"), "module must still expose main()");
        assert!(output.contains("run_standard_crud("));
        // create / update / read / delete must all be wired.
        assert!(output.contains("sdk_create=("));
        assert!(output.contains("sdk_update=("));
        assert!(output.contains("sdk_read=("));
        assert!(output.contains("sdk_delete=("));
        // And the old per-op function definitions must not reappear.
        assert!(!output.contains("def create_resource"));
        assert!(!output.contains("def update_resource"));
        assert!(!output.contains("def delete_resource"));
        assert!(!output.contains("def read_resource"));
    }

    #[test]
    fn resource_module_state_dispatch_logic() {
        // State dispatch (read current → diff → create/update/delete)
        // moved into run_standard_crud. The generated module only needs
        // to declare 'state' in the argspec and the four lifecycle
        // (Model, method) tuples; the helper performs the dispatch.
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        // The 'state' argspec entry is the contract the helper depends on.
        assert!(
            output.contains("'state': {'type': 'str', 'choices': ['present', 'absent'], 'default': 'present'}"),
            "argument_spec must still declare the state present/absent param"
        );
        // The helper invocation carries every CRUD branch the old
        // dispatch logic implemented.
        assert!(output.contains("run_standard_crud("));
        assert!(output.contains("sdk_create=("));
        assert!(output.contains("sdk_update=("));
        assert!(output.contains("sdk_delete=("));
        assert!(output.contains("sdk_read=("));
    }

    #[test]
    fn data_source_module_has_ansible_module_import() {
        // The generated module no longer imports AnsibleModule directly —
        // that import (and the AnsibleModule(...) construction) now live
        // inside run_info_module in akeyless_client.py. Pin instead that
        // the generated module imports the helper from akeyless_client
        // and hands it the argument_spec + sdk_call tuple.
        let ds = IacDataSource {
            name: "test_ds".to_string(),
            description: "DS".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "Read".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            output.contains("from ansible_collections.akeyless.test.plugins.module_utils.akeyless_client import"),
            "data source module must import the akeyless_client helper, got:\n{output}"
        );
        assert!(output.contains("run_info_module,"));
        assert!(output.contains("run_info_module("));
        // AnsibleModule construction is owned by the helper now, not the
        // generated module.
        assert!(
            !output.contains("from ansible.module_utils.basic import AnsibleModule"),
            "generated data source must not import AnsibleModule directly"
        );
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
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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
        let output = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
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
        // The import block now only pulls in the one lifecycle helper
        // (`run_standard_crud`) — get_client / call_api / build_body
        // are private to the helper module and no longer surfaced to
        // generated modules.
        let mut resource = sample_resource();
        resource.name = "akeyless_static_secret".to_string();
        let output = generate_resource_module(&resource, "akeyless", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            output.contains(
                "from ansible_collections.akeyless.akeyless.plugins.module_utils.akeyless_client import"
            ),
            "resource module must import from the shared akeyless_client helper"
        );
        assert!(
            output.contains("run_standard_crud,"),
            "resource module must import the run_standard_crud lifecycle helper"
        );
        // Internal helpers must NOT be re-imported by generated modules.
        assert!(
            !output.contains("get_client, call_api, build_body"),
            "generated modules must not re-import the helper's internal primitives"
        );
    }

    #[test]
    fn data_source_module_imports_akeyless_client_helper() {
        let ds = IacDataSource {
            name: "akeyless_thing_info".to_string(),
            description: "thing".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadThing".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let output = generate_data_source_module(&ds, "akeyless", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains(
            "from ansible_collections.akeyless.akeyless.plugins.module_utils.akeyless_client import"
        ));
    }

    #[test]
    fn resource_module_uses_custom_namespace_in_import_path() {
        let mut resource = sample_resource();
        resource.name = "akeyless_static_secret".to_string();
        let output = generate_resource_module(&resource, "akeyless", "drzln0", "pleme-io (@pleme-io)");
        assert!(
            output.contains(
                "from ansible_collections.drzln0.akeyless.plugins.module_utils.akeyless_client import"
            ),
            "resource module must honor the namespace argument in the import path: {output}"
        );
        assert!(
            !output.contains("ansible_collections.akeyless.akeyless"),
            "custom namespace must not leak the old hardcoded namespace"
        );
    }

    #[test]
    fn data_source_module_uses_custom_namespace_in_import_path() {
        let ds = IacDataSource {
            name: "akeyless_thing_info".to_string(),
            description: "thing".to_string(),
            read_endpoint: "/read".to_string(),
            read_schema: "ReadThing".to_string(),
            read_response_schema: None,
            attributes: vec![],
            read_mapping: std::collections::BTreeMap::new(),
        };
        let output = generate_data_source_module(&ds, "akeyless", "drzln0", "pleme-io (@pleme-io)");
        assert!(
            output.contains(
                "from ansible_collections.drzln0.akeyless.plugins.module_utils.akeyless_client import"
            ),
            "data source module must honor the namespace argument in the import path"
        );
        assert!(
            !output.contains("ansible_collections.akeyless.akeyless"),
            "custom namespace must not leak the old hardcoded namespace"
        );
    }

    #[test]
    fn action_module_uses_custom_namespace_in_import_path() {
        let action = sample_action();
        let output = generate_action_module(&action, "akeyless", "drzln0", "pleme-io (@pleme-io)");
        assert!(
            output.contains(
                "from ansible_collections.drzln0.akeyless.plugins.module_utils.akeyless_client import"
            ),
            "action module must honor the namespace argument in the import path"
        );
    }

    #[test]
    fn resource_module_uses_build_body_with_create_schema_class() {
        // build_body(...) is no longer called at the module level — the
        // helper calls it internally given the (Model, method) tuple.
        // Pin instead that the SDK model class name from
        // crud.create_schema is forwarded verbatim as the first element
        // of `sdk_create=("CreateBody", "create_body")`.
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        // sample_resource.crud.create_schema = "CreateBody"
        assert!(
            output.contains("sdk_create=(\"CreateBody\", \"create_body\")"),
            "sdk_create tuple must forward the create_schema model class and python-method name, got:\n{output}"
        );
    }

    #[test]
    fn resource_module_uses_snake_case_sdk_method() {
        // Method names are now the second element of each
        // sdk_*=(Class, method) tuple rather than the third arg to a
        // call_api(...) literal. Same naming contract though: snake_case
        // conversion of each CRUD schema name.
        // Resource crud schemas:    "CreateBody" / "UpdateBody" / "ReadBody" / "DeleteBody".
        // Expected python SDK methods: "create_body" / "update_body" / etc.
        let resource = sample_resource();
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(output.contains("sdk_create=(\"CreateBody\", \"create_body\")"));
        assert!(output.contains("sdk_read=(\"ReadBody\", \"read_body\")"));
        assert!(output.contains("sdk_delete=(\"DeleteBody\", \"delete_body\")"));
        assert!(output.contains("sdk_update=(\"UpdateBody\", \"update_body\")"));
    }

    #[test]
    fn resource_without_update_endpoint_fails_with_unsupported_message() {
        // The literal "update not supported" fail_json block at the
        // module level is gone; the equivalent contract is now expressed
        // as `sdk_update=None, immutable=True` in the run_standard_crud
        // call. The runtime helper (akeyless_client.py) is what raises
        // the "drift detected but the resource is immutable after
        // creation" failure when state diverges and update isn't
        // supported. Pin the new kwargs.
        let mut resource = sample_resource();
        resource.crud.update_endpoint = None;
        resource.crud.update_schema = None;
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            output.contains("sdk_update=None"),
            "no-update resources must pass sdk_update=None to run_standard_crud, got:\n{output}"
        );
        assert!(
            output.contains("immutable=True"),
            "no-update resources must pass immutable=True so the helper fails on drift, got:\n{output}"
        );
        // Sanity: the now-removed literal must not sneak back in.
        assert!(
            !output.contains("update not supported, delete+recreate"),
            "the old inline fail_json literal must not be regenerated"
        );
    }

    #[test]
    fn resource_module_read_mapping_passes_through_to_ir() {
        // The read_mapping field is plumbed via the IR but the Phase 1
        // generator does not yet feed it into the helper call. The
        // contract pinned here is: the generator stays a total function
        // of the IR (a populated read_mapping doesn't error) and still
        // emits the standard CRUD dispatch. When read_mapping
        // consumption lands, swap this for a stronger assertion.
        let mut resource = sample_resource();
        resource.read_mapping.insert("item_name".into(), "name".into());
        let output = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            output.contains("run_standard_crud("),
            "generator must remain a total function of the IR even when read_mapping is populated, got:\n{output}"
        );
        // Read still wires up regardless of read_mapping presence.
        assert!(output.contains("sdk_read=(\"ReadBody\", \"read_body\")"));
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
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        // Action modules do not have create/read/update/delete semantics.
        assert!(!out.contains("'state':"), "action modules must not declare state");
        assert!(!out.contains("def create_resource"));
        assert!(!out.contains("def delete_resource"));
    }

    #[test]
    fn action_module_disables_check_mode() {
        // run_action_module defaults supports_check_mode to False
        // internally (actions have side effects that can't be
        // simulated), so the generated module no longer passes that
        // kwarg at all. Pin the inverse: the generated module must not
        // try to *enable* check_mode for an action, which would override
        // the helper's safe default.
        let action = sample_action();
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            !out.contains("supports_check_mode=True"),
            "action modules must not enable check_mode (their side effects can't be simulated)"
        );
        // And the helper invocation must be present.
        assert!(out.contains("run_action_module("));
    }

    #[test]
    fn action_module_calls_expected_sdk_method() {
        // call_api(...) / build_body(...) are no longer inlined — both
        // happen inside run_action_module given a single
        // `sdk_call=(Model, method)` tuple. Verify the model class and
        // python method name still derive from `IacAction::schema`
        // ("uidGenerateToken" → UidGenerateToken / uid_generate_token).
        let action = sample_action();
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(out.contains("run_action_module("));
        assert!(out.contains("sdk_call=(\"UidGenerateToken\", \"uid_generate_token\")"));
    }

    #[test]
    fn action_module_masks_sensitive_response_fields() {
        // INVERTED contract: action modules deliberately do NOT mask
        // sensitive_response_fields at the module layer. Masking
        // server-side breaks chained playbook tasks that legitimately
        // consume the token (e.g. uid_generate_token →
        // uid_rotate_token). Output redaction belongs in the calling
        // playbook via `no_log: true` (input-side no_log is still
        // honored — see the argspec's 'no_log' entries). This test pins
        // the absence of the old `_sensitive = {...}` set + `'***'`
        // masking sentinel so the masking layer can't sneak back in.
        let action = sample_action();
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            !out.contains("_sensitive ="),
            "action modules must not emit a sensitive-response masking set, got:\n{out}"
        );
        assert!(
            !out.contains("'***'"),
            "action modules must not emit a masking sentinel; redaction lives at the playbook layer"
        );
        assert!(
            !out.contains("\"***\""),
            "action modules must not emit a masking sentinel; redaction lives at the playbook layer"
        );
    }

    #[test]
    fn action_module_empty_sensitive_set_renders_set_literal() {
        // The `_sensitive = ...` masking block is gone — output
        // redaction now lives at the playbook layer via `no_log: true`
        // (see comment in generate_action_module). With or without
        // sensitive_response_fields, the generated module must NOT emit
        // a masking set literal.
        let mut action = sample_action();
        action.sensitive_response_fields.clear();
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            !out.contains("_sensitive ="),
            "empty sensitive_response_fields must not emit any _sensitive = ... literal, got:\n{out}"
        );
        assert!(
            !out.contains("set()"),
            "no empty-set Python literal should leak through to the action module"
        );
    }

    #[test]
    fn action_module_mutating_false_emits_changed_false() {
        // The "mutating: false" branch is no longer expressed at the
        // module layer — run_action_module hard-codes changed=True for
        // every invocation (RPC-style actions are assumed to mutate
        // server state; the IR's `mutating` field is dead at this
        // backend, see generate_action_module's doc comment). Pin that
        // the generated module always dispatches via run_action_module
        // and never inlines its own exit_json(changed=...).
        let mut action = sample_action();
        action.mutating = false;
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            out.contains("run_action_module("),
            "non-mutating actions must still dispatch via run_action_module"
        );
        assert!(
            !out.contains("module.exit_json"),
            "exit_json is owned by the helper now, not the generated module, got:\n{out}"
        );
    }

    #[test]
    fn action_module_mutating_true_emits_changed_true() {
        // changed=True is now hard-coded inside run_action_module — the
        // generated module's job is just to delegate via the sdk_call
        // tuple. Pin the delegation and the absence of an inlined
        // exit_json (which would be a regression to the old shape).
        let action = sample_action();
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(out.contains("run_action_module("));
        assert!(
            out.contains("sdk_call=(\"UidGenerateToken\", \"uid_generate_token\")"),
            "mutating action must wire its SDK call via sdk_call tuple, got:\n{out}"
        );
        assert!(
            !out.contains("module.exit_json"),
            "exit_json is owned by run_action_module, not the generated module"
        );
    }

    #[test]
    fn action_module_strips_provider_prefix_from_name() {
        let mut action = sample_action();
        action.name = "akeyless_uid_generate_token".to_string();
        let out = generate_action_module(&action, "akeyless", "akeyless", "pleme-io (@pleme-io)");
        assert!(out.contains("module: uid_generate_token"));
    }

    #[test]
    fn action_module_required_attribute_renders_in_argument_spec() {
        let action = sample_action();
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(out.contains("'auth_method_name': {'type': 'str', 'required': True}"));
    }

    #[test]
    fn action_module_uses_sdk_method_override_when_provided() {
        // Same override contract under the new shape: the second
        // element of sdk_call carries either the override or the
        // schema-derived snake_case form. The first element (the model
        // class) always comes from `schema` — the body type stays
        // correct even when the method name diverges (batch endpoints).
        let mut action = sample_action();
        // Batch endpoints reuse the BatchEncryptionRequestLine schema but
        // the actual SDK method is encrypt_batch / decrypt_batch.
        action.schema = "BatchEncryptionRequestLine".to_string();
        action.sdk_method = Some("encrypt_batch".to_string());
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            out.contains("sdk_call=(\"BatchEncryptionRequestLine\", \"encrypt_batch\")"),
            "sdk_call must pair the schema-derived model class with the override method name, got:\n{out}"
        );
    }

    #[test]
    fn action_module_falls_back_to_derived_method_when_override_absent() {
        // call_api(...) literal is gone; the method name now sits in
        // sdk_call=(Class, method). Pin the same derivation contract:
        // sdk_method=None → method derives from the schema name.
        let action = sample_action();
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(
            out.contains("sdk_call=(\"UidGenerateToken\", \"uid_generate_token\")"),
            "sdk_method=None must fall back to the snake_case form of the schema name, got:\n{out}"
        );
    }

    // ------------------------------------------------------------------
    // Snapshot-style behaviour tests for the documented shape contracts.
    // These complement the existing per-fragment checks by exercising one
    // representative input per generator branch and pattern-matching the
    // emitted Python for the expected invariants.
    // ------------------------------------------------------------------

    /// CRUD resource with no update endpoint -- the helper invocation
    /// must opt the resource into the helper's immutable-drift-failure
    /// behaviour via `sdk_update=None, immutable=True`. The "drift
    /// detected but the resource is immutable after creation" failure
    /// itself is now produced by run_standard_crud in akeyless_client.py.
    #[test]
    fn snapshot_resource_without_update_emits_no_update_branch() {
        let mut resource = sample_resource();
        resource.crud.update_endpoint = None;
        resource.crud.update_schema = None;
        let out = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        // The kwargs that wire the no-update behaviour into the helper.
        assert!(
            out.contains("sdk_update=None"),
            "no-update branch must pass sdk_update=None to run_standard_crud"
        );
        assert!(
            out.contains("immutable=True"),
            "no-update branch must pass immutable=True so the helper fails on drift"
        );
        // And the per-op functions / inline fail_json that used to live
        // in the module must not be regenerated.
        assert!(!out.contains("def update_resource"));
        assert!(!out.contains("fail_json("));
    }

    /// CRUD resource where every input field is immutable AND there is
    /// no update endpoint -- the WARNING comment is emitted just above
    /// the `sdk_update=None, immutable=True` kwargs and must list every
    /// immutable field by canonical name.
    ///
    /// (The comment is only emitted on the no-update branch now — if an
    /// update endpoint exists, immutability is documented field-by-field
    /// in the YAML options block and the helper handles the field-level
    /// diff itself.)
    #[test]
    fn snapshot_all_immutable_fields_lists_every_name_in_comment() {
        let mut resource = sample_resource();
        // Drop update endpoint so the no-update branch (which carries
        // the immutable-fields comment) actually runs.
        resource.crud.update_endpoint = None;
        resource.crud.update_schema = None;
        // Mark every non-computed attribute immutable.
        for attr in &mut resource.attributes {
            if !attr.computed {
                attr.immutable = true;
            }
        }
        let out = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
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
        // And the comment is followed by the helper kwargs it documents.
        assert!(out.contains("sdk_update=None,\n        immutable=True,"));
    }

    /// Resource with a sensitive field -- both argspec and YAML docstring
    /// must declare no_log on that field.
    #[test]
    fn snapshot_sensitive_field_emits_no_log_in_argspec_and_yaml() {
        let resource = sample_resource();
        let out = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        // sample_resource declares `value` as sensitive.
        assert!(out.contains("'value': {'type': 'str', 'required': True, 'no_log': True}"));
        // YAML doc section between DOCUMENTATION and EXAMPLES.
        let doc_start = out.find("DOCUMENTATION").unwrap();
        let doc_end = out.find("EXAMPLES").unwrap();
        let doc = &out[doc_start..doc_end];
        assert!(doc.contains("no_log: true"), "YAML docstring missing no_log: true");
    }

    /// Action with mutating=true -- the generated module delegates to
    /// run_action_module, which hard-codes changed=True. INVERTED
    /// contract from the old shape: there must be NO `_sensitive =
    /// {...}` masking set and NO `'***'` masking sentinel.
    /// `IacAction::sensitive_response_fields` is deliberately not
    /// honored at the module layer because masking server-side breaks
    /// chained tasks that consume tokens; redaction lives in the
    /// calling playbook via `no_log: true` instead.
    #[test]
    fn snapshot_mutating_action_changed_true_and_masks_response() {
        let action = sample_action();
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        // sample_action has sensitive_response_fields = ["token"], yet
        // the generated module must NOT emit any masking apparatus.
        assert!(!action.sensitive_response_fields.is_empty(), "fixture sanity check: sensitive fields should be set");
        assert!(
            !out.contains("_sensitive"),
            "action modules must not emit a sensitive-response masking set even when sensitive_response_fields is populated, got:\n{out}"
        );
        assert!(
            !out.contains("'***'"),
            "no masking sentinel allowed at the module layer"
        );
        // The delegation contract still holds.
        assert!(out.contains("run_action_module("));
        assert!(out.contains("sdk_call=(\"UidGenerateToken\", \"uid_generate_token\")"));
    }

    /// Action with mutating=false -- the generator no longer branches
    /// on `IacAction::mutating` at all (the helper hard-codes
    /// changed=True). Pin that the delegation still happens and that
    /// the generated module emits no inline exit_json call regardless
    /// of mutating value (and that the `mutating` flag does not break
    /// the generator).
    #[test]
    fn snapshot_non_mutating_action_changed_false() {
        let mut action = sample_action();
        action.mutating = false;
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(out.contains("run_action_module("));
        assert!(
            !out.contains("module.exit_json"),
            "exit_json is the helper's job; the generated module must not inline it"
        );
        // The IR.mutating field stays in IR for other backends but is
        // not consumed here — output must be identical to mutating=true.
        let mut mutating_action = sample_action();
        mutating_action.mutating = true;
        let mutating_out = generate_action_module(&mutating_action, "test", "akeyless", "pleme-io (@pleme-io)");
        assert_eq!(
            out, mutating_out,
            "IacAction::mutating is no longer consumed at this backend; output must be invariant under it"
        );
    }

    /// Action with sdk_method override -- the second element of
    /// sdk_call must carry the override, not the schema-derived name.
    #[test]
    fn snapshot_action_sdk_method_override_takes_priority() {
        let mut action = sample_action();
        action.sdk_method = Some("custom_batch_call".to_string());
        let out = generate_action_module(&action, "test", "akeyless", "pleme-io (@pleme-io)");
        // sample_action.schema = "uidGenerateToken" -> derived name
        // would be "uid_generate_token"; the override should win.
        assert!(
            out.contains("sdk_call=(\"UidGenerateToken\", \"custom_batch_call\")"),
            "sdk_call must carry the override method name, got:\n{out}"
        );
        // The derived name MUST NOT appear anywhere in the sdk_call
        // tuple (it's fine in DOCUMENTATION / module name etc.).
        assert!(
            !out.contains("sdk_call=(\"UidGenerateToken\", \"uid_generate_token\")"),
            "schema-derived method must NOT appear when sdk_method override is set"
        );
    }

    /// Data source -- no state parameter, no CRUD helper functions,
    /// delegates the read to run_info_module (which is also responsible
    /// for emitting `changed=False` from its exit_json).
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
        let out = generate_data_source_module(&ds, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(!out.contains("'state':"));
        assert!(!out.contains("def create_resource"));
        assert!(!out.contains("def update_resource"));
        assert!(!out.contains("def delete_resource"));
        // exit_json is now owned by the helper, not the generated module.
        assert!(
            !out.contains("module.exit_json"),
            "exit_json is the helper's job for data sources too"
        );
        // The delegation contract: read goes via run_info_module with
        // sdk_call=(ReadModel, read_method).
        assert!(out.contains("run_info_module("));
        assert!(out.contains("sdk_call=(\"GetThing\", \"get_thing\")"));
    }

    /// Sanity: a CRUD resource with a populated read_mapping still
    /// wires up all four lifecycle hooks on run_standard_crud. The four
    /// per-op `def *_resource(...)` functions are gone in the new
    /// shape — collapsed into the helper — so pin the four
    /// `sdk_*=(Class, method)` kwargs instead. (read_mapping is plumbed
    /// in IR but doesn't yet rewrite the helper invocation; when it
    /// does, this test should grow an assertion on the new kwarg.)
    #[test]
    fn snapshot_crud_with_read_mapping_still_emits_all_four_operations() {
        let mut resource = sample_resource();
        resource.read_mapping = {
            let mut m = std::collections::BTreeMap::new();
            m.insert("$.name".to_string(), "name".to_string());
            m
        };
        let out = generate_resource_module(&resource, "test", "akeyless", "pleme-io (@pleme-io)");
        assert!(out.contains("run_standard_crud("));
        assert!(out.contains("sdk_create=(\"CreateBody\", \"create_body\")"));
        assert!(out.contains("sdk_read=(\"ReadBody\", \"read_body\")"));
        assert!(out.contains("sdk_update=(\"UpdateBody\", \"update_body\")"));
        assert!(out.contains("sdk_delete=(\"DeleteBody\", \"delete_body\")"));
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
