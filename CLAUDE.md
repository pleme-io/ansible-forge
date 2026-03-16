# ansible-forge

Ansible collection code generator. Implements `iac_forge::Backend` to produce
Python Ansible modules from the iac-forge IR.

## Architecture

Takes `IacResource` and `IacDataSource` from iac-forge IR and generates
complete Python module files following the standard Ansible module layout.
Each resource produces a module with `DOCUMENTATION`, `EXAMPLES`, `RETURN`
docstrings, an `argument_spec`, and a `main()` function. Data sources produce
`_info` suffixed modules.

Ansible has no provider concept -- the `generate_provider()` method is a no-op.

## Module Structure

Generated Python modules contain:

```python
DOCUMENTATION = r'''
module: <module_name>
short_description: <description>
description: [<description>]
options:
    <field_name>:
        description: "<field_description>"
        type: <ansible_type>
        required: <true/false>
        no_log: <true/false>        # for sensitive fields
'''

EXAMPLES = r'''
- name: Create <resource>
  <namespace>.<module_name>:
    <field>: "example_value"
    state: present
'''

RETURN = r'''
<field_name>:
    description: "<field_description>"
    type: <ansible_type>
    returned: always
'''

def main():
    argument_spec = dict(
        <field_name>=dict(type='<type>', required=<True/False>, no_log=<True/False>),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    # CRUD dispatch based on state parameter
```

## Key Types

- `AnsibleBackend` -- implements `iac_forge::Backend` trait
- `AnsibleNaming` -- naming convention: snake_case for types, fields, and files

## Type Mappings (IacType -> Ansible argument_spec type)

```
IacType::String       -> "str"
IacType::Integer      -> "int"
IacType::Float        -> "float"
IacType::Boolean      -> "bool"
IacType::List(T)      -> "list" (elements: <T>)
IacType::Set(T)       -> "list" (elements: <T>)
IacType::Map(T)       -> "dict"
IacType::Object       -> "dict"
IacType::Enum         -> type of underlying (e.g. "str" or "int")
IacType::Any          -> "str"
```

## File Output

- Resources: `plugins/modules/{snake_case_name}.py`
- Data sources: `plugins/modules/{snake_case_name}_info.py`
- Tests: `tests/integration/targets/{snake_case_name}/tasks/main.yml`

## Test Playbooks

Generated test playbooks exercise the full lifecycle:

```yaml
- name: Create <resource>
  <namespace>.<module>:
    <fields>...
    state: present
  register: create_result

- name: Verify creation
  assert:
    that: create_result is changed

- name: Delete <resource>
  <namespace>.<module>:
    <id_field>: "{{ create_result.<id_field> }}"
    state: absent
```

## Source Layout

```
src/
  lib.rs          # Public API re-exports (AnsibleBackend)
  backend.rs      # Backend trait implementation + naming convention
  module_gen.rs   # Python module generation (DOCUMENTATION, EXAMPLES, RETURN, main())
```

## Usage

```rust
use ansible_forge::AnsibleBackend;
use iac_forge::Backend;

let backend = AnsibleBackend::new();
let artifacts = backend.generate_resource(&resource, &provider)?;
// artifacts[0].content is the Python module source
// artifacts[0].path is e.g. "plugins/modules/static_secret.py"
```

## Testing

Run: `cargo test`
