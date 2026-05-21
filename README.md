# ansible-forge

> Ansible code-gen backend for [`iac-forge`](https://github.com/pleme-io/iac-forge) — emits Ansible modules from IR.

[![Crates.io](https://img.shields.io/crates/v/ansible-forge.svg)](https://crates.io/crates/ansible-forge)
[![docs.rs](https://docs.rs/ansible-forge/badge.svg)](https://docs.rs/ansible-forge)
[![CI](https://github.com/pleme-io/ansible-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/pleme-io/ansible-forge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## What it does

`ansible-forge` is a Rust library that implements the `iac_forge::Backend`
trait for the Ansible target. Given the IR types from `iac-forge` —
`IacResource`, `IacAction`, `IacDataSource`, and `IacProvider` — it emits:

- a Python module per resource / action / data source under
  `plugins/modules/<name>.py`
- a shared `plugins/module_utils/akeyless_client.py` helper holding the SDK
  binding (auth, body builder, API dispatch)
- collection metadata: `galaxy.yml`, `meta/runtime.yml`,
  `requirements.txt`, a stub `README.md`
- a smoke-test playbook under `tests/integration/targets/<name>/tasks/main.yml`

The emitter is consumed by [`iac-forge-cli`](https://github.com/pleme-io/iac-forge-cli)
behind `iac-forge-cli generate --backend ansible`, and ships the
[`akeyless.akeyless`](https://github.com/pleme-io/ansible-akeyless-gen)
collection on Galaxy.

---

## Usage

Add the crate as a dependency:

```toml
[dependencies]
ansible-forge = "0.1"
iac-forge = "0.1"
```

Then plug it into your generator pipeline:

```rust
use ansible_forge::AnsibleBackend;
use iac_forge::{Backend, IacResource, IacProvider};

let backend = AnsibleBackend::new();

let artifacts = backend.generate_resource(&resource, &provider)?;
for artifact in artifacts {
    std::fs::write(&artifact.path, &artifact.content)?;
}
```

For one-shot CLI use, install the dispatcher and let it walk the spec set:

```sh
cargo install iac-forge-cli
iac-forge-cli generate --backend ansible --output ./out
```

---

## Output shape

Three emitter variants cover the entire Akeyless surface:

| IR type          | File suffix       | Pattern                                                        |
|------------------|-------------------|----------------------------------------------------------------|
| `IacResource`    | `<name>.py`       | `state: present \| absent` — drives create / update / delete   |
| `IacAction`      | `<name>.py`       | one-shot RPC, `changed: true`, sensitive output masking        |
| `IacDataSource`  | `<name>_info.py`  | read-only fetch via the matching `list`/`get` API method       |

All modules share a single `plugins/module_utils/akeyless_client.py`:

- `get_client(module)` — resolves auth from params / env / pre-issued token,
  returns `(akeyless.V2Api, token)`.
- `build_body(model_class_name, params)` — filters `None`s and unknown keys,
  instantiates `akeyless.<Model>`.
- `call_api(module, client, method_name, body)` — invokes the SDK method,
  normalizes the response.

---

## Pipeline diagram

```
akeyless-terraform-resources/resources/*.toml  ← spec source
  → iac-forge ResourceSpec parser
  → iac-forge IR (IacResource / IacAction / IacDataSource)
  → ansible-forge AnsibleBackend
  → plugins/modules/*.py + collection metadata
  → ansible-galaxy collection build
  → galaxy.ansible.com
```

The hand-off boundary is the IR — `iac-forge` owns parsing and shape
inference, `ansible-forge` owns Python emission. Adding a new IR shape (the
most recent example: `IacAction`) means a new dispatch arm and a new
emitter, no parser changes here.

---

## Extending

To add a new emitter variant:

1. Add the IR type upstream in `iac-forge` (e.g. `IacAction`) and have
   `iac-forge-cli` dispatch to a new `Backend` method (e.g. `generate_action`).
2. Implement the method on `AnsibleBackend` in
   [`src/backend.rs`](./src/backend.rs); delegate body generation to a new
   function in [`src/module_gen.rs`](./src/module_gen.rs).
3. Add a snapshot test for a representative spec — see the bottom of
   `module_gen.rs`.
4. The end-to-end test in `tests/integration_toml_walk.rs` will walk every
   TOML spec and assert nothing panics or generates an unparseable Python
   file.

Idiom-first: stay close to existing patterns, lean on
`iac-forge::{NamingConvention, to_snake_case, strip_provider_prefix}` for
string transforms, and don't reinvent the IR.

---

## Testing

```sh
# Unit + snapshot tests
cargo test --lib

# End-to-end: walk all 119+ TOML specs and emit each through the backend
cargo test --test integration_toml_walk
```

The integration test is what gives us the "208 modules generate without
panic" guarantee, and it runs in CI on every push.

For iterative dev against a local `iac-forge` checkout, use a `[patch]`
section in `Cargo.toml`:

```toml
[patch."https://github.com/pleme-io/iac-forge"]
iac-forge = { path = "../iac-forge" }
```

Drop the patch before opening a PR.

---

## Doctrine

This crate operates under
[**Constructive Substrate Engineering**](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md).
The Compounding Directive (solve-once, load-bearing fixes, idiom-first,
direction beats velocity) is in the org `CLAUDE.md`. Read both before
non-trivial changes.

---

## License

[MIT](./LICENSE). Copyright (c) 2026 pleme-io.
