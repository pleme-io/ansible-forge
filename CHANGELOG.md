# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- (placeholder for next release)

## [0.2.0] — 2026-05-21

First fully-working baseline. Emits real Ansible modules that call the akeyless Python SDK; no more TODO stubs.

### Added

- `src/client_helper.rs` — embeds the `akeyless_client.py` helper as a Rust const. Single auth touch-point for every generated module; handles 404-tolerant reads, sensitive-value masking on responses, and request-body construction via `inspect.signature`.
- `module_gen::format_resource_python` — emits real CRUD modules using `crud.{create,read,update,delete}_endpoint` + `*_schema`. Reads `identity.id_field` for read/delete lookups; reads `identity.force_replace_fields` for destroy+recreate semantics.
- `module_gen::generate_action_module` — RPC-style module emitter for `IacAction` specs. No `state` parameter, `supports_check_mode=False`, masks `sensitive_response_fields` in `result`, dispatches `mutating=true|false` to `changed=true|false`.
- `module_gen::generate_data_source_module` — read-only `_info` module emitter.
- `module_gen::python_sdk_method_name` — inflection.underscore conversion that preserves acronym runs (`CreatePKICertIssuer` → `create_pki_cert_issuer`, not `create_p_k_i_cert_issuer`).
- `module_gen::python_sdk_model_class_name` — first-character uppercase for the request-body model.
- `module_gen::render_update_function` — handles both with-update and no-update flavours; the no-update branch mirrors `terraform-forge::render_no_update`.
- `backend::AnsibleBackend::generate_provider` — emits `plugins/module_utils/akeyless_client.py`, `galaxy.yml`, `meta/runtime.yml`, `requirements.txt` (`akeyless>=5.0.22`), `README.md`.
- `backend::AnsibleBackend::generate_action` — implements the new `Backend::generate_action` hook.
- Snapshot tests for 10 representative generator output shapes (basic CRUD, no-update, all-immutable, sensitive field, action mutating, action read-only, action with `sdk_method` override, data source).
- `tests/integration_toml_walk.rs` — end-to-end test that walks every TOML in `akeyless-terraform-resources/` and confirms the generated Python contains `def main():`, the right `module_utils` import, and no placeholder TODOs. Currently asserts 208/208 specs pass.

### Changed

- `AnsibleTypeExt::ansible_type` collapses `String | Any | _` into a single fallback arm (clippy `match_same_arms` compliance) and adds explicit `Float | Numeric` and `Object | Map` handling.
- `Cargo.toml` adds `openapi-forge` as a dev-dependency for the integration test (the test needs to construct a `Spec`; `iac-forge` doesn't re-export it).

### Removed

- All `# TODO: implement API call` placeholders from the generator output.

[Unreleased]: https://github.com/pleme-io/ansible-forge/compare/v0.2-full-api...HEAD
[0.2.0]: https://github.com/pleme-io/ansible-forge/releases/tag/v0.2-full-api
