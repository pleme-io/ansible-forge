//! Bundled Python helper distributed at
//! `plugins/module_utils/akeyless_client.py` in the generated collection.
//!
//! Every emitted Ansible module imports from this helper (one of the
//! `run_*_module` lifecycle wrappers, or directly the lower-level
//! `get_client` / `call_api` / `build_body` primitives for legacy or
//! hand-written modules). It is the single Akeyless-SDK boundary in
//! every generated collection.
//!
//! Source-of-truth is `src/client_helper.py` in this crate; we ship it
//! verbatim via `include_str!` so the .py file stays a real Python file
//! (lintable, type-checkable, no raw-string escape headaches) and any
//! drift between the generator's bundled copy and a downstream
//! collection checkout fails the regen-vs-collection backstop in
//! `tests/integration_regen_matches_collection.rs`.

/// Source of the `akeyless_client.py` helper. Embedded at compile time
/// from `src/client_helper.py` so the generator binary carries the
/// canonical helper text without a separate runtime dependency.
pub const AKEYLESS_CLIENT_PY: &str = include_str!("client_helper.py");
