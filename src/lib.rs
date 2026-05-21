//! Ansible collection code generator.
//!
//! Implements [`iac_forge::Backend`] to produce Python Ansible modules from
//! the iac-forge IR.  Each resource generates a module with `DOCUMENTATION`,
//! `EXAMPLES`, `RETURN` docstrings, an `argument_spec`, and a `main()`
//! function.  Data sources produce `_info`-suffixed modules.

pub mod backend;
pub mod client_helper;
pub mod module_gen;

pub use backend::AnsibleBackend;
pub use module_gen::AnsibleTypeExt;
