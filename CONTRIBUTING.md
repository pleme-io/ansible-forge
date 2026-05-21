# Contributing to `ansible-forge`

Thanks for your interest. `ansible-forge` is a small, focused Rust crate
that emits Ansible modules from the `iac-forge` IR. The bar for accepted
contributions is straightforward: changes should fit existing patterns,
move the substrate forward, and not over-engineer.

## Dev setup

Install the Rust toolchain via [`rustup`](https://rustup.rs), or use the
provided Nix flake:

```sh
nix develop
```

The flake pins `rust-toolchain.toml`, so everything in CI matches your
local build.

## Running the tests

```sh
# Unit + snapshot tests
cargo test --lib

# End-to-end: walk every TOML spec in akeyless-terraform-resources and emit it
cargo test --test integration_toml_walk
```

CI runs both on every push. The integration test is what gives us the "208
modules generate without panic" guarantee, so please don't skip it locally.

## Iterating against a local `iac-forge`

When you need to change `iac-forge` and `ansible-forge` together, drop a
`[patch]` section into your local `Cargo.toml`:

```toml
[patch."https://github.com/pleme-io/iac-forge"]
iac-forge = { path = "../iac-forge" }
```

This stays out of git via the standard `.gitignore` patterns; just be sure
to remove the patch before opening the PR (CI will fail loudly if you
don't).

## Style notes

- **Idiom-first.** Prefer existing crate patterns over novel abstractions.
  When in doubt, look at how `IacResource` is handled and follow suit for
  `IacAction` / `IacDataSource`.
- **Solve once.** Fixes should be load-bearing. If two emitter arms have the
  same bug, fix the shared helper rather than copy-pasting the patch.
- **Clippy pedantic.** The crate runs `clippy::pedantic = warn`. Don't
  silence lints without a comment justifying why.
- **No new deps without a reason.** This crate is intentionally small —
  three runtime deps (`iac-forge`, `serde`, `serde_json`). Adding more
  needs a sentence in the PR.
- **CSE alignment.** See the
  [Constructive Substrate Engineering canonical spec](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md).
  TL;DR: each change should leave the codebase a little easier to extend,
  not a little more clever.

## Filing issues

- **Bug?** Use [`bug.yml`](./.github/ISSUE_TEMPLATE/bug.yml). Include the
  smallest reproducer — ideally a unit test that fails.
- **Feature request?** Use [`feature.yml`](./.github/ISSUE_TEMPLATE/feature.yml).
  Frame the change in terms of "what new IR shape needs to round-trip" or
  "what cleanup unlocks the next emitter".

Missing-module requests for the Akeyless collection itself belong on
[`ansible-akeyless-gen`](https://github.com/pleme-io/ansible-akeyless-gen)
or the spec repo
[`akeyless-terraform-resources`](https://github.com/pleme-io/akeyless-terraform-resources),
not here.

## Releasing

Releases are tag-driven. The flow:

1. Land your change on `main` and verify CI is green.
2. Bump `version` in `Cargo.toml` (semver: bug fixes → patch, new emitter
   variant or behavior change → minor, breaking IR contract → major).
3. Update `CHANGELOG.md` (`Unreleased` → new version).
4. Tag and push:

   ```sh
   git tag -a v0.x.y -m "ansible-forge v0.x.y"
   git push origin v0.x.y
   ```

5. CI publishes to crates.io on tag push (once the publish workflow and
   `CARGO_REGISTRY_TOKEN` secret are wired up).

## Code of conduct

By participating you agree to abide by the
[Contributor Covenant 2.1](./CODE_OF_CONDUCT.md).

## License

By contributing you agree your work is offered under the [MIT License](./LICENSE).
