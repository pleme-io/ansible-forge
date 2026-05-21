<!-- Thanks! A few prompts to help reviewers. -->

## Summary

<!-- 1–3 sentences: what does this PR change and why? -->

## Related issue

<!-- "Closes #123" or "Refs #123" — leave blank if standalone -->

## Type

- [ ] Bug fix
- [ ] New emitter / feature
- [ ] Refactor / cleanup
- [ ] Docs
- [ ] Test / CI
- [ ] Chore (deps, build)
- [ ] Breaking change to the generator's output (please justify)

## Checklist

- [ ] `cargo test --lib` passes
- [ ] `cargo test --test integration_toml_walk` passes (if you touched output shape)
- [ ] `cargo clippy --lib --tests -- -D warnings` clean
- [ ] If output shape changed: regenerated a sample module locally and AST-parsed it
- [ ] If breaking: noted in `CHANGELOG.md` under `[Unreleased]`
