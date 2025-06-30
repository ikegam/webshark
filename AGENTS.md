# Codex Instructions

This repository is a Rust project. When modifying any code, run the following commands before committing:

```
cargo build --verbose
cargo test --verbose
```

If the `rustfmt` component is installed, also run:

```
cargo fmt -- --check
```

Include the commands' results in the Testing section of the PR message.
