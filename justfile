export RUST_BACKTRACE := "1"
alias s:= setup
alias h:= set-hooks
alias c:= clean
alias f:= format
alias l:= clippy  # l for lint

alias cov:= coverage

@setup:
    # rustup install nightly
    # cargo install cargo-tarpaulin
    rustup component add clippy-preview
    pip install pre-commit
    pip install maturin
    maturin build 
    just h
    cargo build

@clean:
    rm -rf target  dist  cobertura.xml

@set-hooks:
    bash ./scripts/conventional-commits
    bash ./scripts/pre-commit
    bash ./scripts/pre-push

@coverage:
    cargo +nightly tarpaulin --verbose --all-features --workspace --timeout 120 --out html


@format:
     cargo fmt

@clippy:
    cargo clippy -- -D warnings -A incomplete_features -W clippy::dbg_macro -W clippy::print_stdout
