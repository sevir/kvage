# AGENTS.md

Guide for coding agents working on kvage. Humans: see `README.md`.

## What this is

Go CLI (`package main` in `src/`) that stores key-value pairs in a YAML file
with age-encrypted values. Dependencies: cobra, `filippo.io/age`, yaml.v3,
`golang.org/x/term`, `golang.org/x/sys`, `filippo.io/edwards25519` (field
arithmetic only). The repository uses **jj**
(not colocated: there is no `.git` at the top level).

## Layout

```
src/
  main.go            root command, app struct, set/get/list/search/rm/export/encrypt/decrypt
  commands_rc.go     rc and rekey commands
  commands_vault.go  vault init/passwd, unlock, lock, status, hidden agent command
  paths.go           where store, key and recipients files are resolved
  store.go           YAML store load/save, atomic writes
  agetools.go        encrypt/decrypt helpers, generate-key
  recipients.go      public-keys.txt parsing, who to encrypt for
  rc.go              .kvagerc parser and the blocked variable names
  vault.go           passphrase-protected key file format, passphrase prompts
  keyring.go         keyring interface: local key or session agent
  agent_unix.go      session agent: protocol, server, client (linux, darwin)
  agent_linux.go     hardening and peer checks on Linux
  agent_darwin.go    the same on macOS (uid check only)
  agent_other.go     stubs for platforms without an agent (windows)
  keyslot.go         where the agent keeps an unlocked key: memory or TPM
  tpm_linux.go       TPM 2.0 sealed session key (hand-encoded commands)
  tpm_darwin.go      stub: no TPM
  x25519.go          erasable X25519 age identity, bech32
  tty_unix.go, tty_windows.go   passphrase prompt on the terminal
  userconfig.go      <config>/config.yaml
  textutil.go        masking, shell quoting, secret input
  config.go          per-OS config directory
  kvagerc.txt        the bash hook printed by `kvage shellrc` (embedded)
  *_test.go          tests
scripts/build.sh     release build for 6 targets; holds the version number
keys/                ignored by jj/git; may contain a REAL private key
build/               ignored; release artifacts
```

## Commands

```bash
go test ./src            # all tests
go test -race ./src      # run before finishing agent or keyring changes
sg tss -c 'go test ./src'   # also runs the tests that need the real TPM
go vet ./src
GOOS=windows go vet ./src && GOOS=darwin go vet ./src   # build tags compile
go build -o /tmp/kvage ./src
bash scripts/build.sh    # only when asked: rewrites build/
```

## Never touch

- `keys/key.txt` in this repository is a real private key. Do not print it,
  copy it, commit it or use it in tests.
- The user's real data: `~/.config/kvage/` (store, key, config) and any real
  `.kvagerc`. Never read values from them, never write to them.
- `~/bin/kvage` (the installed binary), releases, tags and `jj git push`
  need the owner's explicit go-ahead.

### Running binaries safely

Tests and manual checks must use a temporary `HOME`, a temporary
`XDG_RUNTIME_DIR` and throwaway keys.

**The v1.11.0 binary ignores `HOME`**: it finds the home directory through
`os/user`, so it writes to the real `~/.config/kvage/kvage.yaml` whatever the
environment says. When running an old binary for compatibility checks, always
pass `-f <temp store>` and `-k <temp key>`. The current code uses
`os.UserHomeDir`, which honours `HOME`.

## Compatibility rules

These must keep working without migration:

- The store format: a YAML document with one `data:` map of key to binary age
  value. No other top-level layout, no JSON.
- Plain key files as v1.11.0 wrote them, `AGE_KEY_FILE`, the `-f` and `-k`
  flags, every existing command and its output on stdout.
- Values and `.kvagerc` files encrypted by v1.11.0.
- A v1.11.0 binary must be able to read a store written now, as long as the
  user's key is among the recipients. Do not add fields or change how values
  are encoded.
- `eval "$(kvage shellrc)"` in `~/.bashrc` and the command name `shellrc`.

## Conventions

- Everything in the repository is in English.
- Commands are built by `newRootCmd(in, out, errw)` and use `a.in`, `a.out`,
  `a.errw`; never `os.Stdout` or `fmt.Print` directly, so tests can drive them.
- Commands return errors (`RunE`). `main` prints `Error: ...` to stderr and
  exits 1. stdout carries only the command's result.
- Warnings go through `a.warnf`. Error and warning text must never contain
  secret values or the content of a decrypted file.
- Secrets are not taken from command line arguments in new commands: use
  `a.readSecret` (stdin or no-echo prompt). Passphrases use `readPassphrase`,
  which reads from the terminal, never stdin.
- Files are written with `writeFileAtomic` (0600 in 0700 directories for new
  files, existing modes kept).
- Decrypting with the user's key goes through `a.keyring(...)`, never by
  loading the identity directly, so the passphrase and agent logic applies.
  Pass `noPrompt=true` from anything a shell hook runs.
- Platform-specific code lives in files with build tags; the build must pass
  for linux, darwin and windows on amd64 and arm64 with `CGO_ENABLED=0`.

## Security invariants

- The shell hook evaluates only the output of `kvage rc`, which is built from
  parsed assignments and `shellQuote`. Decrypted text must never reach `eval`.
- `rc.go` treats `.kvagerc` content as untrusted. Adding syntax to the parser
  needs a test in `TestParseRC` showing it cannot run a command.
- `config.yaml` is read only from the user's config directory. A project
  directory must not be able to change settings.
- The recipients list used for a store comes from that store's directory.
- The agent never returns the identity. Clients send ciphertexts and receive
  plaintexts.
- In the agent the private key only ever lives in buffers that kvage owns and
  erases (`keySlot.use`, `secretIdentity`). Do not convert it to a string,
  pass it through JSON, or hand it to a library that copies it: that is why
  `x25519.go` and `tpm_linux.go` exist instead of `crypto/ecdh` and a TPM
  library. Changes to `x25519.go` must keep `TestX25519RFC7748` and the
  comparison tests against `crypto/ecdh` and `filippo.io/age` passing.
- TPM tests skip themselves when `/dev/tpmrm0` cannot be opened. A change to
  `tpm_linux.go` is not verified until they have run on a machine with a TPM.
- Be accurate in the README about what is protected. The session agent does
  not defend against root, nor against other programs of the same user
  running kvage.

## Tests

- `newEnv(t)` gives a temporary HOME, working directory and key.
- `usePrompts(t, answers...)` answers passphrase prompts and counts them.
- `useAgent(t)` runs the agent inside the test process; `useRealAgent(t)`
  re-executes the test binary as a separate, hardened agent process.
- New behaviour needs a test. Changes to file resolution, the rc parser or
  the agent need tests for the unsafe case too.

## Releasing

The version lives in `scripts/build.sh` (`VERSION`). Bump it there; do not
tag or publish unless asked.
