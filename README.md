# KVage

Command line tool that keeps key-value pairs in a YAML file with every value
encrypted with [age](https://github.com/FiloSottile/age).

Website: https://www.sevir.org/kvage/

- Values are standard age files: anything kvage writes can be read with `age`.
- The store can be shared: encrypt for several people with a `public-keys.txt`
  and commit both files to git.
- The private key can be protected with a passphrase and unlocked once per
  session.
- Encrypted `.kvagerc` files load environment variables when you enter a
  directory.

## Install

Download a binary from the releases page, or build it (Go 1.26 or newer):

```bash
go build -o kvage ./src
```

## Quick start

```bash
kvage vault init          # create a passphrase-protected key
kvage set github_token    # asks for the value without echo
kvage get github_token
kvage list                # values masked
```

`vault init` puts the key in the kvage config directory
(`~/.config/kvage/key.txt` on Linux). To use a key somewhere else, pass
`--key <file>` or set `AGE_KEY_FILE`.

## Commands

Global flags:

```
-f, --file <file>   store file to use
-k, --key <file>    private key file to use
```

| Command | What it does |
|---|---|
| `kvage set <key> [value]` | Save a value. Alias: `up`. |
| `kvage get <key>` | Print a value. |
| `kvage list [--filter text] [--reveal]` | List keys with masked values. |
| `kvage search <pattern>` | Find keys by name (no decryption). |
| `kvage search --value [pattern]` | Find keys by value. |
| `kvage rm <key>` | Delete a key. |
| `kvage export [--filter text]` | Print `export NAME='value'` lines. |
| `kvage encrypt` / `kvage decrypt` | Encrypt or decrypt stdin to stdout. |
| `kvage rekey [--rc[=file]] [--no-store]` | Re-encrypt for the current recipients. |
| `kvage rc [file]` | Print the variables of a `.kvagerc` as exports. |
| `kvage shellrc` | Print the shell hook that loads `.kvagerc` files. |
| `kvage vault init` / `kvage vault passwd` | Protect the key with a passphrase. |
| `kvage unlock` / `kvage lock` / `kvage status` | Session control. |
| `kvage generate-key` | Write a new plain key to `./keys/key.txt`. |
| `kvage version` | Print the version. |

Errors go to stderr and make the command exit with a non-zero status.

### Setting values

```bash
kvage set db_password            # prompted, no echo
pass show db | kvage set db_password   # from stdin
kvage set db_password 's3cret'   # works, but warns: it stays in your shell history
```

### Listing and searching

`list` never prints full values unless you ask for them:

```
$ kvage list
db_password: s3****et
pin: ****
$ kvage list --reveal
```

A masked value shows two characters at each end (one for values of 4 or 5
characters, none below 4) around a fixed-width mask, so it does not reveal
the length.

`kvage search tok` matches key names, ignoring case, as a substring or as a
glob (`git*`). `kvage search --value` asks for the text to look for (it is
never taken from the command line) and lists the keys whose value contains
it, masked.

### Export

```bash
eval "$(kvage export --filter aws)"
```

Names are upper-cased and values are single-quoted. Keys whose name is not a
valid shell variable name are skipped with a warning.

## Where files are looked up

Each file is resolved on its own; the first place that has it wins.

| File | Order |
|---|---|
| Store | `--file`, `./.kvage/kvage.yaml`, `./kvage.yaml`, `<config>/kvage.yaml` |
| Private key | `--key`, `./.kvage/key.txt`, `AGE_KEY_FILE`, `<config>/key.txt` |
| Recipients | `public-keys.txt` in the same directory as the store |
| Settings | `<config>/config.yaml` only |

`<config>` is `~/.config/kvage` on Linux, `~/Library/Application Support/kvage`
on macOS and `%APPDATA%\kvage` on Windows. Only the current directory is
checked for `.kvage`, not its parents.

`kvage status` shows which files are in use and why.

Notes:

- An empty `.kvage/` directory changes nothing. To get a project store,
  create the file: `mkdir .kvage && touch .kvage/kvage.yaml`.
- A key in `./.kvage/key.txt` wins over `AGE_KEY_FILE`. `set` warns when it
  uses that key to write to a store outside `./.kvage`.
- The recipients list always comes from the directory of the store being
  written, so entering a project can never change who the values of your
  personal store are encrypted for. `encrypt` and `rekey --rc`, which work on
  project files, look at `./.kvage/public-keys.txt` first.
- `config.yaml` is never read from a project directory.

## Sharing a store (several recipients)

Put a `public-keys.txt` next to the store, one age public key per line:

```
# team
age1qy...   # alice
age1zx...   # bob
```

From then on `set` and `encrypt` encrypt for everyone listed, and `set` does
not need your private key at all. kvage warns when your own public key is not
in the list. Without the file, values are encrypted for your own key only.

After changing the list, re-encrypt what already exists:

```bash
kvage rekey            # the store
kvage rekey --rc       # the store and ./.kvagerc
kvage rekey --rc=path --no-store   # only that file
```

`rekey` writes nothing unless every value could be decrypted. The store and
`public-keys.txt` can then be committed to git, as with SOPS.

Removing someone from the list does not take back what they could already
read (they may have kept a copy of the store, and git keeps history). When
someone must lose access, change the secrets themselves.

A store written by this version can still be read by kvage v1.11.0 as long as
your key is one of the recipients.

## `.kvagerc`: environment variables per directory

A `.kvagerc` is an encrypted file with variable definitions:

```bash
cat > env.txt <<'END'
# comments are fine
export API_URL="https://api.example.com"
export API_TOKEN='s3cret'
CACHE_DIR=$HOME/.cache/myapp
END
kvage encrypt < env.txt > .kvagerc && rm env.txt
```

Install the hook once in your `~/.bashrc`:

```bash
echo 'eval "$(kvage shellrc)"' >> ~/.bashrc
```

When you enter a directory that has a `.kvagerc`, its variables are exported
into your shell. `kvage decrypt < .kvagerc` shows the content.

### Only variables, never code

age does not authenticate who encrypted a file: anyone who knows your public
key can create a `.kvagerc` that decrypts correctly. So the decrypted text is
never given to the shell. `kvage rc` parses it and prints only
`export NAME='value'` lines, and that is what the hook evaluates.

Accepted:

- `NAME=value` and `export NAME=value`, several per line
- `#` comments, blank lines
- `'single'` and `"double"` quotes, backslash escapes, values over several
  lines inside quotes
- `$VAR` and `${VAR}`, replaced by variables defined earlier in the file or
  taken from the environment; a leading `~` is your home directory

Ignored, with a warning that names the line but never its content: command
substitution (`$(...)`, backticks), `${VAR:-default}` and similar, `;`, `|`,
`&`, redirections, `alias`, functions, `source`, and any other command.

**Upgrading from v1.11.0:** files that only contain `export NAME=value` lines
keep working. Lines that ran commands, defined aliases or functions no longer
have any effect.

Variables that change how programs are found or loaded are not set either:
`PATH`, `LD_*`, `DYLD_*`, `PROMPT_COMMAND`, `BASH_ENV`, `ENV`, `IFS`,
`SHELLOPTS`, `HOME`, `SHELL`, `PS1`, `EDITOR`, `PAGER`, `GIT_SSH*`,
`GIT_CONFIG*`, `PYTHONPATH`, `NODE_OPTIONS`, `AGE_KEY_FILE` and a few more
(the full list is `rcBlockedNames` in `src/rc.go`). To allow some of them:

```yaml
# <config>/config.yaml
rc:
  allow: [PATH, "GIT_CONFIG*"]
```

Only allow `PATH` if you trust everyone who can write a `.kvagerc` into a
directory you enter.

## Protecting the private key

```bash
kvage vault init      # asks for a new passphrase twice
```

If you already have a key, `vault init` protects it in place: same key, same
public key, nothing to re-encrypt. Otherwise it creates a new one. The result
is the usual age identity file encrypted with a passphrase in the standard
age format, so:

- you can copy it to another machine and use it there with the passphrase;
- `age -d -i key.txt file.age` works with it;
- a copy of the file is useless without the passphrase.

The public key is saved next to it as `key.txt.pub`, so `set` can encrypt
without unlocking. `kvage vault passwd` changes the passphrase. A plain key
file keeps working; kvage reminds you to protect it when used from a
terminal (`key.warn_plaintext: false` in `config.yaml` turns that off).

There is no recovery for a forgotten passphrase. Protecting a key in place
does not erase older copies of the plain file (backups, other machines, old
disk blocks): if the plain key may have leaked, protect a **new** key and
`rekey`.

The passphrase is always asked for on the terminal, never read from stdin,
so `kvage decrypt < file` keeps working.

### Sessions

By default you type the passphrase once: the first command that needs the key
asks for it and starts a background agent (a `kvage` process) that keeps the
key in memory and decrypts for later commands.

```bash
kvage unlock    # optional: open the session explicitly
kvage status    # files in use, session state, agent protections
kvage lock      # forget the key and stop the agent
```

The session ends on `kvage lock`, when you log out, on reboot, or after the
inactivity timeout if you set one:

```yaml
# <config>/config.yaml
session:
  mode: session     # or "always": ask every time, no agent
  timeout: 30m      # lock after 30 minutes without use (default: none)
  tpm: auto         # auto | off | require (Linux, see below)
```

With the key locked, the `.kvagerc` hook does not ask for the passphrase on
every `cd`: it prints one line and loads nothing. Run `eval "$(kvage rc)"` to
unlock and load.

Sessions exist on Linux and macOS. On Windows the passphrase is asked for on
every command.

### TPM-guarded sessions (Linux)

On a Linux machine with a TPM 2.0, the agent does not keep the unlocked key
at all. On unlock it hands the key to the TPM, which holds it sealed for the
session, and keeps only a random authorization value. For each command the
key is unsealed, used for a few milliseconds and erased again.

- A memory image of the machine (hibernation file, swap, crash dump) taken
  while the session is open does not contain the key, and what it does
  contain is useless on any other machine or after a reboot.
- The session ends on reboot **and on hibernation**: the TPM forgets the
  sealed key when it is reset. Suspend to RAM keeps it.
- It costs one TPM operation per command, not per value: about 60 ms on the
  machine it was developed on, whether the command reads one value or all.
- The key file on disk is not tied to the TPM. It remains a normal
  passphrase-protected age key that you can copy and use elsewhere.

Your user needs access to `/dev/tpmrm0`, usually by being in the `tss` group
(`sudo usermod -aG tss "$USER"`, then log in again). `kvage status` shows
where the unlocked key is held. With `tpm: auto` (the default) kvage falls
back to keeping the key in the agent's memory when there is no usable TPM,
and `status` says why; `tpm: require` refuses to open a session instead;
`tpm: off` never uses the TPM.

This is protection for memory at rest, not against a live attacker: see the
limits below.

## Security: what is and is not protected

kvage protects secrets **at rest**: a copy of the store, of a `.kvagerc` or
of a passphrase-protected key file is useless without the passphrase (and,
for the store, without the key).

While a session is open, on Linux:

- the key is sealed in the TPM when there is one, otherwise it lives only in
  the agent's memory; either way it is not on disk in the clear;
- the agent cannot be ptraced or have its memory read by other programs of
  your user (`PR_SET_DUMPABLE=0`), produces no core dumps, and keeps its
  memory out of swap when `RLIMIT_MEMLOCK` allows it (`kvage status` tells);
- the agent only answers your user, and only the kvage executable.

Limits you should know:

- **Any program running as you can use an open session.** The executable
  check stops programs from talking to the agent directly, but nothing stops
  them from running `kvage get` themselves. An open session means "programs I
  run can read my secrets". Use `kvage lock`, a timeout, or
  `session.mode: always` when that matters.
- **root is not kept out.** root can read the agent's memory and take the
  key, capture your passphrase as you type it, or read values as they are
  decrypted. Nothing in kvage defends against a compromised root or kernel.
- **A TPM-guarded session changes none of the two points above.** Whoever
  can read the agent's memory (root) can take the authorization value and ask
  the TPM for the key, and any program of yours can still run `kvage get`.
  The key and that value also travel unencrypted between kvage and the TPM
  chip, so someone probing the TPM bus of a running, unlocked machine could
  read them.
- **Erasing memory is best effort.** Without a TPM-guarded session the key
  stays in the agent's memory until `lock` ends the process, so the memory of
  a hibernated machine, a crash dump or a VM snapshot taken while a session
  was open may contain it. With one, kvage erases every buffer the key
  passes through, but the Go runtime gives no hard guarantee that no copy
  survives.
- On macOS the agent checks only the user and applies no memory protection.
- Secrets passed as command line arguments (`kvage set key value`) are
  visible in your shell history and, briefly, to other users in the process
  list. Prefer the prompt or stdin.
- `list --reveal`, `get` and `export` print secrets to the terminal; they end
  up in your scrollback.

## Development

```bash
go test ./src          # tests use temporary directories and keys only
go vet ./src
bash scripts/build.sh  # release binaries for all platforms, into build/
```

See `AGENTS.md` for the layout and conventions.
