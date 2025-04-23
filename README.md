# publicly

Authenticate publicly, chat privately.

*Publicly* is a lean, *invite only* chat server over SSH connections.  

### Quickstart

Install *publicly* either by downloading a release or building from source.

```sh
cargo install --git https://github.com/lavafroth/publicly
```

Generate a keypair for the administrator.

```sh
ssh-keygen -f op -C "op:admin" -t ed25519 -N ""
mv op.pub Authfile
```

Deploy.

```sh
publicly
```

This binds to port 2222 on all interfaces. Members with the respective
private keys can join like so:

```sh
ssh 0.0.0.0 -p 2222 -oStrictHostKeyChecking=No -i op
```

Here, the private key file is named `op`.

### Roadmap

- [x] SSH authentication and authorization
- [x] Ability for admins to reload Authfile with `Ctrl` `r`
- [x] Emacs-like shortcuts for textarea
- [x] multiline support with `Alt` `Return`
- [x] Adjustable parameters:
  - [x] history size
  - [x] Authfile path
  - [x] Listening port number
- [x] `/add` command to add new keys
- [x] `/rename` command
- [x] `/commit` command to commit in-memory changes to Authfile
- [ ] `#mention` tags

### Authfile

The `Authfile` is the source of truth.

Keys can be added via the chat interface with the `/add` command
but they won't persist over multiple runs of the server
unless they are committed using the `/commit` command.

Consider the keys in the example `Authfile`

```
ssh-ed25519 AAAA... bob@work
ssh-ed25519 AAAA... h@cafe:admin
```

The Authfile intentionally uses the same format as the `~/.ssh/authorized_keys` file,
with the only difference being that it parses the last field, the comment, to assign usernames.

For example, the first key has a comment `bob@work` which will be the username assigned to
anyone joining with the respective key. Further, `bob@work` can join only with normal privileges.

`h@cafe`, whose comment is tagged as `:admin` will be able to join the chat with admin privileges.

> [!NOTE]
Usernames may only contain ASCII alphanumeric characters and the symbols `@-_.`.
All other characters will be stripped.
