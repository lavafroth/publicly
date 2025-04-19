# publicly

Authenticate publicly, chat privately.

*Publicly* aims to mirror a subset of IRC, replacing the "default permit" policy with "invite only".

New users can be added by modifying the authorization file `Authfile` either via the chat
interface or by editing it externally.

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

Keys can be added via the chat interface but they won't persist over multiple runs of the server
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

### Getting started

Create a file called `Authfile` and add the SSH public keys of trusted members
as described in the previous section.

Inside the project directory run

```sh
cargo r
```

This binds to localhost on port 2222 over all interfaces. Members with the respective
private keys will now be able to SSH as

```sh
ssh 0.0.0.0 -p 2222 -oStrictHostKeyChecking=No
```
