# publik

Private chats using public keys.

Publik aims to be an subset of IRC, replacing the "default permit" policy with "invite only".
New users can be added by modifying the authorization file `authfile` either via the chat
interface or by editing it externally.

### Roadmap

- [x] SSH authentication and authorization
- [x] Ability for admins to reload Authfile with `Ctrl` `r`
- [x] Emacs-like shortcuts for textarea
- [x] multiline support with `Alt` `Return`
- [ ] `/commit` command to commit in-memory changes to Authfile
- [ ] `/rename` command
- [ ] `#mention` tags
- [ ] Adjustable parameters like history size and Authfile paths

### Authfile

The `authfile` is the source of truth.

Though keys can be added via the chat interface, unless they are committed using the `/commit`
command, they will NOT persist on the subsequent runs or reload.

Consider the following keys added to `authfile`

```
ssh-ed25519 AAAA... bob@work
ssh-ed25519 AAAA... h@cafe:admin
```

The authfile intentionally uses the same format as the `~/.ssh/authorized_keys` file,
with the only difference is that it parses the last field, the comment. This will be used
to assign usernames.

For example, the first key has a comment `bob@work` which will be the username assigned to
people joining in with the respective privileges. Further, `bob@work` can join only with normal privileges.

`h@cafe`, whose comment is tagged as `:admin` will be able to join the chat with admin privileges.

> [!NOTE] Usernames can only contain ASCII alphanumeric characters and the `@`
symbol. All other characters will be stripped.

### Getting started

Create a file called `authfile` and add the SSH public keys of trusted members
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
