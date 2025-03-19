# publik

Private chats using public keys.

Publik aims to be an subset of IRC, replacing the "default permit" policy with invite only.
New users can be added by modifying the authorization file `authfile` either via the chat
interface or by editing it externally.

The `authfile` is the source of truth. Over multiple runs or reloads of the server, the state
of who is authorized is reflected in the `authfile`.

Though keys can be added via the chat interface, unless they are committed using the `/commit`
command, they will NOT persist on the subsequent runs or reload with `ctrl-r`.
