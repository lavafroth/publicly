# publik

Private chats using public keys.

Publik aims to be an subset of IRC, replacing the "default permit" policy with invite only.
New users can be added by modifying the authorization file `authfile` either via the chat
interface or by editing it externally.

The `authfile` is the source of truth. Over multiple runs or reloads of the server, the state
of who is authorized is reflected in the `authfile`.

Ephemeral keys can be added via the chat interface but unless the changes are committed using the `/commit`
command, the changes will NOT persist on the next run or when an admin performs a reload.
