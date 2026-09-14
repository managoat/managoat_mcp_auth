# Managoat.McpAuth

The client side of MCP authorization: discovery, dynamic client
registration and the OAuth 2.0 authorization-code client, behind a
server-side URL guard.

The discovery chain follows the MCP authorization specification:

1. RFC 9728 protected-resource metadata comes from the MCP server's `401`
   challenge, its path-specific well-known URL, or the origin fallback.
2. RFC 8414 authorization-server metadata supplies the authorization, token,
   revocation, and optional registration endpoints. OpenID Connect's
   `openid-configuration` is the fallback.
3. RFC 7591 dynamic client registration creates a client when the server
   offers a registration endpoint.

Every fetched URL must use HTTPS, name a hostname rather than an IP literal,
and resolve without any loopback, private, link-local, CGNAT, or metadata
address. The guard applies to URLs returned by metadata too: a malicious
protected-resource document could otherwise point the next discovery request
at the cluster's metadata service.

```elixir
{:ok, metadata} = Managoat.McpAuth.discover("https://mcp.example/mcp")
opts = [client_name: "My client", client_uri: "https://client.example"]
{:ok, client} =
  Managoat.McpAuth.register(metadata, "https://client.example/callback", opts)
client["client_id"]
```

## The OAuth client

`Managoat.McpAuth.Client` runs the authorization-code flow the discovered
metadata (or any OAuth 2.0 provider a user configured) describes. Everything
that varies per provider is a field on `Managoat.McpAuth.Client.Config`;
the client names no service.

```elixir
alias Managoat.McpAuth.Client

config =
  Client.Config.new(
    authorize_url: metadata["authorization_endpoint"],
    token_url: metadata["token_endpoint"],
    revoke_url: metadata["revocation_endpoint"],
    scopes: metadata["scopes"],
    client_id: client["client_id"],
    client_secret: client["client_secret"],
    token_endpoint_auth: client["token_endpoint_auth"],
    resource: metadata["resource"]
  )

verifier = Client.code_verifier()
url = Client.authorize_url(config, "https://client.example/callback", state, verifier)
# ... send the user to `url`; the provider comes back with `code` ...
{:ok, grant} = Client.exchange_code(config, code, "https://client.example/callback", verifier)
grant.access_token
{:ok, fresh} = Client.refresh(config, grant.refresh_token)
:ok = Client.revoke(config, fresh.refresh_token || fresh.access_token)
```

`exchange_code/4` answers `{:error, :invalid_grant}` when the provider no
longer honours the code (also for GitHub's `bad_refresh_token` and Slack's
`invalid_refresh_token` / `token_revoked`, and for an error carried in a
200 body), `{:error, :no_refresh_token}` when `require_refresh_token?` is
set and an expiring token came without one, and
`{:error, {:unsafe_url, reason}}` when a URL failed the guard. A provider
that nests the user's grant in its token response (Slack's `authed_user`)
names the key in `token_body_nest`; `authorize_params` are merged over the
standard authorize parameters; `userinfo_url` with a dotted
`account_label_path` (`"data.login"`, `"emails.0"`) labels the account.
`trusted_urls?: true` skips the guard for URLs the operator owns.

The library reads optional defaults from its own application environment:
`config :managoat_mcp_auth, timeout_ms: 15_000, req_options: [],
allow_private_hosts: false`. A `Client.Config` carries its own
`receive_timeout` and `req_options`, which win over those defaults. Prefer
the `allow_private_hosts:` option on `Managoat.McpAuth.UrlGuard.check/2`
when a test only needs to bypass DNS resolution.

## Licence

Apache-2.0. See `LICENSE`.
