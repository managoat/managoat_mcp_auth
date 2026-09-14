defmodule Managoat.McpAuth.Client.Config do
  @moduledoc """
  Everything `Managoat.McpAuth.Client` needs to know about one provider,
  as data. A host keeps its providers wherever it likes (a database row, a
  config file, the output of `Managoat.McpAuth.discover/1` plus
  `register/3`) and builds one of these at the moment it talks to the
  provider, with the plaintext `client_secret` already in hand.

  What varies per provider is a field here, never a clause in the client:

    * `authorize_url`, `token_url`, `revoke_url` (nil: revoke is local only),
      `userinfo_url` (nil: the client returns no account label).
    * `account_label_path` — a dotted path into the userinfo JSON
      (`"data.login"`, `"emails.0"`), defaulting to `"email"`.
    * `scopes` — what the authorize URL asks for and what the grant falls
      back to when the token response names none.
    * `client_id`, `client_secret`, `token_endpoint_auth` — one of
      `"client_secret_post"` (the default), `"client_secret_basic"` or
      `"none"` (a public client, `client_id` in the form and no secret).
    * `pkce` — send an S256 challenge when the caller supplies a verifier.
    * `resource` — the RFC 8707 resource an MCP token is bound to, sent on
      the authorize URL and every token request; nil when there is none.
    * `authorize_params` — extra authorize-URL parameters merged over the
      standard ones, so a provider may replace `scope` itself.
    * `token_body_nest` — the key under which the provider nests the user's
      grant in its token response (Slack: `"authed_user"`); the client lifts
      `access_token`, `refresh_token`, `expires_in` and `scope` from there
      to the RFC 6749 top level.
    * `trusted_urls?` — skip `Managoat.McpAuth.UrlGuard` because the URLs are
      the operator's own. False by default: a URL a tenant typed is checked
      again at the moment it is fetched, since DNS can change after a save.
    * `require_refresh_token?` — refuse a code exchange whose access token
      expires but comes with no refresh token. A connection like that is dead
      within the hour; a platform provider insists, a tenant provider takes
      what it gets.
    * `receive_timeout` and `req_options` — the `Req` settings for every
      request, replacing the library's `config :managoat_mcp_auth,
      timeout_ms: ..., req_options: ...` defaults when set. A host that
      stubs HTTP with `Req.Test` puts its plug here.
  """

  @type token_endpoint_auth :: String.t()

  @type t :: %__MODULE__{
          authorize_url: String.t() | nil,
          token_url: String.t() | nil,
          revoke_url: String.t() | nil,
          userinfo_url: String.t() | nil,
          account_label_path: String.t() | nil,
          scopes: [String.t()],
          client_id: String.t() | nil,
          client_secret: String.t() | nil,
          token_endpoint_auth: token_endpoint_auth(),
          pkce: boolean(),
          resource: String.t() | nil,
          authorize_params: %{optional(String.t()) => String.t()},
          token_body_nest: String.t() | nil,
          trusted_urls?: boolean(),
          require_refresh_token?: boolean(),
          receive_timeout: pos_integer() | nil,
          req_options: keyword() | nil
        }

  defstruct authorize_url: nil,
            token_url: nil,
            revoke_url: nil,
            userinfo_url: nil,
            account_label_path: nil,
            scopes: [],
            client_id: nil,
            client_secret: nil,
            token_endpoint_auth: "client_secret_post",
            pkce: true,
            resource: nil,
            authorize_params: %{},
            token_body_nest: nil,
            trusted_urls?: false,
            require_refresh_token?: false,
            receive_timeout: nil,
            req_options: nil

  @doc """
  Build a config from a keyword list or a map with atom keys. An unknown key
  raises, so a misspelt field is a crash at the call site rather than a
  provider silently driven with the default.
  """
  @spec new(keyword() | %{optional(atom()) => term()}) :: t()
  def new(attrs) when is_list(attrs) or is_map(attrs), do: struct!(__MODULE__, attrs)
end
