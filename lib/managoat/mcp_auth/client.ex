defmodule Managoat.McpAuth.Client do
  @moduledoc """
  The OAuth 2.0 authorization-code client: the authorize URL, the code
  exchange, the refresh and the revoke, driven entirely by a
  `Managoat.McpAuth.Client.Config`. A plain client over `Req`; nothing here
  keeps state, and the config must already carry its plaintext
  `client_secret`.

  What differs per provider is data on the config, so this module names no
  service:

    * PKCE (S256) when `pkce` is set and the caller supplies a verifier; an
      MCP provider also sends its `resource` (RFC 8707) so the token is bound
      to the server the tenant named.
    * Client authentication at the token endpoint: `client_secret_post`,
      `client_secret_basic` or `none` (a public client).
    * Refresh: a response that carries a new refresh token rotates it; no
      `expires_in` means the access token does not expire; no refresh token
      at all means the token is good until it expires, and then gone.
    * Revoke: RFC 7009 at `revoke_url` when set; local only otherwise.
    * The account label: `userinfo_url` + `account_label_path`, or nothing,
      in which case the caller names the account.

  Every URL is checked by `Managoat.McpAuth.UrlGuard` at the moment it is
  fetched, not only when it was saved, unless the config marks its URLs as
  `trusted_urls?` (the operator's own).
  """

  alias Managoat.McpAuth.Client.Config
  alias Managoat.McpAuth.UrlGuard

  @type grant :: %{
          refresh_token: String.t() | nil,
          access_token: String.t(),
          expires_at: DateTime.t() | nil,
          scopes: [String.t()],
          account_email: String.t() | nil
        }

  @type refreshed :: %{
          access_token: String.t(),
          expires_at: DateTime.t() | nil,
          refresh_token: String.t() | nil
        }

  @doc "True when the config has a client to drive: an id, plus a secret unless the client is public."
  @spec configured?(Config.t()) :: boolean()
  def configured?(%Config{client_id: id, token_endpoint_auth: "none"}), do: present?(id)

  def configured?(%Config{client_id: id, client_secret: secret}),
    do: present?(id) and present?(secret)

  defp present?(v), do: is_binary(v) and v != ""

  @doc "A PKCE code verifier: 43 to 128 unreserved characters (RFC 7636)."
  @spec code_verifier() :: String.t()
  def code_verifier, do: Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false)

  @doc """
  Where to send the user. `verifier` is the PKCE verifier the caller keeps
  in its session, or nil for no PKCE. `authorize_params` are merged over
  the standard parameters, so a provider may override `scope` itself.
  """
  @spec authorize_url(Config.t(), String.t(), String.t(), String.t() | nil) :: String.t()
  def authorize_url(%Config{} = c, redirect_uri, state, verifier \\ nil)
      when is_binary(redirect_uri) and is_binary(state) do
    base = %{
      "client_id" => c.client_id || "",
      "redirect_uri" => redirect_uri,
      "response_type" => "code",
      "scope" => Enum.join(c.scopes, " "),
      "state" => state
    }

    query =
      base
      |> Map.merge(c.authorize_params || %{})
      |> Map.merge(pkce_params(c, verifier))
      |> Map.merge(resource_params(c))
      |> URI.encode_query()

    join = if String.contains?(c.authorize_url, "?"), do: "&", else: "?"
    c.authorize_url <> join <> query
  end

  defp pkce_params(%Config{pkce: true}, verifier) when is_binary(verifier) do
    challenge = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)
    %{"code_challenge" => challenge, "code_challenge_method" => "S256"}
  end

  defp pkce_params(_, _), do: %{}

  defp resource_params(%Config{resource: r}) when is_binary(r) and r != "", do: %{"resource" => r}
  defp resource_params(_), do: %{}

  @doc """
  Exchange the code from the callback for tokens: `{:ok, grant}`. The grant
  has no `refresh_token` when the provider issued none, no `expires_at` when
  it said nothing about expiry, and no `account_email` when the config
  has no userinfo endpoint — the caller labels the account then.

  `{:error, :no_refresh_token}` when `require_refresh_token?` is set and an
  expiring token came without one; `{:error, :invalid_grant}` when the
  provider rejected the code; `{:error, {:unsafe_url, reason}}` when a URL
  failed the guard; `{:error, {:http, status, body}}` otherwise.
  """
  @spec exchange_code(Config.t(), String.t(), String.t(), String.t() | nil) ::
          {:ok, grant()} | {:error, term()}
  def exchange_code(%Config{} = c, code, redirect_uri, verifier \\ nil)
      when is_binary(code) and is_binary(redirect_uri) do
    form =
      %{
        "code" => code,
        "redirect_uri" => redirect_uri,
        "grant_type" => "authorization_code"
      }
      |> maybe_put("code_verifier", verifier)
      |> maybe_put("resource", c.resource)

    with {:ok, %{"access_token" => access} = body} when is_binary(access) <-
           token_request(c, form),
         :ok <- require_refresh_token(c, body),
         {:ok, label} <- account_label(c, access) do
      {:ok,
       %{
         refresh_token: refresh_token(body),
         access_token: access,
         expires_at: expires_at(body["expires_in"]),
         scopes: scopes(body["scope"], c.scopes),
         account_email: label
       }}
    else
      {:ok, other} -> {:error, {:unexpected, other}}
      {:error, _} = err -> err
    end
  end

  # Google issues an hour-long access token and, on a repeat consent, no
  # refresh token unless the user removes the app first: a connection
  # without one would be dead in an hour, so a provider that insists refuses
  # it — but only when the token expires at all. Slack's user tokens carry
  # no expiry and no refresh token unless the app opts in to rotation, and
  # are good until revoked. A config that does not insist takes what it
  # gets; a missing refresh token there is the provider's design, and the
  # token is simply gone when it expires.
  defp require_refresh_token(%Config{require_refresh_token?: true}, body) do
    expiring? = is_integer(body["expires_in"]) or is_binary(body["expires_in"])

    if is_binary(refresh_token(body)) or not expiring?,
      do: :ok,
      else: {:error, :no_refresh_token}
  end

  defp require_refresh_token(_c, _body), do: :ok

  @doc """
  A fresh access token for a refresh token: `{:ok, %{access_token,
  expires_at, refresh_token}}` (the last only when the provider rotated
  it), `{:error, :invalid_grant}` when the provider has forgotten the grant,
  or `{:error, reason}`.
  """
  @spec refresh(Config.t(), String.t()) :: {:ok, refreshed()} | {:error, term()}
  def refresh(%Config{} = c, refresh_token) when is_binary(refresh_token) do
    form =
      %{"refresh_token" => refresh_token, "grant_type" => "refresh_token"}
      |> maybe_put("resource", c.resource)

    case token_request(c, form) do
      {:ok, %{"access_token" => access} = body} when is_binary(access) ->
        {:ok,
         %{
           access_token: access,
           expires_at: expires_at(body["expires_in"]),
           refresh_token: refresh_token(body)
         }}

      {:ok, other} ->
        {:error, {:unexpected, other}}

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Tell the provider to forget the grant (RFC 7009). Best effort: an
  already-revoked token is a 400 there and `:ok` here, because the outcome
  is the same; a config with no `revoke_url` is `:ok` at once.
  """
  @spec revoke(Config.t(), String.t()) :: :ok | {:error, term()}
  def revoke(%Config{revoke_url: nil}, _token), do: :ok
  def revoke(%Config{revoke_url: ""}, _token), do: :ok

  def revoke(%Config{} = c, token) when is_binary(token) do
    with :ok <- guard(c, c.revoke_url) do
      {form, opts} = client_auth(c, %{"token" => token})

      case Req.post(req(c), [url: c.revoke_url, form: form] ++ opts) do
        {:ok, %{status: status}} when status in 200..299 -> :ok
        {:ok, %{status: 400}} -> :ok
        {:ok, %{status: status, body: body}} -> {:error, {:http, status, body}}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # ── the token endpoint ─────────────────────────────────────────────────────

  defp token_request(c, form) do
    with :ok <- guard(c, c.token_url) do
      {form, opts} = client_auth(c, form)

      case Req.post(
             req(c),
             [url: c.token_url, form: form, headers: [accept: "application/json"]] ++ opts
           ) do
        {:ok, %{status: status, body: body}} when status in 200..299 ->
          case decode_token_body(body) do
            {:ok, decoded} ->
              # Reshaped before the error check: a nested success body has no
              # top-level access_token until the grant is lifted out.
              decoded = normalize_token_body(c, decoded)
              if error_body?(decoded), do: token_error(status, decoded), else: {:ok, decoded}

            {:error, _} = err ->
              err
          end

        {:ok, %{status: status, body: body}} when status in 400..499 ->
          token_error(status, body)

        {:ok, %{status: status, body: body}} ->
          {:error, {:http, status, body}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # A provider's token response, reshaped to the RFC 6749 top level where
  # the provider nests it under `token_body_nest` (Slack: `authed_user`).
  defp normalize_token_body(%Config{token_body_nest: key}, body)
       when is_binary(key) and key != "" do
    case body do
      %{^key => %{"access_token" => _} = nested} ->
        Map.merge(body, Map.take(nested, ~w(access_token refresh_token expires_in scope)))

      _ ->
        body
    end
  end

  defp normalize_token_body(_c, body), do: body

  # Not every provider signals failure on the status line: Slack answers
  # HTTP 200 with `{"ok": false, "error": "invalid_refresh_token"}` and says
  # to inspect `ok`; GitHub answers 200 with `error=bad_refresh_token`. A
  # body that carries an error and no token is an error, whatever the status.
  defp error_body?(%{"access_token" => access}) when is_binary(access) and access != "", do: false
  defp error_body?(%{"ok" => ok}) when ok in [false, "false"], do: true
  defp error_body?(%{"error" => e}) when is_binary(e) and e != "", do: true
  defp error_body?(_), do: false

  defp token_error(status, body) do
    if invalid_grant?(body), do: {:error, :invalid_grant}, else: {:error, {:http, status, body}}
  end

  # GitHub answers a form-encoded body unless asked for JSON, and some
  # providers ignore the Accept header altogether.
  defp decode_token_body(body) when is_map(body), do: {:ok, body}

  defp decode_token_body(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, map} when is_map(map) -> {:ok, map}
      _ -> {:ok, URI.decode_query(body)}
    end
  end

  defp decode_token_body(other), do: {:error, {:unexpected, other}}

  # `invalid_grant` is the RFC 6749 shape; GitHub says `bad_refresh_token`
  # and Slack `invalid_refresh_token` / `token_revoked`. All mean the same:
  # the provider no longer honours this grant.
  defp invalid_grant?(%{"error" => e}) when is_binary(e),
    do: e in ~w(invalid_grant bad_refresh_token invalid_refresh_token token_revoked)

  defp invalid_grant?(body) when is_binary(body),
    do: String.contains?(body, "invalid_grant") or String.contains?(body, "bad_refresh_token")

  defp invalid_grant?(_), do: false

  defp client_auth(%Config{token_endpoint_auth: "client_secret_basic"} = c, form),
    do: {form, [auth: {:basic, "#{c.client_id}:#{c.client_secret}"}]}

  defp client_auth(%Config{token_endpoint_auth: "none"} = c, form),
    do: {Map.put(form, "client_id", c.client_id || ""), []}

  defp client_auth(c, form) do
    {Map.merge(form, %{"client_id" => c.client_id || "", "client_secret" => c.client_secret || ""}),
     []}
  end

  # ── the account label ──────────────────────────────────────────────────────

  defp account_label(%Config{userinfo_url: url} = c, access)
       when is_binary(url) and url != "" do
    with :ok <- guard(c, url) do
      case Req.get(req(c),
             url: url,
             auth: {:bearer, access},
             headers: [accept: "application/json"]
           ) do
        {:ok, %{status: 200, body: body}} when is_map(body) ->
          case dig(body, c.account_label_path || "email") do
            label when is_binary(label) and label != "" -> {:ok, label}
            number when is_integer(number) -> {:ok, Integer.to_string(number)}
            _ -> {:error, {:userinfo, :no_label, c.account_label_path}}
          end

        {:ok, %{status: status, body: body}} ->
          {:error, {:userinfo, status, body}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp account_label(_c, _access), do: {:ok, nil}

  @doc """
  Walk a decoded JSON body along a dotted path: a key into a map, an
  integer into a list. `"data.emails.0"` on `%{"data" => %{"emails" =>
  ["a@x"]}}` is `"a@x"`; a path that leaves the document is nil.
  """
  @spec dig(map(), String.t()) :: term()
  def dig(body, path) when is_map(body) and is_binary(path) do
    path
    |> String.split(".", trim: true)
    |> Enum.reduce_while(body, fn key, acc ->
      case acc do
        %{} = m -> {:cont, Map.get(m, key)}
        list when is_list(list) -> {:cont, index(list, key)}
        _ -> {:halt, nil}
      end
    end)
  end

  defp index(list, key) do
    case Integer.parse(key) do
      {i, ""} -> Enum.at(list, i)
      _ -> nil
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────

  # The operator's own URLs are trusted; anyone else's are checked on every
  # fetch, since DNS can change between a save and a request.
  defp guard(%Config{trusted_urls?: true}, _url), do: :ok

  defp guard(_c, url) do
    case UrlGuard.check(url) do
      :ok -> :ok
      {:error, reason} -> {:error, {:unsafe_url, reason}}
    end
  end

  defp refresh_token(%{"refresh_token" => r}) when is_binary(r) and r != "", do: r
  defp refresh_token(_), do: nil

  defp scopes(scope, _default) when is_binary(scope) and scope != "",
    do: String.split(scope, ~r/[ ,]+/, trim: true)

  defp scopes(_, default), do: default

  defp expires_at(ttl) when is_integer(ttl) and ttl > 0,
    do: DateTime.utc_now() |> DateTime.add(ttl, :second) |> DateTime.truncate(:second)

  defp expires_at(ttl) when is_binary(ttl) do
    case Integer.parse(ttl) do
      {n, ""} -> expires_at(n)
      _ -> nil
    end
  end

  defp expires_at(_), do: nil

  defp maybe_put(map, _k, nil), do: map
  defp maybe_put(map, k, v), do: Map.put(map, k, v)

  # The config's Req settings win; the library's own application env is the
  # fallback, the same keys `Managoat.McpAuth.Discovery` reads.
  defp req(%Config{} = c) do
    Req.new(
      [
        receive_timeout:
          c.receive_timeout || Application.get_env(:managoat_mcp_auth, :timeout_ms, 15_000),
        retry: false,
        redirect: false
      ] ++ (c.req_options || Application.get_env(:managoat_mcp_auth, :req_options, []))
    )
  end
end
