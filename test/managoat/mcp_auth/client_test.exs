defmodule Managoat.McpAuth.ClientTest do
  use ExUnit.Case, async: true

  alias Managoat.McpAuth.Client
  alias Managoat.McpAuth.Client.Config

  @redirect "https://client.example/cb"

  # A tenant-style provider: PKCE, the secret in the form, a userinfo
  # endpoint. The test helper's Req.Test plug answers every request.
  defp config(overrides \\ []) do
    Config.new(
      Keyword.merge(
        [
          authorize_url: "https://svc.example/oauth/authorize",
          token_url: "https://svc.example/oauth/token",
          userinfo_url: "https://svc.example/user",
          account_label_path: "login",
          scopes: ["read"],
          client_id: "cid",
          client_secret: "csec"
        ],
        overrides
      )
    )
  end

  defp query(url), do: url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

  defp form(req) do
    {:ok, body, _} = Plug.Conn.read_body(req)
    URI.decode_query(body)
  end

  describe "Config.new/1" do
    test "takes a keyword list or a map and refuses an unknown field" do
      assert %Config{client_id: "a", pkce: true} = Config.new(client_id: "a")
      assert %Config{client_id: "b", pkce: false} = Config.new(%{client_id: "b", pkce: false})
      assert_raise KeyError, fn -> Config.new(client_idd: "typo") end
    end
  end

  describe "configured?/1" do
    test "needs an id and a secret, or only an id for a public client" do
      assert Client.configured?(config())
      refute Client.configured?(config(client_secret: nil))
      refute Client.configured?(config(client_secret: ""))
      refute Client.configured?(config(client_id: nil))
      assert Client.configured?(config(client_secret: nil, token_endpoint_auth: "none"))
      refute Client.configured?(config(client_id: "", token_endpoint_auth: "none"))
    end
  end

  describe "authorize_url/4" do
    test "composes the standard parameters and a PKCE S256 challenge" do
      verifier = Client.code_verifier()
      assert String.length(verifier) in 43..128
      assert verifier =~ ~r/^[A-Za-z0-9_-]+$/

      url = Client.authorize_url(config(), @redirect, "st", verifier)
      assert String.starts_with?(url, "https://svc.example/oauth/authorize?")
      q = query(url)
      assert q["client_id"] == "cid"
      assert q["redirect_uri"] == @redirect
      assert q["response_type"] == "code"
      assert q["scope"] == "read"
      assert q["state"] == "st"
      assert q["code_challenge_method"] == "S256"

      assert q["code_challenge"] ==
               :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)

      refute Map.has_key?(q, "resource")
    end

    test "sends no challenge without a verifier, or when pkce is off" do
      refute Map.has_key?(
               query(Client.authorize_url(config(), @redirect, "st")),
               "code_challenge"
             )

      url = Client.authorize_url(config(pkce: false), @redirect, "st", "verifier")
      refute Map.has_key?(query(url), "code_challenge")
    end

    test "sends the RFC 8707 resource, and appends to an existing query string" do
      c =
        config(resource: "https://mcp.example/mcp", authorize_url: "https://a.example/o?tenant=t")

      url = Client.authorize_url(c, @redirect, "st")
      assert String.starts_with?(url, "https://a.example/o?tenant=t&")
      assert query(url)["resource"] == "https://mcp.example/mcp"

      refute Map.has_key?(
               query(Client.authorize_url(config(resource: ""), @redirect, "st")),
               "resource"
             )
    end

    test "authorize_params merge over the standard ones, so a provider may replace scope" do
      c =
        config(
          scopes: ["chat:write"],
          authorize_params: %{"user_scope" => "chat:write", "scope" => "", "prompt" => "consent"}
        )

      q = query(Client.authorize_url(c, @redirect, "st"))
      assert q["scope"] == ""
      assert q["user_scope"] == "chat:write"
      assert q["prompt"] == "consent"

      # A nil map is the same as none, and a nil client id is an empty one.
      q =
        query(
          Client.authorize_url(config(authorize_params: nil, client_id: nil), @redirect, "st")
        )

      assert q["client_id"] == ""
      assert q["scope"] == "read"
    end
  end

  describe "exchange_code/4 client authentication" do
    test "client_secret_post sends the id and secret in the form, with PKCE and the label" do
      verifier = Client.code_verifier()

      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/oauth/token" ->
            assert req.method == "POST"
            assert Plug.Conn.get_req_header(req, "accept") == ["application/json"]
            assert Plug.Conn.get_req_header(req, "authorization") == []
            f = form(req)
            assert f["grant_type"] == "authorization_code"
            assert f["code"] == "code"
            assert f["redirect_uri"] == @redirect
            assert f["code_verifier"] == verifier
            assert f["client_id"] == "cid"
            assert f["client_secret"] == "csec"
            refute Map.has_key?(f, "resource")

            Req.Test.json(req, %{
              "access_token" => "a-1",
              "refresh_token" => "r-1",
              "expires_in" => 3600,
              "scope" => "read write"
            })

          "/user" ->
            assert Plug.Conn.get_req_header(req, "authorization") == ["Bearer a-1"]
            Req.Test.json(req, %{"login" => "octocat"})
        end
      end)

      assert {:ok, grant} = Client.exchange_code(config(), "code", @redirect, verifier)
      assert grant.access_token == "a-1"
      assert grant.refresh_token == "r-1"
      assert grant.scopes == ["read", "write"]
      assert grant.account_email == "octocat"
      assert DateTime.diff(grant.expires_at, DateTime.utc_now()) in 3595..3600
    end

    test "client_secret_basic sends the credentials in the Authorization header only" do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/oauth/token" ->
            assert Plug.Conn.get_req_header(req, "authorization") == [
                     "Basic " <> Base.encode64("cid:csec")
                   ]

            f = form(req)
            refute Map.has_key?(f, "client_id")
            refute Map.has_key?(f, "client_secret")
            Req.Test.json(req, %{"access_token" => "a-1"})

          "/user" ->
            Req.Test.json(req, %{"login" => "octocat"})
        end
      end)

      c = config(token_endpoint_auth: "client_secret_basic")
      assert {:ok, %{access_token: "a-1"}} = Client.exchange_code(c, "code", @redirect)
    end

    test "a public client (none) sends its id in the form and no secret at all" do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/oauth/token" ->
            assert Plug.Conn.get_req_header(req, "authorization") == []
            f = form(req)
            assert f["client_id"] == "cid"
            refute Map.has_key?(f, "client_secret")
            Req.Test.json(req, %{"access_token" => "a-1"})

          "/user" ->
            Req.Test.json(req, %{"login" => "octocat"})
        end
      end)

      c = config(token_endpoint_auth: "none", client_secret: nil)
      assert {:ok, %{access_token: "a-1"}} = Client.exchange_code(c, "code", @redirect)

      # A public client with no id yet still sends the field, empty.
      Req.Test.stub(stub_name(), fn req ->
        assert form(req)["client_id"] == ""
        Req.Test.json(req, %{"access_token" => "a-2"})
      end)

      c = config(token_endpoint_auth: "none", client_id: nil, userinfo_url: nil)
      assert {:ok, %{access_token: "a-2"}} = Client.exchange_code(c, "code", @redirect)
    end

    test "a missing client id or secret is sent as empty rather than crashing" do
      Req.Test.stub(stub_name(), fn req ->
        f = form(req)
        assert f["client_id"] == ""
        assert f["client_secret"] == ""
        Req.Test.json(req, %{"access_token" => "a-1"})
      end)

      c = config(client_id: nil, client_secret: nil, userinfo_url: nil)
      assert {:ok, %{access_token: "a-1"}} = Client.exchange_code(c, "code", @redirect)
    end
  end

  describe "exchange_code/4 token responses" do
    test "GitHub's shape: a form-encoded body, no expiry, no refresh token, comma-separated scopes" do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/oauth/token" ->
            Plug.Conn.send_resp(
              req,
              200,
              "access_token=gho_1&scope=repo%2Cread%3Auser&token_type=bearer"
            )

          "/user" ->
            Req.Test.json(req, %{"data" => %{"login" => "octocat"}})
        end
      end)

      c = config(account_label_path: "data.login")
      assert {:ok, grant} = Client.exchange_code(c, "code", @redirect)
      assert grant.access_token == "gho_1"
      assert grant.account_email == "octocat"
      assert is_nil(grant.refresh_token)
      assert is_nil(grant.expires_at)
      assert grant.scopes == ["repo", "read:user"]
    end

    test "the token body nest lifts the grant to the top level, and is ignored when absent" do
      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{
          "ok" => true,
          "app_id" => "A1",
          "authed_user" => %{
            "id" => "U1",
            "access_token" => "xoxp-1",
            "scope" => "channels:history,chat:write",
            "token_type" => "user"
          }
        })
      end)

      c = config(token_body_nest: "authed_user", userinfo_url: nil)
      assert {:ok, grant} = Client.exchange_code(c, "code", @redirect)
      assert grant.access_token == "xoxp-1"
      assert grant.scopes == ~w(channels:history chat:write)
      assert grant.refresh_token == nil
      assert grant.account_email == nil

      # The nest names a key the body does not carry a grant under: read as it came.
      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{"access_token" => "top", "authed_user" => %{"id" => "U1"}})
      end)

      assert {:ok, %{access_token: "top"}} = Client.exchange_code(c, "code", @redirect)

      # No nest configured: a nested access_token is not the grant.
      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{
          "access_token" => "a",
          "expires_in" => 3600,
          "authed_user" => %{"access_token" => "b"}
        })
      end)

      c = config(userinfo_url: nil)
      assert {:ok, %{access_token: "a"}} = Client.exchange_code(c, "code", @redirect)
    end

    test "JSON that arrives without a JSON content type is still decoded" do
      Req.Test.stub(stub_name(), fn req ->
        Plug.Conn.send_resp(req, 200, ~s({"access_token":"a","scope":"read"}))
      end)

      c = config(userinfo_url: nil)

      assert {:ok, %{access_token: "a", scopes: ["read"]}} =
               Client.exchange_code(c, "code", @redirect)
    end

    test "a string expires_in is read; an unparsable one means no expiry" do
      Req.Test.stub(stub_name(), fn req ->
        Plug.Conn.send_resp(req, 200, "access_token=a&expires_in=120&refresh_token=r")
      end)

      c = config(userinfo_url: nil)
      assert {:ok, %{expires_at: at}} = Client.exchange_code(c, "code", @redirect)
      assert DateTime.diff(at, DateTime.utc_now()) in 115..120

      Req.Test.stub(stub_name(), fn req ->
        Plug.Conn.send_resp(req, 200, "access_token=a&expires_in=soon")
      end)

      assert {:ok, %{expires_at: nil}} = Client.exchange_code(c, "code", @redirect)
    end

    test "a scope the provider left out or emptied falls back to the config's" do
      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{"access_token" => "a", "scope" => ""})
      end)

      c = config(userinfo_url: nil, scopes: ["read", "write"])
      assert {:ok, %{scopes: ["read", "write"]}} = Client.exchange_code(c, "code", @redirect)
    end

    test "an error in a 200 body is an error, whatever the status" do
      c = config(userinfo_url: nil)

      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{"ok" => false, "error" => "invalid_refresh_token"})
      end)

      assert {:error, :invalid_grant} = Client.exchange_code(c, "code", @redirect)

      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{"ok" => "false", "error" => "ratelimited"})
      end)

      assert {:error, {:http, 200, %{"error" => "ratelimited"}}} =
               Client.exchange_code(c, "code", @redirect)

      Req.Test.stub(stub_name(), fn req ->
        Plug.Conn.send_resp(req, 200, "error=bad_refresh_token&error_description=x")
      end)

      assert {:error, :invalid_grant} = Client.exchange_code(c, "code", @redirect)

      # `ok: true` beside a token is a success, and an empty error is no error.
      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{"ok" => true, "error" => "", "access_token" => "a"})
      end)

      assert {:ok, %{access_token: "a"}} = Client.exchange_code(c, "code", @redirect)
    end

    test "a 2xx body with no token and no error is unexpected" do
      c = config(userinfo_url: nil)

      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{"token_type" => "bearer"})
      end)

      assert {:error, {:unexpected, %{"token_type" => "bearer"}}} =
               Client.exchange_code(c, "code", @redirect)

      # A body that is neither an object nor text cannot be a token response.
      Req.Test.stub(stub_name(), fn req -> Req.Test.json(req, [1, 2]) end)
      assert {:error, {:unexpected, [1, 2]}} = Client.exchange_code(c, "code", @redirect)
    end

    test "4xx answers: the invalid_grant aliases, other errors, and text bodies" do
      c = config(userinfo_url: nil)

      for alias_name <- ~w(invalid_grant bad_refresh_token invalid_refresh_token token_revoked) do
        Req.Test.stub(stub_name(), fn req ->
          req |> Plug.Conn.put_status(400) |> Req.Test.json(%{"error" => alias_name})
        end)

        assert {:error, :invalid_grant} = Client.exchange_code(c, "code", @redirect)
      end

      Req.Test.stub(stub_name(), fn req ->
        req |> Plug.Conn.put_status(401) |> Req.Test.json(%{"error" => "invalid_client"})
      end)

      assert {:error, {:http, 401, %{"error" => "invalid_client"}}} =
               Client.exchange_code(c, "code", @redirect)

      Req.Test.stub(stub_name(), fn req ->
        Plug.Conn.send_resp(req, 400, "error: invalid_grant (the code was used)")
      end)

      assert {:error, :invalid_grant} = Client.exchange_code(c, "code", @redirect)

      Req.Test.stub(stub_name(), fn req -> Plug.Conn.send_resp(req, 429, "slow down") end)
      assert {:error, {:http, 429, "slow down"}} = Client.exchange_code(c, "code", @redirect)

      Req.Test.stub(stub_name(), fn req ->
        req |> Plug.Conn.put_status(400) |> Req.Test.json([%{"error" => "invalid_grant"}])
      end)

      assert {:error, {:http, 400, [_]}} = Client.exchange_code(c, "code", @redirect)
    end

    test "a 5xx and a transport failure are reported as they came" do
      c = config(userinfo_url: nil)

      Req.Test.stub(stub_name(), fn req -> Plug.Conn.send_resp(req, 503, "down") end)
      assert {:error, {:http, 503, "down"}} = Client.exchange_code(c, "code", @redirect)

      Req.Test.stub(stub_name(), fn req -> Req.Test.transport_error(req, :econnrefused) end)

      assert {:error, %Req.TransportError{reason: :econnrefused}} =
               Client.exchange_code(c, "code", @redirect)
    end
  end

  describe "exchange_code/4 and require_refresh_token?" do
    test "insists on a refresh token only when the access token expires" do
      c = config(userinfo_url: nil, require_refresh_token?: true)

      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{"access_token" => "a", "expires_in" => 3600})
      end)

      assert {:error, :no_refresh_token} = Client.exchange_code(c, "code", @redirect)

      Req.Test.stub(stub_name(), fn req ->
        Plug.Conn.send_resp(req, 200, "access_token=a&expires_in=3600")
      end)

      assert {:error, :no_refresh_token} = Client.exchange_code(c, "code", @redirect)

      # Slack's shape: no expiry, no refresh token, good until revoked.
      Req.Test.stub(stub_name(), fn req -> Req.Test.json(req, %{"access_token" => "a"}) end)

      assert {:ok, %{refresh_token: nil, expires_at: nil}} =
               Client.exchange_code(c, "c", @redirect)

      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{"access_token" => "a", "expires_in" => 3600, "refresh_token" => "r"})
      end)

      assert {:ok, %{refresh_token: "r"}} = Client.exchange_code(c, "code", @redirect)
    end

    test "a config that does not insist takes an expiring token without one" do
      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{"access_token" => "a", "expires_in" => 3600})
      end)

      c = config(userinfo_url: nil)
      assert {:ok, %{refresh_token: nil}} = Client.exchange_code(c, "code", @redirect)
    end
  end

  describe "exchange_code/4 and the account label" do
    defp token_then(userinfo) do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/oauth/token" -> Req.Test.json(req, %{"access_token" => "a"})
          "/user" -> userinfo.(req)
        end
      end)
    end

    test "reads a dotted path through maps and lists, and an integer id" do
      token_then(&Req.Test.json(&1, %{"data" => %{"emails" => [%{"value" => "me@x.example"}]}}))
      c = config(account_label_path: "data.emails.0.value")
      assert {:ok, %{account_email: "me@x.example"}} = Client.exchange_code(c, "code", @redirect)

      token_then(&Req.Test.json(&1, %{"id" => 42}))
      c = config(account_label_path: "id")
      assert {:ok, %{account_email: "42"}} = Client.exchange_code(c, "code", @redirect)

      # No path configured: `email` is the default.
      token_then(&Req.Test.json(&1, %{"email" => "e@x.example"}))
      c = config(account_label_path: nil)
      assert {:ok, %{account_email: "e@x.example"}} = Client.exchange_code(c, "code", @redirect)
    end

    test "a body with nothing at the path is an error naming the path" do
      token_then(&Req.Test.json(&1, %{"login" => ""}))

      assert {:error, {:userinfo, :no_label, "login"}} =
               Client.exchange_code(config(), "c", @redirect)

      token_then(&Req.Test.json(&1, %{"data" => "flat"}))
      c = config(account_label_path: "data.login")

      assert {:error, {:userinfo, :no_label, "data.login"}} =
               Client.exchange_code(c, "c", @redirect)

      token_then(&Req.Test.json(&1, %{"list" => ["a"]}))
      c = config(account_label_path: "list.x")
      assert {:error, {:userinfo, :no_label, "list.x"}} = Client.exchange_code(c, "c", @redirect)
    end

    test "a userinfo failure is reported, and a non-object body is a failure" do
      token_then(&(&1 |> Plug.Conn.put_status(401) |> Req.Test.json(%{"message" => "bad"})))

      assert {:error, {:userinfo, 401, %{"message" => "bad"}}} =
               Client.exchange_code(config(), "c", @redirect)

      token_then(&Plug.Conn.send_resp(&1, 200, "octocat"))

      assert {:error, {:userinfo, 200, "octocat"}} =
               Client.exchange_code(config(), "c", @redirect)

      token_then(&Req.Test.transport_error(&1, :timeout))

      assert {:error, %Req.TransportError{reason: :timeout}} =
               Client.exchange_code(config(), "c", @redirect)
    end

    test "no userinfo URL leaves the label to the caller" do
      Req.Test.stub(stub_name(), fn req ->
        assert req.request_path == "/oauth/token"
        Req.Test.json(req, %{"access_token" => "a"})
      end)

      assert {:ok, %{account_email: nil}} =
               Client.exchange_code(config(userinfo_url: nil), "c", @redirect)

      assert {:ok, %{account_email: nil}} =
               Client.exchange_code(config(userinfo_url: ""), "c", @redirect)
    end
  end

  describe "dig/2" do
    test "walks maps and lists, and answers nil past the document" do
      body = %{"a" => [%{"b" => 1}, "x"], "n" => 2}
      assert Client.dig(body, "a.0.b") == 1
      assert Client.dig(body, "a.1") == "x"
      assert Client.dig(body, "a.9") == nil
      assert Client.dig(body, "a.b") == nil
      assert Client.dig(body, "n.deeper") == nil
      assert Client.dig(body, "missing") == nil
      assert Client.dig(body, "") == body
    end
  end

  describe "refresh/2" do
    test "rotates the refresh token when the provider sends a new one" do
      Req.Test.stub(stub_name(), fn req ->
        assert req.request_path == "/oauth/token"
        f = form(req)
        assert f["grant_type"] == "refresh_token"
        assert f["refresh_token"] == "r-1"
        assert f["client_id"] == "cid"
        assert f["client_secret"] == "csec"
        assert f["resource"] == "https://mcp.example/mcp"

        Req.Test.json(req, %{
          "access_token" => "a-new",
          "refresh_token" => "r-2",
          "expires_in" => 100
        })
      end)

      c = config(resource: "https://mcp.example/mcp")

      assert {:ok, %{access_token: "a-new", refresh_token: "r-2", expires_at: at}} =
               Client.refresh(c, "r-1")

      assert DateTime.diff(at, DateTime.utc_now()) in 95..100
    end

    test "keeps the old refresh token and reports no expiry when the provider says nothing" do
      Req.Test.stub(stub_name(), fn req ->
        refute Map.has_key?(form(req), "resource")
        Req.Test.json(req, %{"access_token" => "a-new"})
      end)

      assert {:ok, %{access_token: "a-new", refresh_token: nil, expires_at: nil}} =
               Client.refresh(config(), "r-1")
    end

    test "lifts a nested body, and reports invalid grants and other failures" do
      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{
          "ok" => true,
          "authed_user" => %{"access_token" => "x", "expires_in" => 5}
        })
      end)

      assert {:ok, %{access_token: "x"}} =
               Client.refresh(config(token_body_nest: "authed_user"), "r")

      Req.Test.stub(stub_name(), fn req ->
        req |> Plug.Conn.put_status(400) |> Req.Test.json(%{"error" => "invalid_grant"})
      end)

      assert {:error, :invalid_grant} = Client.refresh(config(), "r-1")

      Req.Test.stub(stub_name(), fn req ->
        Req.Test.json(req, %{"ok" => false, "error" => "token_revoked"})
      end)

      assert {:error, :invalid_grant} = Client.refresh(config(), "r-1")

      Req.Test.stub(stub_name(), fn req -> Req.Test.json(req, %{"token_type" => "bearer"}) end)

      assert {:error, {:unexpected, %{"token_type" => "bearer"}}} =
               Client.refresh(config(), "r-1")

      Req.Test.stub(stub_name(), fn req -> Plug.Conn.send_resp(req, 500, "") end)
      assert {:error, {:http, 500, ""}} = Client.refresh(config(), "r-1")
    end
  end

  describe "revoke/2" do
    test "posts the token to revoke_url with client auth; 2xx and 400 are both ok" do
      Req.Test.stub(stub_name(), fn req ->
        assert req.request_path == "/oauth/revoke"
        f = form(req)
        assert f["token"] == "r-1"
        assert f["client_id"] == "cid"
        assert f["client_secret"] == "csec"
        Req.Test.json(req, %{})
      end)

      c = config(revoke_url: "https://svc.example/oauth/revoke")
      assert :ok = Client.revoke(c, "r-1")

      Req.Test.stub(stub_name(), fn req ->
        req |> Plug.Conn.put_status(400) |> Req.Test.json(%{"error" => "invalid_token"})
      end)

      assert :ok = Client.revoke(c, "r-1")
    end

    test "basic auth goes in the header at the revoke endpoint too" do
      Req.Test.stub(stub_name(), fn req ->
        assert Plug.Conn.get_req_header(req, "authorization") == [
                 "Basic " <> Base.encode64("cid:csec")
               ]

        refute Map.has_key?(form(req), "client_secret")
        Plug.Conn.send_resp(req, 204, "")
      end)

      c =
        config(
          revoke_url: "https://svc.example/oauth/revoke",
          token_endpoint_auth: "client_secret_basic"
        )

      assert :ok = Client.revoke(c, "r-1")
    end

    test "any other failure is reported" do
      c = config(revoke_url: "https://svc.example/oauth/revoke")

      Req.Test.stub(stub_name(), fn req -> Plug.Conn.send_resp(req, 503, "down") end)
      assert {:error, {:http, 503, "down"}} = Client.revoke(c, "r-1")

      Req.Test.stub(stub_name(), fn req -> Req.Test.transport_error(req, :closed) end)
      assert {:error, %Req.TransportError{reason: :closed}} = Client.revoke(c, "r-1")
    end

    test "is local only without a revoke_url" do
      Req.Test.stub(stub_name(), fn _ -> flunk("no revoke_url, no call") end)
      assert :ok = Client.revoke(config(revoke_url: nil), "r-1")
      assert :ok = Client.revoke(config(revoke_url: ""), "r-1")
    end
  end

  describe "the URL guard" do
    # The test helper allows private hosts, so a URL that fails for a reason
    # other than resolution proves the guard ran: the scheme rule.
    test "refuses an unsafe token, userinfo or revoke URL before any request" do
      Req.Test.stub(stub_name(), fn _ -> flunk("an unsafe URL must not be fetched") end)

      c = config(token_url: "http://svc.example/oauth/token")
      assert {:error, {:unsafe_url, :not_https}} = Client.exchange_code(c, "code", @redirect)
      assert {:error, {:unsafe_url, :not_https}} = Client.refresh(c, "r-1")

      c = config(revoke_url: "https://10.0.0.1/revoke")
      assert {:error, {:unsafe_url, :ip_literal}} = Client.revoke(c, "r-1")

      Req.Test.stub(stub_name(), fn req ->
        assert req.request_path == "/oauth/token"
        Req.Test.json(req, %{"access_token" => "a"})
      end)

      c = config(userinfo_url: "https://localhost/user")
      assert {:error, {:unsafe_url, :internal_host}} = Client.exchange_code(c, "code", @redirect)
    end

    test "is skipped for trusted URLs" do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/oauth/token" -> Req.Test.json(req, %{"access_token" => "a"})
          "/user" -> Req.Test.json(req, %{"login" => "me"})
          "/revoke" -> Req.Test.json(req, %{})
        end
      end)

      c =
        config(
          trusted_urls?: true,
          token_url: "http://localhost/oauth/token",
          userinfo_url: "http://localhost/user",
          revoke_url: "http://localhost/revoke"
        )

      assert {:ok, %{access_token: "a", account_email: "me"}} =
               Client.exchange_code(c, "c", @redirect)

      assert {:ok, %{access_token: "a"}} = Client.refresh(c, "r-1")
      assert :ok = Client.revoke(c, "r-1")
    end
  end

  describe "Req settings" do
    test "the config's req_options and receive_timeout replace the library defaults" do
      # A private stub name: only a request built from this config reaches it.
      Req.Test.stub(ClientTest.Private, fn req ->
        Req.Test.json(req, %{"access_token" => "private"})
      end)

      c =
        config(
          userinfo_url: nil,
          req_options: [plug: {Req.Test, ClientTest.Private}],
          receive_timeout: 1
        )

      assert {:ok, %{access_token: "private"}} = Client.exchange_code(c, "code", @redirect)
    end
  end

  defp stub_name do
    {Req.Test, name} =
      :managoat_mcp_auth
      |> Application.fetch_env!(:req_options)
      |> Keyword.fetch!(:plug)

    name
  end
end
