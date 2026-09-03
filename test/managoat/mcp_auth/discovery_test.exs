defmodule Managoat.McpAuth.DiscoveryTest do
  use ExUnit.Case, async: true

  alias Managoat.McpAuth

  # A conforming server: 401 with the challenge, the resource document, the
  # AS metadata with registration, and a registration endpoint that issues a
  # confidential client.
  defp conforming_server(req) do
    case {req.method, req.request_path} do
      {"GET", "/mcp"} ->
        req
        |> Plug.Conn.put_resp_header(
          "www-authenticate",
          ~s(Bearer resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/mcp")
        )
        |> Plug.Conn.send_resp(401, "")

      {"GET", "/.well-known/oauth-protected-resource/mcp"} ->
        Req.Test.json(req, %{
          "resource" => "https://mcp.example/mcp",
          "authorization_servers" => ["https://auth.example"],
          "scopes_supported" => ["mcp:tools"]
        })

      {"GET", "/.well-known/oauth-authorization-server"} ->
        Req.Test.json(req, %{
          "issuer" => "https://auth.example",
          "authorization_endpoint" => "https://auth.example/authorize",
          "token_endpoint" => "https://auth.example/token",
          "revocation_endpoint" => "https://auth.example/revoke",
          "registration_endpoint" => "https://auth.example/register",
          "code_challenge_methods_supported" => ["S256"],
          "token_endpoint_auth_methods_supported" => ["client_secret_post", "none"]
        })

      {"POST", "/register"} ->
        {:ok, body, _} = Plug.Conn.read_body(req)
        reg = Jason.decode!(body)
        assert reg["client_name"] == "Example client"
        assert reg["client_uri"] == "https://client.example"
        assert reg["redirect_uris"] == ["https://client.example/connections/x/callback"]
        assert reg["token_endpoint_auth_method"] == "client_secret_post"
        assert "refresh_token" in reg["grant_types"]

        req
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{
          "client_id" => "dcr-client",
          "client_secret" => "dcr-secret",
          "token_endpoint_auth_method" => "client_secret_post"
        })
    end
  end

  describe "discover/1" do
    test "follows the 401 challenge to the resource and authorization server metadata" do
      Req.Test.stub(stub_name(), &conforming_server/1)

      assert {:ok, md} = McpAuth.discover("https://mcp.example/mcp")
      assert md["issuer"] == "https://auth.example"
      assert md["authorization_endpoint"] == "https://auth.example/authorize"
      assert md["token_endpoint"] == "https://auth.example/token"
      assert md["revocation_endpoint"] == "https://auth.example/revoke"
      assert md["registration_endpoint"] == "https://auth.example/register"
      assert md["scopes"] == ["mcp:tools"]
      assert md["resource"] == "https://mcp.example/mcp"
    end

    test "falls back to the well-known path when the server names no resource metadata" do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/mcp" ->
            Plug.Conn.send_resp(req, 401, "")

          "/.well-known/oauth-protected-resource/mcp" ->
            Plug.Conn.send_resp(req, 404, "")

          "/.well-known/oauth-protected-resource" ->
            Req.Test.json(req, %{"authorization_servers" => ["https://auth.example/tenant"]})

          "/.well-known/oauth-authorization-server/tenant" ->
            Plug.Conn.send_resp(req, 404, "")

          "/tenant/.well-known/openid-configuration" ->
            Req.Test.json(req, %{
              "issuer" => "https://auth.example/tenant",
              "authorization_endpoint" => "https://auth.example/tenant/authorize",
              "token_endpoint" => "https://auth.example/tenant/token"
            })
        end
      end)

      assert {:ok, md} = McpAuth.discover("https://mcp.example/mcp")
      assert md["issuer"] == "https://auth.example/tenant"
      assert is_nil(md["registration_endpoint"])
      assert md["scopes"] == []
    end

    test "refuses a non-https server and a metadata chain that points somewhere private" do
      assert {:error, {:unsafe_url, _, :not_https}} =
               McpAuth.discover("http://mcp.example/mcp")

      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/mcp" ->
            req
            |> Plug.Conn.put_resp_header(
              "www-authenticate",
              ~s(Bearer resource_metadata="https://169.254.169.254/latest")
            )
            |> Plug.Conn.send_resp(401, "")
        end
      end)

      assert {:error, {:unsafe_url, "https://169.254.169.254/latest", :ip_literal}} =
               McpAuth.discover("https://mcp.example/mcp")
    end

    test "says so when the resource names no authorization server" do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/mcp" -> Plug.Conn.send_resp(req, 401, "")
          "/.well-known/oauth-protected-resource/mcp" -> Req.Test.json(req, %{"resource" => "x"})
        end
      end)

      assert {:error, :no_authorization_server} =
               McpAuth.discover("https://mcp.example/mcp")
    end

    test "a root resource uses the origin well-known path and accepts JSON text" do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/" ->
            Plug.Conn.send_resp(req, 200, "")

          "/.well-known/oauth-protected-resource" ->
            Plug.Conn.send_resp(
              req,
              200,
              Jason.encode!(%{"authorization_servers" => ["https://auth.example"]})
            )

          "/.well-known/oauth-authorization-server" ->
            Plug.Conn.send_resp(
              req,
              200,
              Jason.encode!(%{
                "authorization_endpoint" => "https://auth.example/authorize",
                "token_endpoint" => "https://auth.example/token",
                "scopes_supported" => ["server:scope"]
              })
            )
        end
      end)

      assert {:ok, md} = McpAuth.discover("https://mcp.example/")
      assert md["resource"] == "https://mcp.example/"
      assert md["issuer"] == "https://auth.example"
      assert md["scopes"] == ["server:scope"]
    end

    test "ignores unrelated authentication challenges" do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/mcp" ->
            req
            |> Plug.Conn.put_resp_header("www-authenticate", ~s(Basic realm="example"))
            |> Plug.Conn.send_resp(401, "")

          "/.well-known/oauth-protected-resource/mcp" ->
            Req.Test.json(req, %{"authorization_servers" => ["https://auth.example"]})

          "/.well-known/oauth-authorization-server" ->
            Req.Test.json(req, %{
              "authorization_endpoint" => "https://auth.example/authorize",
              "token_endpoint" => "https://auth.example/token"
            })
        end
      end)

      assert {:ok, _} = McpAuth.discover("https://mcp.example/mcp")
    end

    test "reports server status and transport failures" do
      Req.Test.stub(stub_name(), &Plug.Conn.send_resp(&1, 500, "failed"))
      assert {:error, {:mcp_server, 500}} = McpAuth.discover("https://mcp.example/mcp")

      Req.Test.stub(stub_name(), &Req.Test.transport_error(&1, :timeout))

      assert {:error, {:mcp_server, %Req.TransportError{reason: :timeout}}} =
               McpAuth.discover("https://mcp.example/mcp")
    end

    test "rejects invalid JSON and incomplete authorization metadata" do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/mcp" ->
            req
            |> Plug.Conn.put_resp_header(
              "www-authenticate",
              ~s(Bearer resource_metadata="https://mcp.example/bad-metadata")
            )
            |> Plug.Conn.send_resp(401, "")

          "/bad-metadata" ->
            Plug.Conn.send_resp(req, 200, "not json")
        end
      end)

      assert {:error, {:metadata, "https://mcp.example/bad-metadata", :not_json}} =
               McpAuth.discover("https://mcp.example/mcp")

      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/mcp" ->
            Plug.Conn.send_resp(req, 401, "")

          "/.well-known/oauth-protected-resource/mcp" ->
            Req.Test.json(req, %{"authorization_servers" => ["https://auth.example"]})

          "/.well-known/oauth-authorization-server" ->
            Req.Test.json(req, %{"authorization_endpoint" => "https://auth.example/authorize"})
        end
      end)

      assert {:error, :incomplete_authorization_server_metadata} =
               McpAuth.discover("https://mcp.example/mcp")
    end

    test "reports a transport failure while fetching metadata" do
      Req.Test.stub(stub_name(), fn req ->
        case req.request_path do
          "/mcp" ->
            req
            |> Plug.Conn.put_resp_header(
              "www-authenticate",
              ~s(Bearer resource_metadata="https://mcp.example/metadata")
            )
            |> Plug.Conn.send_resp(401, "")

          "/metadata" ->
            Req.Test.transport_error(req, :timeout)
        end
      end)

      assert {:error,
              {:metadata, "https://mcp.example/metadata", %Req.TransportError{reason: :timeout}}} =
               McpAuth.discover("https://mcp.example/mcp")
    end
  end

  describe "register/3" do
    test "registers a named client and reports the auth method" do
      Req.Test.stub(stub_name(), &conforming_server/1)
      {:ok, md} = McpAuth.discover("https://mcp.example/mcp")

      assert {:ok, client} =
               McpAuth.register(md, "https://client.example/connections/x/callback",
                 client_name: "Example client",
                 client_uri: "https://client.example"
               )

      assert client == %{
               "client_id" => "dcr-client",
               "client_secret" => "dcr-secret",
               "token_endpoint_auth" => "client_secret_post",
               "client_source" => "dcr"
             }

      assert {:error, :no_registration_endpoint} =
               McpAuth.register(%{}, "https://client.example/cb", [])
    end

    test "requires the client name and URI" do
      md = %{"registration_endpoint" => "https://auth.example/register"}

      assert_raise KeyError, fn ->
        McpAuth.register(md, "https://client.example/cb", client_uri: "https://client.example")
      end

      assert_raise KeyError, fn ->
        McpAuth.register(md, "https://client.example/cb", client_name: "Example client")
      end
    end

    test "negotiates public and basic clients from server capabilities" do
      Req.Test.stub(stub_name(), fn req ->
        {:ok, body, _} = Plug.Conn.read_body(req)
        registration = Jason.decode!(body)

        case registration["client_name"] do
          "Basic client" ->
            assert registration["token_endpoint_auth_method"] == "client_secret_basic"
            Req.Test.json(req, %{"client_id" => "basic", "client_secret" => "secret"})

          "Public client" ->
            assert registration["token_endpoint_auth_method"] == "none"
            Req.Test.json(req, %{"client_id" => "public"})
        end
      end)

      base = %{"registration_endpoint" => "https://auth.example/register", "scopes" => []}
      opts = [client_uri: "https://client.example"]

      assert {:ok, %{"token_endpoint_auth" => "client_secret_post"}} =
               McpAuth.register(
                 Map.put(base, "token_endpoint_auth_methods_supported", ["client_secret_basic"]),
                 "https://client.example/cb",
                 Keyword.put(opts, :client_name, "Basic client")
               )

      assert {:ok, %{"token_endpoint_auth" => "none", "client_secret" => nil}} =
               McpAuth.register(
                 Map.put(base, "token_endpoint_auth_methods_supported", ["none"]),
                 "https://client.example/cb",
                 Keyword.put(opts, :client_name, "Public client")
               )
    end

    test "defaults registration auth and reports HTTP and transport failures" do
      base = %{"registration_endpoint" => "https://auth.example/register", "scopes" => []}
      opts = [client_name: "Example", client_uri: "https://client.example"]

      Req.Test.stub(stub_name(), fn req ->
        {:ok, body, _} = Plug.Conn.read_body(req)
        assert Jason.decode!(body)["token_endpoint_auth_method"] == "client_secret_post"
        Req.Test.json(Plug.Conn.put_status(req, 422), %{"error" => "invalid_client"})
      end)

      assert {:error, {:registration, 422, %{"error" => "invalid_client"}}} =
               McpAuth.register(base, "https://client.example/cb", opts)

      Req.Test.stub(stub_name(), &Req.Test.transport_error(&1, :timeout))

      assert {:error, {:registration, %Req.TransportError{reason: :timeout}}} =
               McpAuth.register(base, "https://client.example/cb", opts)
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
