defmodule Boruta.Oauth.Authorization.ClientTest do
  use Boruta.DataCase

  import Boruta.Factory

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  alias Boruta.Oauth.Authorization.Client
  alias Boruta.Oauth.Error

  describe "authorize/1" do
    test "returns an error with bad auth method (client_secret_post)" do
      client = insert(:client, token_endpoint_auth_methods: ["client_secret_post"])
      source = %{type: "basic", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with POST body parameters."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")

      source = %{type: "jwt", value: "value"}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with POST body parameters."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad auth method (client_secret_basc)" do
      client = insert(:client, token_endpoint_auth_methods: ["client_secret_basic"])
      source = %{type: "post", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with BasicAuth."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")

      source = %{type: "jwt", value: "value"}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with BasicAuth."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad auth method (client_secret_jwt)" do
      client = insert(:client, token_endpoint_auth_methods: ["client_secret_jwt"])
      source = %{type: "post", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with a jwt assertion."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")

      source = %{type: "basic", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with a jwt assertion."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad auth method (private_key_jwt)" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "RS512",
          jwt_public_key: valid_public_key()
        )

      source = %{type: "post", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with a jwt assertion."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")

      source = %{type: "basic", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with a jwt assertion."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad auth method (private_key_jwt with bad configuration)" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "HS512",
          jwt_public_key: valid_public_key()
        )

      source = %{type: "jwt", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Bad client jwt authentication method configuration (jwks and token endpoint jwt auth algorithm do not match)."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "authorizes with post auth method" do
      client = insert(:client, token_endpoint_auth_methods: ["client_secret_post"])
      source = %{type: "post", value: client.secret}

      assert {:ok, _client} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "authorizes with basic auth method" do
      client = insert(:client, token_endpoint_auth_methods: ["client_secret_basic"])
      source = %{type: "basic", value: client.secret}

      assert {:ok, _client} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "authorizes with client secret jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["client_secret_jwt"],
          token_endpoint_jwt_auth_alg: "HS512"
        )

      signer = Joken.Signer.create("HS512", client.secret)
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)
      source = %{type: "jwt", value: client_assertion}

      assert {:ok, _client} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with nil client secret jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["client_secret_jwt"],
          token_endpoint_jwt_auth_alg: "HS512"
        )

      source = %{type: "jwt", value: nil}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description: "The given client secret jwt does not match signature key."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad client secret jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["client_secret_jwt"],
          token_endpoint_jwt_auth_alg: "HS512"
        )

      signer = Joken.Signer.create("HS512", "bad secret")
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)
      source = %{type: "jwt", value: client_assertion}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description: "The given client secret jwt does not match signature key."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "authorizes with private key jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "RS512",
          jwt_public_key: valid_public_key()
        )

      signer = Joken.Signer.create("RS512", %{"pem" => valid_private_key()})
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)
      source = %{type: "jwt", value: client_assertion}

      assert {:ok, _client} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "authorizes with private key jwt auth method with key rotation" do
      bypass = Bypass.open()
      jwks_uri = "http://localhost:#{bypass.port}/jwks"

      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "RS512",
          jwt_public_key: valid_public_key(),
          jwks_uri: jwks_uri
        )

      signer = Joken.Signer.create("RS512", %{"pem" => other_valid_private_key()})
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)
      source = %{type: "jwt", value: client_assertion}

      {_, jwk} = JOSE.JWK.from_pem(other_valid_public_key()) |> JOSE.JWK.to_map()
      jwk = Map.put(jwk, "alg", "RS512")
      Bypass.expect_once(bypass, "GET", "/jwks", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"keys" => [jwk]}))
      end)

      assert {:ok, _client} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with nil private key jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "RS512",
          jwt_public_key: valid_public_key()
        )

      source = %{type: "jwt", value: nil}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description: "The given client secret jwt does not match signature key."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad private key jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "RS512",
          jwt_public_key: valid_public_key()
        )

      signer = Joken.Signer.create("RS512", %{"pem" => invalid_private_key()})
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)
      source = %{type: "jwt", value: client_assertion}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description: "The given client secret jwt does not match signature key."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end
  end

  def valid_public_key do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def valid_private_key do
    "***REMOVED***\n\n"
  end

  def other_valid_private_key do
    "***REMOVED***\n"
  end

  def other_valid_public_key do
    "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAN0Mhw3A4JqMERW8ObFDLBYOMnmIDo3BJo9h8OYGlahXeCt1rvoNNHnN\no3lRy6nasZR4CE+brZHU9qq9Nukoyy6+qBddidwQ3Sh3T98GqCh8IEWh0F84i8ZA\noVXURCS+s4I/SbA7JjiS3zvwjUklk55fGm90jEArzF+JUH2LsSGFAgMBAAE=\n-----END RSA PUBLIC KEY-----\n"
  end

  def invalid_private_key do
    "***REMOVED***\n\n"
  end
end
