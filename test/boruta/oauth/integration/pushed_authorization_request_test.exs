defmodule Boruta.OauthTest.PushedAuthorizationRequestTest do
  use Boruta.DataCase

  import Boruta.Factory

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  alias Boruta.Ecto.AuthorizationRequest
  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.PushedAuthorizationResponse
  alias Boruta.Repo

  describe "pushed authorization request - authorize" do
    setup do
      client = insert(:client, redirect_uris: ["https://redirect.uri"])

      confidential_client =
        insert(:client, redirect_uris: ["https://redirect.uri"], confidential: true)

      wildcard_redirect_uri_client = insert(:client, redirect_uris: ["https://*.uri"])
      pkce_client = insert(:client, pkce: true, redirect_uris: ["https://redirect.uri"])
      client_without_grant_type = insert(:client, supported_grant_types: [])

      client_with_scope =
        insert(:client,
          redirect_uris: ["https://redirect.uri"],
          authorize_scope: true,
          authorized_scopes: [
            insert(:scope, name: "public", public: true),
            insert(:scope, name: "private", public: false)
          ]
        )

      {:ok,
       client: client,
       confidential_client: confidential_client,
       wildcard_redirect_uri_client: wildcard_redirect_uri_client,
       client_with_scope: client_with_scope,
       client_without_grant_type: client_without_grant_type,
       pkce_client: pkce_client}
    end

    test "returns an error if `response_type` is 'code' and schema is invalid" do
      assert Oauth.pushed_authorization_request(
               %Plug.Conn{body_params: %{"response_type" => "code"}},
               ApplicationMock
             ) ==
               {:pushed_authorization_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Query params validation failed. Required properties client_id, redirect_uri are missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error if `client_id` is invalid" do
      assert Oauth.pushed_authorization_request(
               %Plug.Conn{
                 body_params: %{
                   "response_type" => "code",
                   "client_id" => "6a2f41a3-c54c-fce8-32d2-0324e1c32e22",
                   "redirect_uri" => "http://redirect.uri"
                 }
               },
               ApplicationMock
             ) ==
               {:pushed_authorization_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or redirect_uri.",
                  status: :unauthorized,
                  format: nil,
                  redirect_uri: nil
                }}
    end

    test "returns an error if `redirect_uri` is invalid", %{client: client} do
      assert Oauth.pushed_authorization_request(
               %Plug.Conn{
                 body_params: %{
                   "response_type" => "code",
                   "client_id" => client.id,
                   "redirect_uri" => "http://bad.redirect.uri"
                 }
               },
               ApplicationMock
             ) ==
               {:pushed_authorization_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or redirect_uri.",
                  status: :unauthorized,
                  format: nil,
                  redirect_uri: nil
                }}
    end

    test "returns an error with private scope", %{client: client} do
      given_scope = "private"
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.pushed_authorization_request(
               %Plug.Conn{
                 body_params: %{
                   "response_type" => "code",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "scope" => given_scope
                 }
               },
               ApplicationMock
             ) ==
               {:pushed_authorization_error,
                %Error{
                  error: :invalid_scope,
                  error_description: "Given scopes are unknown or unauthorized.",
                  status: :bad_request,
                  format: :json,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns an error if scope is unknown or unauthorized", %{
      client_with_scope: client
    } do
      given_scope = "bad_scope"
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.pushed_authorization_request(
               %Plug.Conn{
                 body_params: %{
                   "response_type" => "code",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "scope" => given_scope
                 }
               },
               ApplicationMock
             ) ==
               {:pushed_authorization_error,
                %Error{
                  error: :invalid_scope,
                  error_description: "Given scopes are unknown or unauthorized.",
                  format: :json,
                  redirect_uri: "https://redirect.uri",
                  status: :bad_request
                }}
    end

    test "returns an error if grant type is not allowed by client", %{
      client_without_grant_type: client
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.pushed_authorization_request(
               %Plug.Conn{
                 body_params: %{
                   "response_type" => "code",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "scope" => ""
                 }
               },
               ApplicationMock
             ) ==
               {:pushed_authorization_error,
                %Error{
                  error: :unsupported_grant_type,
                  error_description: "Client do not support given grant type.",
                  format: :json,
                  redirect_uri: redirect_uri,
                  status: :bad_request
                }}
    end

    test "returns an error with pkce client without code_challenge", %{
      pkce_client: client
    } do
      given_state = "state"
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.pushed_authorization_request(
               %Plug.Conn{
                 body_params: %{
                   "response_type" => "code",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "state" => given_state
                 }
               },
               ApplicationMock
             ) == {:pushed_authorization_error,
               %Boruta.Oauth.Error{
                 error: :invalid_request,
                 error_description: "Code challenge is invalid.",
                 format: :json,
                 redirect_uri: "https://redirect.uri",
                 status: :bad_request,
                 state: given_state
               }
             }
    end

    test "stores the request", %{
      client: client
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert {:request_stored,
              %PushedAuthorizationResponse{
                request_uri: request_uri,
                expires_in: expires_in
              }} =
               Oauth.pushed_authorization_request(
                 %Plug.Conn{
                   body_params: %{
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "state" => "state",
                     "code_challenge" => "code_challenge",
                     "code_challenge_method" => "plain"
                   }
                 },
                 ApplicationMock
               )

      assert [_, request_id] = Regex.run(~r/urn\:ietf\:params\:oauth\:request_uri\:(.+)/, request_uri)
      request = Repo.get(AuthorizationRequest, request_id)
      assert request.client_id
      assert expires_in
    end
  end

  def valid_public_key do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def valid_private_key do
    "***REMOVED***\n\n"
  end
end
