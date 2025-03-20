defmodule Boruta.OpenidTest.CredentialTest do
  alias Boruta.Openid.DeferedCredentialResponse
  use Boruta.DataCase

  import Boruta.Factory
  import Plug.Conn
  import Mox

  alias Boruta.Config
  alias Boruta.Ecto.Token
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock
  alias Boruta.Openid.CredentialResponse
  alias Boruta.Openid.VerifiableCredentials

  setup :verify_on_exit!

  describe "deliver verifiable credentials" do
    test "returns an error with no access token" do
      conn = %Plug.Conn{}

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                error_description: "Invalid bearer from Authorization header.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns credential_failure with a bad authorization header" do
      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "not a bearer")

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                error_description: "Invalid bearer from Authorization header.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns credential_failure with a bad access token" do
      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer bad_token")

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_access_token,
                error_description: "Given access token is invalid, revoked, or expired.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns an error with a valid bearer" do
      credential_params = %{}
      %Token{value: access_token} = insert(:token)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, %{}, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description:
                  "Request body validation failed. Required properties format, proof are missing at #."
                }}
    end

    test "returns an error with an invalid types" do
      credential_params = %{
        "credential_identifier" => "bad type",
        "format" => "jwt_vc",
        "proof" => %{"proof_type" => "jwt", "jwt" => ""}
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok, %ResourceOwner{sub: sub}}
      end)

      %Token{value: access_token} = insert(:token, sub: sub)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, %{}, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description: "Credential not found."
                }}
    end

    test "returns a credential" do
      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      credential_params = %{"format" => "jwt_vc", "proof" => proof, "credential_identifier" => "VerifiableCredential"}
      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{
             "family_name" => "family_name"
           }
         }}
      end)

      %Token{value: access_token} =
        insert(:token,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}]
        )

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_created,
                %CredentialResponse{
                  format: "jwt_vc",
                  credential: credential
                }} = Openid.credential(conn, credential_params, %{}, ApplicationMock)

      # TODO validate credential body
      assert credential
    end
  end

  describe "deliver defered verifiable credentials" do
    test "returns an error with no access token" do
      conn = %Plug.Conn{}

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                error_description: "Invalid bearer from Authorization header.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns credential_failure with a bad authorization header" do
      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "not a bearer")

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                error_description: "Invalid bearer from Authorization header.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns credential_failure with a bad access token" do
      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer bad_token")

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_access_token,
                error_description: "Given access token is invalid, revoked, or expired.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns an error with a valid bearer" do
      credential_params = %{}
      %Token{value: access_token} = insert(:token)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, %{}, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description:
                  "Request body validation failed. Required properties format, proof are missing at #."
                }}
    end

    test "returns an error with an invalid types" do
      credential_params = %{
        "credential_identifier" => "bad type",
        "format" => "jwt_vc",
        "proof" => %{"proof_type" => "jwt", "jwt" => ""}
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok, %ResourceOwner{sub: sub}}
      end)

      %Token{value: access_token} = insert(:token, sub: sub)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, %{}, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description: "Credential not found."
                }}
    end

    test "returns a defered credential response" do
      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      credential_params = %{"format" => "jwt_vc", "proof" => proof, "credential_identifier" => "VerifiableCredential"}
      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               defered: true,
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{
             "family_name" => "family_name"
           }
         }}
      end)

      %Token{value: access_token} =
        insert(:token,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}]
        )

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_created,
                %DeferedCredentialResponse{
                  acceptance_token: acceptance_token,
                }} = Openid.credential(conn, credential_params, %{}, ApplicationMock)

      assert acceptance_token
    end

    test "gets a defered credential" do
      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      credential_params = %{"format" => "jwt_vc", "proof" => proof, "credential_identifier" => "VerifiableCredential"}
      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               defered: true,
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{
             "family_name" => "family_name"
           }
         }}
      end)

      %Token{value: access_token} =
        insert(:token,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}]
        )

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_created,
                %DeferedCredentialResponse{
                  acceptance_token: acceptance_token,
                }} = Openid.credential(conn, credential_params, %{}, ApplicationMock)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{acceptance_token}")

      assert {:credential_created,
                %CredentialResponse{
                  credential: credential
                }} = Openid.defered_credential(conn, ApplicationMock)

      # TODO validate credential body
      assert credential
    end
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def private_key_fixture do
    "***REMOVED***\n\n"
  end
end
