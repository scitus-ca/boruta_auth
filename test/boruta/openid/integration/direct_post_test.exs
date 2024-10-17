defmodule Boruta.OpenidTest.DirectPostTest do
  use Boruta.DataCase

  import Boruta.Factory

  alias Boruta.ClientsAdapter
  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock
  alias Boruta.VerifiablePresentations

  describe "authenticates with direct post response" do
    setup do
      client = ClientsAdapter.public!()

      code =
        insert(:token,
          type: "code",
          redirect_uri: "http://redirect.uri",
          state: "state",
          sub:
            "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
          presentation_definition: %{
            "id" => "test",
            "format" => %{"jwt_vc" => %{"alg" => ["ES256'"]}, "jwt_vp" => %{"alg" => ["ES256"]}},
            "input_descriptors" => [
              %{
                "id" => "test",
                "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
                "constraints" => %{
                  "fields" => [
                    %{
                      "path" => ["$.vc.type"],
                      "filter" => %{
                        "type" => "array",
                        "contains" => %{"const" => "VerifiableAttestation"}
                      }
                    }
                  ]
                }
              }
            ]
          }
        )

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "kid" =>
            "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, id_token, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "iss" =>
              "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ"
          },
          signer
        )

      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => :os.system_time(:second) + 10,
            "vc" => %{
              "validFrom" => DateTime.utc_now() |> DateTime.add(-10) |> DateTime.to_iso8601(),
              "type" => ["VerifiableAttestation"],
            }
          },
          signer
        )

      {:ok, vp_token, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "iss" =>
              "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
            "vp" => %{
              "verifiableCredential" => [credential]
            }
          },
          signer
        )

      {:ok, client: client, code: code, id_token: id_token, vp_token: vp_token}
    end

    test "returns authentication failure without id_token" do
      conn = %Plug.Conn{}

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 status: :unauthorized,
                 error: :unauthorized,
                 error_description: "id_token or vp_token param missing."
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id"
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - returns not found with a bad id_token" do
      conn = %Plug.Conn{}

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :unauthorized,
                error: :unauthorized,
                error_description: "{:error, :token_malformed}"
              }} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id",
                   id_token: "bad_id_token"
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - returns not found with a bad code", %{id_token: id_token} do
      conn = %Plug.Conn{}

      assert {:code_not_found} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id",
                   id_token: id_token
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - retruns an error when code subject does not match", %{id_token: id_token} do
      code =
        insert(:token,
          type: "code",
          redirect_uri: "http://redirect.uri",
          state: "state",
          sub: "did:jwk:other"
        )

      conn = %Plug.Conn{}

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                status: :bad_request,
                error_description: "Code subject do not match with provided id_token or vp_token"
              }} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - authenticates", %{id_token: id_token, code: code} do
      conn = %Plug.Conn{}

      assert {:direct_post_success, callback_uri} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token
                 },
                 ApplicationMock
               )

      assert callback_uri =~ ~r/#{code.redirect_uri}/
      assert callback_uri =~ ~r/code=#{code.value}/
      assert callback_uri =~ ~r/state=#{code.state}/
    end

    test "oid4vp - returns not found with a bad id_token" do
      conn = %Plug.Conn{}

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :unauthorized,
                error: :unauthorized,
                error_description: "{:error, :token_malformed}"
              }} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id",
                   vp_token: "bad_vp_token"
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - returns not found with a bad code", %{vp_token: vp_token} do
      conn = %Plug.Conn{}

      assert {:code_not_found} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id",
                   vp_token: vp_token
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - retruns an error when code subject does not match", %{vp_token: vp_token} do
      code =
        insert(:token,
          type: "code",
          redirect_uri: "http://redirect.uri",
          state: "state",
          sub: "did:jwk:other"
        )

      conn = %Plug.Conn{}

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                status: :bad_request,
                error_description: "Code subject do not match with provided id_token or vp_token"
              }} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - authenticates", %{vp_token: vp_token, code: code} do
      conn = %Plug.Conn{}

      presentation_submission =
        Jason.encode!(%{
          "id" => "test",
          "definition_id" => "test",
          "descriptor_map" => [
            %{
              "id" => "test",
              "format" => "jwt_vp",
              "path" => "$",
              "path_nested" => %{
                "id" => "test",
                "format" => "jwt_vc",
                "path" => "$.vp.verifiableCredential[0]"
              }
            }
          ]
        })

      assert {:direct_post_success, callback_uri} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: presentation_submission
                 },
                 ApplicationMock
               )

      assert callback_uri =~ ~r/#{code.redirect_uri}/
      assert callback_uri =~ ~r/code=#{code.value}/
      assert callback_uri =~ ~r/state=#{code.state}/
    end
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def private_key_fixture do
    "***REMOVED***\n\n"
  end
end
