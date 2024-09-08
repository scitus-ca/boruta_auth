defmodule Boruta.VerifiablePresentationsTest do
  alias Boruta.VerifiablePresentations
  use ExUnit.Case

  describe "validate_presentation/3" do
    setup do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "kid" =>
            "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, expired_credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => 0
          },
          signer
        )

      {:ok, expired_vp_token, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "iss" =>
              "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
            "vp" => %{
              "verifiableCredential" => [expired_credential]
            }
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
              "test" => "pattern"
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

      {:ok, vp_token: vp_token, expired_vp_token: expired_vp_token}
    end

    test "returns invalid signautre", %{expired_vp_token: vp_token} do
      presentation_submission = %{
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
      }

      presentation_definition = %{
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

      assert VerifiablePresentations.validate_presentation(
               vp_token,
               presentation_submission,
               presentation_definition
             ) == {:error, "test is expired."}
    end

    test "returns ok", %{vp_token: vp_token} do
      presentation_submission = %{
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
      }

      presentation_definition = %{
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
                },
                %{
                  "path" => ["$.vc.test"],
                  "filter" => %{
                    "type" => "string",
                    "pattern" => "ttern"
                  }
                }
              ]
            }
          }
        ]
      }

      assert VerifiablePresentations.validate_presentation(
               vp_token,
               presentation_submission,
               presentation_definition
             ) == :ok
    end
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def private_key_fixture do
    "***REMOVED***\n\n"
  end
end
