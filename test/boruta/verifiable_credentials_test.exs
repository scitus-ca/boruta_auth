defmodule Boruta.VerifiableCredentialsTest do
  use ExUnit.Case

  alias Boruta.Config
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.VerifiableCredentials

  describe "issue_verifiable_credential/3" do
    setup do
      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{
        "aud" => Config.issuer(),
        "iat" => :os.system_time(:seconds)
      }, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      resource_owner = %ResourceOwner{sub: SecureRandom.uuid(), extra_claims: %{
        "firstname" => "firstname"
      }}

      credential_identifier = "credential_identifier"

      credential_configuration = %{
        claims: %{
          "credential_identifier" => ["firstname"]
        }
      }

      {:ok,
       proof: proof,
       resource_owner: resource_owner,
       credential_identifier: credential_identifier,
       credential_configuration: credential_configuration,
       signer: signer}
    end

    # test "verifies proof - prints the proof", %{proof: proof} do
    #   dbg(proof)
    #   dbg(Joken.peek_header(proof["proof"]))
    #   dbg(Joken.peek_claims(proof["proof"]))
    # end

    test "verifies proof - proof format", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               %{}
             ) ==
               {:error,
                "Proof validation failed. Required properties type, proof are missing at #."}
    end

    test "verifies proof - header claims", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      signer = Joken.Signer.create("HS256", "secret", %{})

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               proof
             ) ==
               {:error,
                "Proof JWT must be asymetrically signed, Proof JWT must have `openid4vci-proof+jwt` typ header, No proof key material found in JWT headers."}
    end

    test "verifies proof - the algorithm is asymetric", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      signer =
        Joken.Signer.create("HS256", "secret", %{"kid" => "kid", "typ" => "openid4vci-proof+jwt"})

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               proof
             ) == {:error, "Proof JWT must be asymetrically signed."}
    end

    test "verifies proof - typ header", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      signer = Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{"kid" => "kid"})

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               proof
             ) == {:error, "Proof JWT must have `openid4vci-proof+jwt` typ header."}
    end

    test "verifies proof - must have proof material", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               proof
             ) == {:error, "No proof key material found in JWT headers."}
    end

    test "verifies proof - must have required claims", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "typ" => "openid4vci-proof+jwt",
          "kid" => "kid"
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               proof
             ) ==
               {:error,
                "Proof does not contain valid JWT claims, `aud` and `iat` claims are required."}
    end

    # test "issues credential", %{
    #   proof: proof,
    #   resource_owner: resource_owner,
    #   credential_identifier: credential_identifier,
    #   credential_configuration: credential_configuration
    # } do
    #   assert VerifiableCredentials.issue_verifiable_credential(
    #            resource_owner,
    #            credential_identifier,
    #            credential_configuration,
    #            proof
    #          ) == proof
    #   # TODO issue credential
    # end
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def private_key_fixture do
    "***REMOVED***\n\n"
  end
end
