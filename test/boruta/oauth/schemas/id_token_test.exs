defmodule Boruta.Oauth.IdTokenTest do
  use ExUnit.Case
  import Mox

  alias Boruta.Oauth.Client
  alias Boruta.Oauth.IdToken
  alias Boruta.Oauth.Token

  setup :verify_on_exit!

  setup do
    claims = %{"resource_owner_claim" => "claim"}
    expect(Boruta.Support.ResourceOwners, :claims, fn (_sub, _scope) -> claims end)
    {:ok, claims: claims}
  end

  test "generates an id token with a code" do
    client = build_client()
    inserted_at = DateTime.utc_now()
    code = %Token{
      sub: "sub",
      client: client,
      value: "value",
      inserted_at: inserted_at,
      scope: "scope"
    }
    nonce = "nonce"

    assert %{
      sub: "sub",
      client: ^client,
      inserted_at: ^inserted_at,
      scope: "scope",
      value: value,
      type: "id_token"
    } = IdToken.generate(%{code: code}, nonce)

    signer = Joken.Signer.create("RS512", %{"pem" => client.private_key, "aud" => client.id})

    {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
    client_id = client.id

    assert %{
      "aud" => ^client_id,
      "iat" => _iat,
      "exp" => _exp,
      "sub" => "sub",
      "nonce" => ^nonce,
      "c_hash" => _c_hash,
      "resource_owner_claim" => "claim"
    } = claims
  end

  test "generates an id token with a token" do
    client = build_client()
    inserted_at = DateTime.utc_now()
    token = %Token{
      sub: "sub",
      client: client,
      value: "value",
      inserted_at: inserted_at,
      scope: "scope"
    }
    nonce = "nonce"

    assert %{
      sub: "sub",
      client: ^client,
      inserted_at: ^inserted_at,
      scope: "scope",
      value: value,
      type: "id_token"
    } = IdToken.generate(%{token: token}, nonce)

    signer = Joken.Signer.create("RS512", %{"pem" => client.private_key, "aud" => client.id})

    {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
    client_id = client.id

    assert %{
      "aud" => ^client_id,
      "iat" => _iat,
      "exp" => _exp,
      "sub" => "sub",
      "nonce" => ^nonce,
      "at_hash" => _at_hash,
      "resource_owner_claim" => "claim"
    } = claims
  end

  test "generates an id token with a token and a code" do
    client = build_client()
    inserted_at = DateTime.utc_now()
    code = %Token{
      sub: "sub",
      client: client,
      value: "code",
      inserted_at: inserted_at,
      scope: "scope"
    }
    token = %Token{
      sub: "sub",
      client: client,
      value: "token",
      inserted_at: inserted_at,
      scope: "scope"
    }
    nonce = "nonce"

    assert %{
      sub: "sub",
      client: ^client,
      inserted_at: ^inserted_at,
      scope: "scope",
      value: value,
      type: "id_token"
    } = IdToken.generate(%{token: token, code: code}, nonce)

    signer = Joken.Signer.create("RS512", %{"pem" => client.private_key, "aud" => client.id})

    {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
    client_id = client.id

    assert %{
      "aud" => ^client_id,
      "iat" => _iat,
      "exp" => _exp,
      "sub" => "sub",
      "nonce" => ^nonce,
      "at_hash" => _at_hash,
      "c_hash" => _c_hash,
      "resource_owner_claim" => "claim"
    } = claims
  end

  def build_client do
    %Client{
      id: "client_id",
      id_token_ttl: 10,
      private_key:
        "***REMOVED***\n\n",
    }
  end
end
