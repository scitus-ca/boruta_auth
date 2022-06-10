defmodule Boruta.Oauth.IdTokenTest do
  use ExUnit.Case
  import Mox

  alias Boruta.Oauth.Client
  alias Boruta.Oauth.IdToken
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  setup :verify_on_exit!

  setup do
    sub = "resource_owner_sub"
    resource_owner = %ResourceOwner{sub: sub}
    claims = %{"resource_owner_claim" => "claim"}

    stub(Boruta.Support.ResourceOwners, :claims, fn %ResourceOwner{sub: ^sub}, _scope ->
      claims
    end)

    {:ok, resource_owner: resource_owner, claims: claims}
  end

  test "generates an id token with a code", %{resource_owner: resource_owner} do
    client = build_client()
    inserted_at = DateTime.utc_now()
    last_login_at = DateTime.utc_now()
    resource_owner = %{resource_owner | last_login_at: last_login_at}

    code = %Token{
      type: "code",
      sub: "sub",
      client: client,
      value: "value",
      inserted_at: inserted_at,
      resource_owner: resource_owner,
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

    assert {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
    client_id = client.id
    assert {:ok, %{"kid" => ^client_id}} = Joken.peek_header(value)
    auth_time = DateTime.to_unix(last_login_at)

    assert %{
             "aud" => ^client_id,
             "iat" => _iat,
             "exp" => _exp,
             "sub" => "sub",
             "nonce" => ^nonce,
             "c_hash" => c_hash,
             "auth_time" => ^auth_time,
             "resource_owner_claim" => "claim"
           } = claims

    assert c_hash == "7CyD7ey2AwTRVOvbhb369hqSvRQuccT3sloVuctfPAo"
  end

  test "generates an id token with a token", %{resource_owner: resource_owner} do
    client = build_client()
    inserted_at = DateTime.utc_now()
    last_login_at = DateTime.utc_now()
    resource_owner = %{resource_owner | last_login_at: last_login_at}

    token = %Token{
      type: "access_token",
      sub: "sub",
      client: client,
      value: "value",
      inserted_at: inserted_at,
      resource_owner: resource_owner,
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

    assert {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
    client_id = client.id
    assert {:ok, %{"kid" => ^client_id}} = Joken.peek_header(value)
    auth_time = DateTime.to_unix(last_login_at)

    assert %{
             "aud" => ^client_id,
             "iat" => _iat,
             "exp" => _exp,
             "sub" => "sub",
             "nonce" => ^nonce,
             "at_hash" => at_hash,
             "auth_time" => ^auth_time,
             "resource_owner_claim" => "claim"
           } = claims

    assert at_hash == "7CyD7ey2AwTRVOvbhb369hqSvRQuccT3sloVuctfPAo"
  end

  test "generates an id token with a token and a code", %{resource_owner: resource_owner} do
    client = build_client()
    inserted_at = DateTime.utc_now()
    last_login_at = DateTime.utc_now()
    resource_owner = %{resource_owner | last_login_at: last_login_at}

    code = %Token{
      type: "code",
      sub: "sub",
      client: client,
      value: "value",
      inserted_at: inserted_at,
      resource_owner: resource_owner,
      scope: "scope"
    }

    token = %Token{
      type: "access_token",
      sub: "sub",
      client: client,
      value: "value",
      inserted_at: inserted_at,
      resource_owner: resource_owner,
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

    assert {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
    client_id = client.id
    assert {:ok, %{"kid" => ^client_id}} = Joken.peek_header(value)
    auth_time = DateTime.to_unix(last_login_at)

    assert %{
             "aud" => ^client_id,
             "iat" => _iat,
             "exp" => _exp,
             "sub" => "sub",
             "nonce" => ^nonce,
             "at_hash" => at_hash,
             "c_hash" => c_hash,
             "auth_time" => ^auth_time,
             "resource_owner_claim" => "claim"
           } = claims

    assert at_hash == "7CyD7ey2AwTRVOvbhb369hqSvRQuccT3sloVuctfPAo"
    assert c_hash == "7CyD7ey2AwTRVOvbhb369hqSvRQuccT3sloVuctfPAo"
  end

  test "generates an id token with a base token", %{resource_owner: resource_owner} do
    client = build_client()
    inserted_at = DateTime.utc_now()

    base_token = %Token{
      type: "base_token",
      sub: "sub",
      resource_owner: resource_owner,
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
           } = IdToken.generate(%{base_token: base_token}, nonce)

    signer = Joken.Signer.create("RS512", %{"pem" => client.private_key, "aud" => client.id})

    assert {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
    client_id = client.id
    assert {:ok, %{"kid" => ^client_id}} = Joken.peek_header(value)

    assert %{
             "aud" => ^client_id,
             "iat" => _iat,
             "exp" => _exp,
             "sub" => "sub",
             "nonce" => ^nonce,
             "auth_time" => _auth_time,
             "resource_owner_claim" => "claim"
           } = claims
  end

  describe "with RS256 algorithm configuration" do
    test "generates an id token with a token and a code", %{resource_owner: resource_owner} do
      client = %{build_client() | id_token_signature_alg: "RS256"}
      inserted_at = DateTime.utc_now()
      last_login_at = DateTime.utc_now()
      resource_owner = %{resource_owner | last_login_at: last_login_at}

      code = %Token{
        type: "code",
        sub: "sub",
        client: client,
        value: "value",
        inserted_at: inserted_at,
        resource_owner: resource_owner,
        scope: "scope"
      }

      token = %Token{
        type: "access_token",
        sub: "sub",
        client: client,
        value: "value",
        inserted_at: inserted_at,
        resource_owner: resource_owner,
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

      signer = Joken.Signer.create("RS256", %{"pem" => client.private_key, "aud" => client.id})

      assert {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
      client_id = client.id
      assert {:ok, %{"kid" => ^client_id}} = Joken.peek_header(value)
      auth_time = DateTime.to_unix(last_login_at)

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => "sub",
               "nonce" => ^nonce,
               "at_hash" => at_hash,
               "c_hash" => c_hash,
               "auth_time" => ^auth_time,
               "resource_owner_claim" => "claim"
             } = claims

      assert at_hash == "zUJATVKtVcz6mspK3IKKpQ"
      assert c_hash == "zUJATVKtVcz6mspK3IKKpQ"
    end
  end

  describe "with RS384 algorithm configuration" do
    test "generates an id token with a token and a code", %{resource_owner: resource_owner} do
      client = %{build_client() | id_token_signature_alg: "RS384"}
      inserted_at = DateTime.utc_now()
      last_login_at = DateTime.utc_now()
      resource_owner = %{resource_owner | last_login_at: last_login_at}

      code = %Token{
        type: "code",
        sub: "sub",
        client: client,
        value: "value",
        inserted_at: inserted_at,
        resource_owner: resource_owner,
        scope: "scope"
      }

      token = %Token{
        type: "access_token",
        sub: "sub",
        client: client,
        value: "value",
        inserted_at: inserted_at,
        resource_owner: resource_owner,
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

      signer = Joken.Signer.create("RS384", %{"pem" => client.private_key, "aud" => client.id})

      assert {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
      client_id = client.id
      assert {:ok, %{"kid" => ^client_id}} = Joken.peek_header(value)
      auth_time = DateTime.to_unix(last_login_at)

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => "sub",
               "nonce" => ^nonce,
               "at_hash" => at_hash,
               "c_hash" => c_hash,
               "auth_time" => ^auth_time,
               "resource_owner_claim" => "claim"
             } = claims

      assert at_hash == "tGx8OeFdPcLNxQ5Cp6KBgaB0zu8Yx8Sq"
      assert c_hash == "tGx8OeFdPcLNxQ5Cp6KBgaB0zu8Yx8Sq"
    end
  end

  describe "with HS256 algorithm configuration" do
    test "generates an id token with a token and a code", %{resource_owner: resource_owner} do
      client = %{build_client() | id_token_signature_alg: "HS256"}
      inserted_at = DateTime.utc_now()
      last_login_at = DateTime.utc_now()
      resource_owner = %{resource_owner | last_login_at: last_login_at}

      code = %Token{
        type: "code",
        sub: "sub",
        client: client,
        value: "value",
        inserted_at: inserted_at,
        resource_owner: resource_owner,
        scope: "scope"
      }

      token = %Token{
        type: "access_token",
        sub: "sub",
        client: client,
        value: "value",
        inserted_at: inserted_at,
        resource_owner: resource_owner,
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

      signer = Joken.Signer.create("HS256", client.secret)

      assert {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
      client_id = client.id
      auth_time = DateTime.to_unix(last_login_at)

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => "sub",
               "nonce" => ^nonce,
               "at_hash" => at_hash,
               "c_hash" => c_hash,
               "auth_time" => ^auth_time,
               "resource_owner_claim" => "claim"
             } = claims

      assert at_hash == "zUJATVKtVcz6mspK3IKKpQ"
      assert c_hash == "zUJATVKtVcz6mspK3IKKpQ"
    end
  end

  describe "with HS384 algorithm configuration" do
    test "generates an id token with a token and a code", %{resource_owner: resource_owner} do
      client = %{build_client() | id_token_signature_alg: "HS384"}
      inserted_at = DateTime.utc_now()
      last_login_at = DateTime.utc_now()
      resource_owner = %{resource_owner | last_login_at: last_login_at}

      code = %Token{
        type: "code",
        sub: "sub",
        client: client,
        value: "value",
        inserted_at: inserted_at,
        resource_owner: resource_owner,
        scope: "scope"
      }

      token = %Token{
        type: "access_token",
        sub: "sub",
        client: client,
        value: "value",
        inserted_at: inserted_at,
        resource_owner: resource_owner,
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

      signer = Joken.Signer.create("HS384", client.secret)

      assert {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
      client_id = client.id
      auth_time = DateTime.to_unix(last_login_at)

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => "sub",
               "nonce" => ^nonce,
               "at_hash" => at_hash,
               "c_hash" => c_hash,
               "auth_time" => ^auth_time,
               "resource_owner_claim" => "claim"
             } = claims

      assert at_hash == "tGx8OeFdPcLNxQ5Cp6KBgaB0zu8Yx8Sq"
      assert c_hash == "tGx8OeFdPcLNxQ5Cp6KBgaB0zu8Yx8Sq"
    end
  end

  describe "with HS512 algorithm configuration" do
    test "generates an id token with a token and a code", %{resource_owner: resource_owner} do
      client = %{build_client() | id_token_signature_alg: "HS512"}
      inserted_at = DateTime.utc_now()
      last_login_at = DateTime.utc_now()
      resource_owner = %{resource_owner | last_login_at: last_login_at}

      code = %Token{
        type: "code",
        sub: "sub",
        client: client,
        value: "value",
        inserted_at: inserted_at,
        resource_owner: resource_owner,
        scope: "scope"
      }

      token = %Token{
        type: "access_token",
        sub: "sub",
        client: client,
        value: "value",
        inserted_at: inserted_at,
        resource_owner: resource_owner,
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

      signer = Joken.Signer.create("HS512", client.secret)

      assert {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
      client_id = client.id
      auth_time = DateTime.to_unix(last_login_at)

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => "sub",
               "nonce" => ^nonce,
               "at_hash" => at_hash,
               "c_hash" => c_hash,
               "auth_time" => ^auth_time,
               "resource_owner_claim" => "claim"
             } = claims

      assert at_hash == "7CyD7ey2AwTRVOvbhb369hqSvRQuccT3sloVuctfPAo"
      assert c_hash == "7CyD7ey2AwTRVOvbhb369hqSvRQuccT3sloVuctfPAo"
    end
  end

  def build_client do
    %Client{
      id: "client_id",
      id_token_ttl: 10,
      id_token_signature_alg: "RS512",
      secret: "secret",
      private_key:
        "***REMOVED***\n\n"
    }
  end
end
