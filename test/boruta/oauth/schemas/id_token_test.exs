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

    assert {:ok, claims} = Client.Token.verify_and_validate(value, signer)
    assert {:ok, %{"kid" => "Ac9ufCpgwReXGJ6LI"}} = Joken.peek_header(value)
    auth_time = DateTime.to_unix(last_login_at)

    client_id = client.id
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

    assert {:ok, claims} = Client.Token.verify_and_validate(value, signer)
    assert {:ok, %{"kid" => "Ac9ufCpgwReXGJ6LI"}} = Joken.peek_header(value)
    auth_time = DateTime.to_unix(last_login_at)

    client_id = client.id
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

    assert {:ok, claims} = Client.Token.verify_and_validate(value, signer)
    client_id = client.id
    assert {:ok, %{"kid" => "Ac9ufCpgwReXGJ6LI"}} = Joken.peek_header(value)
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

    {:ok, claims} = Client.Token.verify_and_validate(value, signer)
    client_id = client.id

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

  test "generates an id token with resource owner extra claims" do
    resource_owner = %ResourceOwner{
      sub: "resource_owner_sub",
      extra_claims: %{"resource_owner_extra_claim" => "claim"}
    }

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

    assert {:ok, claims} = Client.Token.verify_and_validate(value, signer)
    client_id = client.id
    assert {:ok, %{"kid" => "Ac9ufCpgwReXGJ6LI"}} = Joken.peek_header(value)

    assert %{
             "aud" => ^client_id,
             "iat" => _iat,
             "exp" => _exp,
             "sub" => "sub",
             "nonce" => ^nonce,
             "auth_time" => _auth_time,
             "resource_owner_claim" => "claim",
             "resource_owner_extra_claim" => "claim"
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

      assert {:ok, claims} = Client.Token.verify_and_validate(value, signer)
      client_id = client.id
      assert {:ok, %{"kid" => "Ac9ufCpgwReXGJ6LI"}} = Joken.peek_header(value)
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

      assert {:ok, claims} = Client.Token.verify_and_validate(value, signer)
      assert {:ok, %{"kid" => "Ac9ufCpgwReXGJ6LI"}} = Joken.peek_header(value)
      auth_time = DateTime.to_unix(last_login_at)

      client_id = client.id
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

      assert {:ok, claims} = Client.Token.verify_and_validate(value, signer)
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

      assert {:ok, claims} = Client.Token.verify_and_validate(value, signer)
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
      resource_owner = %{resource_owner | last_login_at: last_login_at,
            extra_claims: %{
               "term" => true,
               "hide" => %{"display" => false, "hide" => true},
               "value" => %{"value" => true},
               "display" => %{"value" => true, "display" => []},
               "status" => %{"value" => true, "display" => ["status"], "status" => "suspended"}
             }
      }

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

      assert {:ok, claims} = Client.Token.verify_and_validate(value, signer)
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
               "resource_owner_claim" => "claim",
                   "display" => true,
                   "status" => %{"status" => "suspended", "value" => true},
                   "term" => true,
                   "value" => true
             } = claims

      assert at_hash == "7CyD7ey2AwTRVOvbhb369hqSvRQuccT3sloVuctfPAo"
      assert c_hash == "7CyD7ey2AwTRVOvbhb369hqSvRQuccT3sloVuctfPAo"
    end
  end

  describe "format_claims/1" do
    test "returns claims with json values" do
      claims = %{
        "boolean" => true,
        "string" => "true"
      }

      assert IdToken.format_claims(claims) == claims
    end

    test "returns claims with claims definition but display" do
      claims = %{
        "boolean" => %{"value" => true},
        "string" => %{"value" => "true"}
      }

      assert IdToken.format_claims(claims) == %{
        "boolean" => true,
        "string" => "true"
      }
    end

    test "returns claims with claims definition and empty display" do
      claims = %{
        "boolean" => %{"value" => true, "display" => []},
        "string" => %{"value" => "true", "display" => []}
      }

      assert IdToken.format_claims(claims) == %{
        "boolean" => true,
        "string" => "true"
      }
    end

    test "returns claims with claims definition and display" do
      claims = %{
        "boolean" => %{"value" => true, "status" => "suspended", "display" => ["status"]},
        "string" => %{"value" => "true", "status" => "valid", "display" => ["status"]}
      }

      assert IdToken.format_claims(claims) == %{
        "boolean" => %{"value" => true, "status" => "suspended"},
        "string" => %{"value" => "true", "status" => "valid"}
      }

    end

    test "returns claims without hidden values" do
      claims = %{
        "hide" => %{"display" => false, "hide" => true},
        "hide_value" => %{"display" => false, "hide" => true},
      }

      assert IdToken.format_claims(claims) == %{}
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
