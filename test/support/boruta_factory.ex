defmodule Boruta.Factory do
  @moduledoc false

  use ExMachina.Ecto, repo: Boruta.Repo

  alias Boruta.Ecto

  def client_factory do
    %Ecto.Client{
      secret: SecureRandom.urlsafe_base64(),
      redirect_uris: ["https://redirect.uri"],
      access_token_ttl: 3600,
      authorization_code_ttl: 60,
      refresh_token_ttl: 3600 * 24 * 30,
      id_token_ttl: 3600 * 24,
      private_key:
        "***REMOVED***\n\n",
      public_key:
        "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
    }
  end

  def scope_factory do
    %Ecto.Scope{
      name: SecureRandom.hex(10),
      public: false
    }
  end

  def token_factory do
    %Ecto.Token{
      client: build(:client),
      type: "access_token",
      value: Boruta.TokenGenerator.generate(),
      expires_at: :os.system_time(:seconds) + 10
    }
  end
end
