defmodule Boruta.OpenidTest.DirectPostTest do
  use Boruta.DataCase

  import Boruta.Factory

  alias Boruta.Ecto.OauthMapper
  alias Boruta.Oauth.Client
  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock

  describe "authenticates with direct post response" do
    setup do
      client = insert(:client, id_token_signature_alg: "RS512")
      code = insert(:token, type: "code", redirect_uri: "http://redirect.uri", state: "state")

      {:ok, client: client, code: code}
    end

    test "returns authentication failure without id_token" do
      conn = %Plug.Conn{}

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 status: :unauthorized,
                 error: :unauthorized,
                 error_description: "id_token param missing."
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

    test "returns not found with a bad id_token" do
      conn = %Plug.Conn{}

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :unauthorized,
                error: :unauthorized,
                error_description: ":token_malformed"
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

    test "returns not found with a bad code", %{client: client} do
      payload = %{}
      conn = %Plug.Conn{}

      assert {:code_not_found} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id",
                   id_token:
                     Client.Crypto.id_token_sign(payload, OauthMapper.to_oauth_schema(client))
                 },
                 ApplicationMock
               )
    end

    test "authenticates", %{client: client, code: code} do
      payload = %{}
      conn = %Plug.Conn{}

      assert {:direct_post_success, callback_uri} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token:
                     Client.Crypto.id_token_sign(payload, OauthMapper.to_oauth_schema(client))
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
