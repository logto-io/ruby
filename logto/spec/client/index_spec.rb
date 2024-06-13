require "jwt"
require "rspec"
require "webmock/rspec"
require "./lib/logto/client"

class MockStorage < LogtoClient::AbstractStorage
  def initialize
    @store = {}
  end

  def get(key)
    @store[key]
  end

  def set(key, value)
    @store[key] = value
  end

  def remove(key)
    @store.delete(key)
  end
end

RSpec.describe LogtoClient do
  let(:endpoint) { "https://example.com" }
  let(:client_id) { "client_id" }
  let(:client_secret) { "client_secret" }
  let(:redirect_uri) { "https://example.com/callback" }
  let(:navigate) { proc {} }
  let(:storage) { MockStorage.new }
  let(:basic_config) {
    LogtoClient::Config.new(
      endpoint: endpoint, app_id: client_id, app_secret: client_secret
    )
  }
  let(:basic_client) {
    LogtoClient.new(
      config: basic_config,
      navigate: navigate,
      storage: storage
    )
  }
  let(:oidc_config_response) do
    {
      issuer: "https://example.com/oidc",
      authorization_endpoint: "https://example.com/oidc/auth",
      token_endpoint: "https://example.com/oidc/token",
      userinfo_endpoint: "https://example.com/oidc/userinfo",
      jwks_uri: "https://example.com/oidc/jwks",
      revocation_endpoint: "https://example.com/oidc/revoke",
      end_session_endpoint: "https://example.com/oidc/end"
    }.to_json
  end

  before do
    mock_rails = begin
      cached_data = {}
      rails_cache = double("cache")
      allow(rails_cache).to receive(:read) { |key| cached_data[key] }
      allow(rails_cache).to receive(:write) { |key, value, force: false| cached_data[key] = value }
      allow(rails_cache).to receive(:delete) { |key| cached_data.delete(key) }
      double("Rails", cache: rails_cache)
    end
    stub_const("Rails", mock_rails)
    stub_request(:get, URI.join(endpoint, LogtoCore::DISCOVERY_PATH).to_s)
      .to_return(
        status: 200,
        body: oidc_config_response,
        headers: {"Content-Type" => "application/json"}
      )
  end

  describe "#initialize" do
    it "sets the config" do
      expect(basic_client.config).to be_a(LogtoClient::Config)
    end
  end

  describe "#sign_in" do
    it "redirects to the authorization endpoint and stores the session" do
      allow(navigate).to receive(:call) do |url|
        uri = URI.parse(url)
        expect(uri.host).to eq("example.com")
        expect(uri.path).to eq("/oidc/auth")
        expect(uri.scheme).to eq("https")
        # Just do some sanity check here since we've tested the URL generation in the core spec
        expect(uri.query).to include("client_id=#{client_id}")
      end
      basic_client.sign_in(redirect_uri: redirect_uri)
      expect(
        storage.get(LogtoClient::STORAGE_KEY[:sign_in_session])&.dig("redirect_uri")
      ).to eq(redirect_uri)
    end
  end

  describe "#sign_out" do
    it "redirects to the end session endpoint and revokes the refresh token" do
      stub_revoke = stub_request(:post, "https://example.com/oidc/revoke")
        .to_return(status: 200)
      storage.set(LogtoClient::STORAGE_KEY[:refresh_token], "refresh_token")
      allow(navigate).to receive(:call) do |url|
        uri = URI.parse(url)
        expect(uri.host).to eq("example.com")
        expect(uri.path).to eq("/oidc/end")
        expect(uri.scheme).to eq("https")
        # Just do some sanity check here since we've tested the URL generation in the core spec
        expect(uri.query).to include("client_id=#{client_id}")
      end
      basic_client.sign_out
      expect(storage.get(LogtoClient::STORAGE_KEY[:refresh_token])).to be_nil
      assert_requested(stub_revoke, times: 1)
    end
  end

  describe "#handle_sign_in_callback" do
    let(:stub_request_proc) do
      proc do
        stub_request(:post, "https://example.com/oidc/token")
          .to_return(
            status: 200,
            body: {
              access_token: "access_token",
              refresh_token: "refresh_token",
              id_token: "id_token",
              expires_in: 3600,
              scope: "openid"
            }.to_json,
            headers: {"Content-Type" => "application/json"}
          )
      end
    end

    it "raises an error when no sign-in session is found" do
      expect { basic_client.handle_sign_in_callback(url: "https://example.com/callback?") }.to raise_error(LogtoError::SessionNotFoundError)
    end

    it "raises an error when the redirect URI mismatch" do
      storage.set(LogtoClient::STORAGE_KEY[:sign_in_session], {redirect_uri: "https://example.com/other"})
      expect { basic_client.handle_sign_in_callback(url: "https://example.com/callback?") }.to raise_error(LogtoError::SessionMismatchError)
    end

    it "raises an error when no state is found in the query parameters" do
      storage.set(LogtoClient::STORAGE_KEY[:sign_in_session], {redirect_uri: "https://example.com/callback"})
      expect { basic_client.handle_sign_in_callback(url: "https://example.com/callback?") }.to raise_error(LogtoError::SessionMismatchError)
    end

    it "raises an error when the session state mismatch" do
      storage.set(LogtoClient::STORAGE_KEY[:sign_in_session], {redirect_uri: "https://example.com/callback", state: "state"})
      expect { basic_client.handle_sign_in_callback(url: "https://example.com/callback?state=other") }.to raise_error(LogtoError::SessionMismatchError)
    end

    it "raises an error when no code is found in the query parameters" do
      storage.set(LogtoClient::STORAGE_KEY[:sign_in_session], {redirect_uri: "https://example.com/callback", state: "state"})
      expect { basic_client.handle_sign_in_callback(url: "https://example.com/callback?state=state") }.to raise_error(LogtoError::SessionMismatchError)
    end

    it "raises an error when error is found in the query parameters" do
      storage.set(LogtoClient::STORAGE_KEY[:sign_in_session], {redirect_uri: "https://example.com/callback", state: "state"})
      expect { basic_client.handle_sign_in_callback(url: "https://example.com/callback?state=state&error=error") }.to raise_error(LogtoError::ServerCallbackError)
    end

    it "recoginizes the `SignInSession` struct stored in the storage" do
      storage.set(LogtoClient::STORAGE_KEY[:sign_in_session], LogtoClient::SignInSession.new(redirect_uri: "https://example.com/callback", state: "state"))
      allow_any_instance_of(LogtoClient).to receive(:verify_jwt).and_return(true)
      stub_request_proc.call
      basic_client.handle_sign_in_callback(url: "https://example.com/callback?state=state&code=code")
      expect(storage.get(LogtoClient::STORAGE_KEY[:sign_in_session])).to be_nil
    end

    it "fetches the token by the authorization code" do
      storage.set(LogtoClient::STORAGE_KEY[:sign_in_session], {redirect_uri: "https://example.com/callback", state: "state", code_verifier: "code_verifier"})
      allow_any_instance_of(LogtoClient).to receive(:verify_jwt).and_return(true)
      stub_request_proc.call
      basic_client.handle_sign_in_callback(url: "https://example.com/callback?state=state&code=code")
      expect(basic_client.access_token).to eq("access_token")
      expect(basic_client.refresh_token).to eq("refresh_token")
      expect(basic_client.id_token).to eq("id_token")
    end
  end

  describe "#verify_jwt" do
    it "raises ArgumentError when token is not a string" do
      expect { basic_client.verify_jwt(token: nil) }.to raise_error(ArgumentError)
    end

    it "verifies the JWT token" do
      token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL29pZGMiLCJhdWQiOiJjbGllbnRfaWQiLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.y9M3xKV68UTtfwdkW5dCzaKKA1O2xQ5Y_9oYTIJAl6qaw9DeRddZFz7QZyKLoI_DaIN9NIRYLBNind1Fr6diWw"
      stub_request(:get, "https://example.com/oidc/jwks")
        .to_return(
          status: 200,
          body: {
            keys: [
              {
                kty: "EC",
                use: "sig",
                alg: "ES256",
                kid: "1",
                crv: "P-256",
                x: "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
                y: "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY"
              }
            ]
          }.to_json,
          headers: {"Content-Type" => "application/json"}
        )
      expect { basic_client.verify_jwt(token: token) }.not_to raise_error
    end
  end

  describe "#id_token and #id_token_claims" do
    it "returns the raw ID token" do
      storage.set(LogtoClient::STORAGE_KEY[:id_token], "id_token")
      expect(basic_client.id_token).to eq("id_token")
    end

    it "returns the ID token claims" do
      storage.set(LogtoClient::STORAGE_KEY[:id_token], "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
      claims = basic_client.id_token_claims
      expect(claims.sub).to eq("1234567890")
      expect(claims.name).to eq("John Doe")
      expect(claims.iat).to eq(1516239022)
    end
  end

  describe "#access_token" do
    let(:stub_request_proc) do
      proc do
        stub_request(:post, "https://example.com/oidc/token")
          .to_return(
            status: 200,
            body: {access_token: "new_access_token", expires_in: 3600, scope: "openid"}.to_json,
            headers: {"Content-Type" => "application/json"}
          )
      end
    end

    it "raises an error when not authenticated" do
      expect { basic_client.access_token(resource: nil) }.to raise_error(LogtoError::NotAuthenticatedError)
    end

    it "returns the access token directly when it's stored and not expired" do
      allow_any_instance_of(LogtoClient).to receive(:is_authenticated?).and_return(true)
      storage.set(LogtoClient::STORAGE_KEY[:access_token_map], {
        ":default" => LogtoCore::AccessToken.new(
          token: "access_token",
          scope: "openid",
          expires_at: Time.now + 3600
        )
      })

      expect(basic_client.access_token(resource: nil)).to eq("access_token")
    end

    it "uses the refresh token to fetch a new access token when the stored one is expired" do
      allow_any_instance_of(LogtoClient).to receive(:is_authenticated?).and_return(true)
      storage.set(LogtoClient::STORAGE_KEY[:access_token_map], {
        ":default" => LogtoCore::AccessToken.new(
          token: "access_token",
          scope: "openid",
          expires_at: Time.now + 5 # Test leeway
        )
      })
      storage.set(LogtoClient::STORAGE_KEY[:refresh_token], "refresh_token")
      stub_request_proc.call
      expect(basic_client.access_token(resource: nil)).to eq("new_access_token")
    end

    it "uses the refresh token to fetch a new access token when no access token is stored (resource)" do
      allow_any_instance_of(LogtoClient).to receive(:is_authenticated?).and_return(true)
      storage.set(LogtoClient::STORAGE_KEY[:refresh_token], "refresh_token")
      stub_request_proc.call

      expect(basic_client.access_token(resource: "https://example.com/")).to eq("new_access_token")
      token_map = storage.get(LogtoClient::STORAGE_KEY[:access_token_map])
      expect(token_map).to include(":https://example.com/")
      expect(token_map[":https://example.com/"].token).to eq("new_access_token")
    end

    it "uses the refresh token to fetch a new access token when no access token is stored (organization ID)" do
      allow_any_instance_of(LogtoClient).to receive(:is_authenticated?).and_return(true)
      storage.set(LogtoClient::STORAGE_KEY[:refresh_token], "refresh_token")
      stub_request_proc.call

      expect(basic_client.access_token(organization_id: "123")).to eq("new_access_token")
      token_map = storage.get(LogtoClient::STORAGE_KEY[:access_token_map])
      expect(token_map).to include("#123:default")
      expect(token_map["#123:default"].token).to eq("new_access_token")
    end

    it "uses the refresh token to fetch a new access token when no access token is stored (resource and organization ID)" do
      allow_any_instance_of(LogtoClient).to receive(:is_authenticated?).and_return(true)
      storage.set(LogtoClient::STORAGE_KEY[:refresh_token], "refresh_token")
      stub_request_proc.call

      expect(basic_client.access_token(resource: "https://example.com/", organization_id: "123")).to eq("new_access_token")
      token_map = storage.get(LogtoClient::STORAGE_KEY[:access_token_map])
      expect(token_map).to include("#123:https://example.com/")
      expect(token_map["#123:https://example.com/"].token).to eq("new_access_token")
    end
  end

  describe "#access_token_claims" do
    it "raises an error when both resource and organization ID are nil" do
      expect { basic_client.access_token_claims(resource: nil, organization_id: nil) }.to raise_error(ArgumentError)
    end

    it "returns the access token claims" do
      allow_any_instance_of(LogtoClient).to receive(:is_authenticated?).and_return(true)
      allow_any_instance_of(LogtoClient).to receive(:access_token).and_return("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
      claims = basic_client.access_token_claims(resource: "openid")
      expect(claims.sub).to eq("1234567890")
      expect(claims.iat).to eq(1516239022)
    end
  end

  describe "#fetch_user_info" do
    it "fetches the user info" do
      stub_request(:get, "https://example.com/oidc/userinfo")
        .to_return(
          status: 200,
          body: {
            sub: "1234567890",
            name: "John Doe",
            iat: 1516239022,
            custom_data: {foo: "bar"},
            identities: [{provider: "google", user_id: "123"}]
          }.to_json,
          headers: {"Content-Type" => "application/json"}
        )
      allow_any_instance_of(LogtoClient).to receive(:is_authenticated?).and_return(true)
      user_info = basic_client.fetch_user_info
      expect(user_info.sub).to eq("1234567890")
      expect(user_info.name).to eq("John Doe")
      expect(user_info.iat).to eq(1516239022)
      expect(user_info.custom_data).to eq("foo" => "bar")
      expect(user_info.identities).to eq([{"provider" => "google", "user_id" => "123"}])
    end

    it "raises an error when not authenticated" do
      expect { basic_client.fetch_user_info }.to raise_error(LogtoError::NotAuthenticatedError)
    end
  end

  describe "#refresh_token" do
    it "returns the refresh token" do
      storage.set(LogtoClient::STORAGE_KEY[:refresh_token], "refresh_token")
      expect(basic_client.refresh_token).to eq("refresh_token")
    end
  end

  describe "#clear_all_tokens" do
    it "clears all tokens" do
      token_keys = [
        LogtoClient::STORAGE_KEY[:access_token_map],
        LogtoClient::STORAGE_KEY[:id_token],
        LogtoClient::STORAGE_KEY[:refresh_token]
      ]

      token_keys.each do |key|
        storage.set(key, "value")
        expect(storage.get(key)).not_to be_nil
      end

      basic_client.clear_all_tokens
      token_keys.each do |key|
        expect(storage.get(key)).to be_nil
      end
    end
  end

  describe "#fetch_jwks" do
    it "fetches the JWKS when kid is not found in the cache and the cache hasn't been updated in the last 5 minutes" do
      request = stub_request(:get, "https://example.com/oidc/jwks")
        .to_return(
          status: 200,
          body: {
            keys: [
              {
                kty: "EC",
                use: "sig",
                alg: "ES256",
                kid: "1",
                crv: "P-256",
                x: "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
                y: "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY"
              }
            ]
          }.to_json,
          headers: {"Content-Type" => "application/json"}
        )
      expect(basic_client.send(:fetch_jwks, kid_not_found: true)).to be_a(JWT::JWK::Set)
      assert_requested(request, times: 1)
    end
  end
end
