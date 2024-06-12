require "rspec"
require "webmock/rspec"
require "./lib/client"

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
    cached_data = {}
    rails_cache = double("cache")
    allow(rails_cache).to receive(:read) { |key| cached_data[key] }
    allow(rails_cache).to receive(:write) { |key, value, force: false| cached_data[key] = value }
    allow(rails_cache).to receive(:delete) { |key| cached_data.delete(key) }
    Rails = double("Rails", cache: rails_cache)

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
      expect { basic_client.fetch_user_info }.to raise_error(LogtoNotAuthenticatedError)
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
end
