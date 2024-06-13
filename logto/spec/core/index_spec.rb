require "rspec"
require "webmock/rspec"
require "./lib/logto/core"

RSpec.describe LogtoCore do
  let(:endpoint) { "https://example.com" }
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
    # Stub the HTTP request to fetch the OIDC config
    stub_request(:get, URI.join(endpoint, LogtoCore::DISCOVERY_PATH).to_s)
      .to_return(
        status: 200,
        body: oidc_config_response,
        headers: {"Content-Type" => "application/json"}
      )
  end

  let(:logto_core) { LogtoCore.new(endpoint: endpoint) }

  describe "#initialize" do
    it "sets the endpoint" do
      expect(logto_core.endpoint).to eq(endpoint)
    end

    it "fetches the OIDC config" do
      expect(logto_core.oidc_config).to be_a(LogtoCore::OidcConfigResponse)
    end
  end

  describe "#revoke_token" do
    it "revokes the token" do
      # Stub the HTTP request to revoke the token
      stub_request(:post, logto_core.oidc_config.revocation_endpoint)
        .to_return(status: 200)

      expect {
        logto_core.revoke_token(client_id: "client_id", client_secret: "client_secret", token: "token")
      }.not_to raise_error
    end

    it "raises an error when the request fails" do
      # Stub the HTTP request to revoke the token
      stub_request(:post, logto_core.oidc_config.revocation_endpoint)
        .to_return(status: 400)

      expect {
        logto_core.revoke_token(
          client_id: "client_id", client_secret: "client_secret", token: "token"
        )
      }.to raise_error(LogtoError::RevocationError)
    end
  end

  describe "#fetch_token_by_authorization_code" do
    it "fetches the token" do
      # Stub the HTTP request to fetch the token
      stub_request(:post, logto_core.oidc_config.token_endpoint)
        .to_return(
          status: 200,
          body: {access_token: "access_token"}.to_json,
          headers: {"Content-Type" => "application/json"}
        )

      expect(logto_core.fetch_token_by_authorization_code(
        client_id: "client_id",
        client_secret: "client_secret",
        redirect_uri: "redirect_uri",
        code_verifier: "code_verifier",
        code: "code"
      )).to be_a(LogtoCore::TokenResponse)
    end

    it "raises an error when the request fails" do
      # Stub the HTTP request to fetch the token
      stub_request(:post, logto_core.oidc_config.token_endpoint)
        .to_return(status: 400)

      expect {
        logto_core.fetch_token_by_authorization_code(
          client_id: "client_id",
          client_secret: "client_secret",
          redirect_uri: "redirect_uri",
          code_verifier: "code_verifier",
          code: "code"
        )
      }.to raise_error(LogtoError::TokenError)
    end
  end

  describe "#fetch_token_by_refresh_token" do
    it "fetches the token" do
      # Stub the HTTP request to fetch the token
      stub_request(:post, logto_core.oidc_config.token_endpoint)
        .to_return(
          status: 200,
          body: {access_token: "access_token"}.to_json,
          headers: {"Content-Type" => "application/json"}
        )

      expect(logto_core.fetch_token_by_refresh_token(
        client_id: "client_id",
        client_secret: "client_secret",
        refresh_token: "refresh_token"
      )).to be_a(LogtoCore::TokenResponse)
    end

    it "raises an error when the request fails" do
      # Stub the HTTP request to fetch the token
      stub_request(:post, logto_core.oidc_config.token_endpoint)
        .to_return(status: 400)

      expect {
        logto_core.fetch_token_by_refresh_token(
          client_id: "client_id",
          client_secret: "client_secret",
          refresh_token: "refresh_token"
        )
      }.to raise_error(LogtoError::TokenError)
    end
  end

  describe "fetch_user_info" do
    it "fetches the user info" do
      # Stub the HTTP request to fetch the user info
      stub_request(:get, logto_core.oidc_config.userinfo_endpoint)
        .to_return(
          status: 200,
          body: {name: "name"}.to_json,
          headers: {"Content-Type" => "application/json"}
        )

      expect(logto_core.fetch_user_info(access_token: "access_token")["name"]).to eq("name")
    end

    it "raises an error when the request fails" do
      # Stub the HTTP request to fetch the user info
      stub_request(:get, logto_core.oidc_config.userinfo_endpoint)
        .to_return(status: 400)

      expect {
        logto_core.fetch_user_info(access_token: "access_token")
      }.to raise_error(LogtoError::UserInfoError)
    end
  end

  describe "#generate_sign_in_uri" do
    it "generates the sign-in URI" do
      uri = logto_core.generate_sign_in_uri(
        client_id: "client_id",
        redirect_uri: "https://example.com/callback",
        code_challenge: "code_challenge",
        state: "state"
      )

      expect(uri).to eq("https://example.com/oidc/auth?client_id=client_id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256&state=state&response_type=code&prompt=consent&scope=openid+offline_access+profile")
    end

    it "generates the sign-in URI with scopes" do
      uri = logto_core.generate_sign_in_uri(
        client_id: "client_id",
        redirect_uri: "https://example.com/callback",
        code_challenge: "code_challenge",
        state: "state",
        scopes: %w[scope1 scope2]
      )

      expect(uri).to eq("https://example.com/oidc/auth?client_id=client_id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256&state=state&response_type=code&prompt=consent&scope=scope1+scope2+openid+offline_access+profile")
    end

    it "generates the sign-in URI with resources" do
      uri = logto_core.generate_sign_in_uri(
        client_id: "client_id",
        redirect_uri: "https://example.com/callback",
        code_challenge: "code_challenge",
        state: "state",
        resources: %w[resource1 resource2]
      )

      expect(uri).to eq("https://example.com/oidc/auth?client_id=client_id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256&state=state&response_type=code&prompt=consent&scope=openid+offline_access+profile&resource=resource1&resource=resource2")
    end

    it "generates the sign-in URI with prompt" do
      uri = logto_core.generate_sign_in_uri(
        client_id: "client_id",
        redirect_uri: "https://example.com/callback",
        code_challenge: "code_challenge",
        state: "state",
        prompt: %w[prompt1 prompt2]
      )

      expect(uri).to eq("https://example.com/oidc/auth?client_id=client_id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256&state=state&response_type=code&prompt=prompt1+prompt2&scope=openid+offline_access+profile")
    end

    it "generates the sign-in URI with first_screen and interaction_mode" do
      uri = logto_core.generate_sign_in_uri(
        client_id: "client_id",
        redirect_uri: "https://example.com/callback",
        code_challenge: "code_challenge",
        state: "state",
        first_screen: "first_screen",
        interaction_mode: "interaction_mode"
      )

      expect(uri).to eq("https://example.com/oidc/auth?client_id=client_id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256&state=state&response_type=code&prompt=consent&scope=openid+offline_access+profile&first_screen=first_screen")
    end

    it "generates the sign-in URI with interaction_mode" do
      uri = logto_core.generate_sign_in_uri(
        client_id: "client_id",
        redirect_uri: "https://example.com/callback",
        code_challenge: "code_challenge",
        state: "state",
        interaction_mode: "interaction_mode"
      )

      expect(uri).to eq("https://example.com/oidc/auth?client_id=client_id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256&state=state&response_type=code&prompt=consent&scope=openid+offline_access+profile&interaction_mode=interaction_mode")
    end

    it "generates the sign-in URI with login_hint" do
      uri = logto_core.generate_sign_in_uri(
        client_id: "client_id",
        redirect_uri: "https://example.com/callback",
        code_challenge: "code_challenge",
        state: "state",
        login_hint: "login_hint"
      )

      expect(uri).to eq("https://example.com/oidc/auth?client_id=client_id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256&state=state&response_type=code&prompt=consent&scope=openid+offline_access+profile&login_hint=login_hint")
    end

    it "generates the sign-in URI with direct_sign_in" do
      uri = logto_core.generate_sign_in_uri(
        client_id: "client_id",
        redirect_uri: "https://example.com/callback",
        code_challenge: "code_challenge",
        state: "state",
        direct_sign_in: {method: "method", target: "target"}
      )

      expect(uri).to eq("https://example.com/oidc/auth?client_id=client_id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256&state=state&response_type=code&prompt=consent&scope=openid+offline_access+profile&direct_sign_in=method%3Atarget")
    end

    it "generates the sign-in URI with extra_params" do
      uri = logto_core.generate_sign_in_uri(
        client_id: "client_id",
        redirect_uri: "https://example.com/callback",
        code_challenge: "code_challenge",
        state: "state",
        extra_params: {key1: "value1", key2: "value2"}
      )

      expect(uri).to eq("https://example.com/oidc/auth?client_id=client_id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256&state=state&response_type=code&prompt=consent&scope=openid+offline_access+profile&key1=value1&key2=value2")
    end

    it "generates the sign-in URI with no reserved scopes" do
      uri = logto_core.generate_sign_in_uri(
        client_id: "client_id",
        redirect_uri: "https://example.com/callback",
        code_challenge: "code_challenge",
        state: "state",
        scopes: %w[scope1 scope2],
        include_reserved_scopes: false
      )

      expect(uri).to eq("https://example.com/oidc/auth?client_id=client_id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256&state=state&response_type=code&prompt=consent&scope=scope1+scope2")
    end
  end

  describe "#generate_sign_out_uri" do
    it "generates the sign-out URI" do
      uri = logto_core.generate_sign_out_uri(
        client_id: "client_id"
      )

      expect(uri).to eq("https://example.com/oidc/end?client_id=client_id")
    end

    it "generates the sign-out URI with post_logout_redirect_uri" do
      uri = logto_core.generate_sign_out_uri(
        client_id: "client_id",
        post_logout_redirect_uri: "https://example.com/post-logout"
      )

      expect(uri).to eq("https://example.com/oidc/end?client_id=client_id&post_logout_redirect_uri=https%3A%2F%2Fexample.com%2Fpost-logout")
    end
  end
end
