require "jwt"
require_relative "index_constants"
require_relative "index_types"
require_relative "index_storage"
require_relative "errors"

# The main client class for the Logto client.
#
# It provides the main functionalities for the client to interact with the Logto server.
#
# @attr_reader config [LogtoClient::Config] The configuration object for the Logto client.
class LogtoClient
  attr_reader :config

  # @param config [LogtoClient::Config] The configuration object for the Logto client.
  # @param navigate [Proc] The navigation function to be used for the sign-in experience.
  #   It should accept a URI string as the only argument. You can use the `redirect_to` method in Rails.
  #   @example
  #     ->(uri) { redirect_to(uri, allow_other_host: true) }
  # @param storage [LogtoClient::AbstractStorage] The storage object for the Logto client.
  #   You can use the `LogtoClient::SessionStorage` for Rails applications.
  #   @example
  #     LogtoClient::SessionStorage.new(session)
  # @param cache [LogtoClient::AbstractStorage] The cache object for the Logto client.
  #   By default, it will use the Rails cache.
  def initialize(config:, navigate:, storage:, cache: RailsCacheStorage.new(app_id: config.app_id))
    raise ArgumentError, "Config must be a LogtoClient::Config" unless config.is_a?(LogtoClient::Config)
    raise ArgumentError, "Navigate must be a Proc" unless navigate.is_a?(Proc)
    raise ArgumentError, "Storage must be a LogtoClient::AbstractStorage" unless storage.is_a?(LogtoClient::AbstractStorage)
    @config = config
    @navigate = navigate
    @storage = storage
    @cache = cache
    @core = LogtoCore.new(endpoint: @config.endpoint, cache: cache)
    # A local access token map cache
    @access_token_map = @storage.get(STORAGE_KEY[:access_token_map]) || {}
  end

  # Triggers the sign-in experience.
  #
  # @param redirect_uri [String] The redirect URI that the user will be redirected to after the sign-in experience is completed.
  # @param first_screen [String] The first screen that the user will see in the sign-in experience. Can be `signIn` or `register`.
  # @param login_hint [String] The login hint to be used for the sign-in experience.
  # @param direct_sign_in [Hash] The direct sign-in configuration to be used for the sign-in experience. It should contain the `method` and `target` keys.
  # @param post_redirect_uri [String] The URI that the user will be redirected to after the redirect URI has successfully handled the sign-in callback.
  # @param extra_params [Hash] Extra parameters to be used for the sign-in experience.
  def sign_in(redirect_uri:, first_screen: nil, login_hint: nil, direct_sign_in: nil, post_redirect_uri: nil, extra_params: nil)
    code_verifier = LogtoUtils.generate_code_verifier
    code_challenge = LogtoUtils.generate_code_challenge(code_verifier)

    state = LogtoUtils.generate_state
    sign_in_uri = @core.generate_sign_in_uri(
      client_id: @config.app_id,
      redirect_uri: redirect_uri,
      code_challenge: code_challenge,
      state: state,
      scopes: @config.scopes,
      resources: @config.resources,
      prompt: @config.prompt,
      first_screen: first_screen,
      login_hint: login_hint,
      direct_sign_in: direct_sign_in,
      extra_params: extra_params
    )

    save_sign_in_session(SignInSession.new(
      redirect_uri: redirect_uri,
      code_verifier: code_verifier,
      state: state,
      post_redirect_uri: post_redirect_uri
    ))
    clear_all_tokens

    @navigate.call(sign_in_uri)
  end

  # Start the sign-out flow with the specified redirect URI. The URI must be
  # registered in the Logto Console.
  #
  # It will also revoke all the tokens and clean up the storage.
  #
  # The user will be redirected to that URI after the sign-out flow is completed.
  # If the `post_logout_redirect_uri` is not specified, the user will be redirected
  # to a default page.
  #
  # @param post_logout_redirect_uri [String] The URI that the user will be redirected to after the sign-out flow is completed.
  def sign_out(post_logout_redirect_uri: nil)
    if refresh_token
      @core.revoke_token(client_id: @config.app_id, client_secret: @config.app_secret, token: refresh_token)
    end

    uri = @core.generate_sign_out_uri(
      client_id: @config.app_id, post_logout_redirect_uri: post_logout_redirect_uri
    )
    clear_all_tokens
    @navigate.call(uri)
  end

  # Handle the sign-in callback from the redirect URI.
  #
  # @param url [String] The URL of the callback from the redirect URI. It should contain the query parameters.
  # @return [String, nil] The URI that the user will be redirected to after the redirect URI has successfully handled the sign-in callback.
  #   It should be the same as the `post_redirect_uri` in the `sign_in` method. If it was not set, no redirection will happen.
  def handle_sign_in_callback(url:)
    query_params = URI.decode_www_form(URI(url).query).to_h
    data = @storage.get(STORAGE_KEY[:sign_in_session])
    raise LogtoError::SessionNotFoundError, "No sign-in session found" unless data

    error = query_params[LogtoCore::QUERY_KEY[:error]]
    error_description = query_params[LogtoCore::QUERY_KEY[:error_description]]
    raise LogtoError::ServerCallbackError, "Error: #{error}, Description: #{error_description}" if error

    current_session = SignInSession.new(@storage.get(STORAGE_KEY[:sign_in_session]))
    # A loose URI check here
    raise LogtoError::SessionMismatchError, "Redirect URI mismatch" unless url.start_with?(current_session.redirect_uri)
    raise LogtoError::SessionMismatchError, "No state found in query parameters" unless query_params[LogtoCore::QUERY_KEY[:state]]
    raise LogtoError::SessionMismatchError, "Session state mismatch" unless current_session.state == query_params[LogtoCore::QUERY_KEY[:state]]
    raise LogtoError::SessionMismatchError, "No code found in query parameters" unless query_params[LogtoCore::QUERY_KEY[:code]]

    token_response = @core.fetch_token_by_authorization_code(
      client_id: @config.app_id,
      client_secret: @config.app_secret,
      redirect_uri: current_session.redirect_uri,
      code_verifier: current_session.code_verifier,
      code: query_params[LogtoCore::QUERY_KEY[:code]]
    )

    verify_jwt(token: token_response[:id_token])
    handle_token_response(token_response)
    clear_sign_in_session

    @navigate.call(current_session.post_redirect_uri)
    current_session.post_redirect_uri
  end

  # Verify the JWT token with the configured client ID and the OIDC issuer.
  #
  # @param token [String] The JWT token to be verified.
  def verify_jwt(token:)
    raise ArgumentError, "Token must be a string" unless token.is_a?(String)

    JWT.decode(
      token,
      nil,
      true,
      # List our current and future possibilities. It could use the `alg` header from the token,
      # but it will be tricky to handle the case of caching.
      algorithms: ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "ES256K"],
      jwks: fetch_jwks,
      iss: @core.oidc_config[:issuer],
      verify_iss: true,
      aud: @config.app_id,
      verify_aud: true
    )
  end

  # Get the raw ID token from the storage.
  #
  # @return [String, nil] The raw ID token.
  def id_token
    @storage.get(STORAGE_KEY[:id_token])
  end

  # Get the ID token claims from the storage.
  # It will return nil if the ID token is not found.
  #
  # @return [LogtoCore::IdTokenClaims, nil] The ID token claims.
  def id_token_claims
    return nil unless (token = id_token)
    LogtoUtils.parse_json_safe(JWT.decode(token, nil, false).first, LogtoCore::IdTokenClaims)
  end

  # Get the access token for the specified resource and organization ID. If both are nil,
  # it will return the opaque access token for the OpenID Connect UserInfo endpoint.
  #
  # If the access token is not found or expired, it will try to use the refresh token to
  # fetch a new access token, if possible.
  #
  # @param resource [String, nil] The resource to be accessed.
  # @param organization_id [String, nil] The organization ID to be accessed.
  # @return [String, nil] The access token.
  def access_token(resource: nil, organization_id: nil)
    raise LogtoError::NotAuthenticatedError, "Not authenticated" unless is_authenticated?
    key = LogtoUtils.build_access_token_key(resource: resource, organization_id: organization_id)
    token = @access_token_map[key]

    # Give it some leeway
    if token&.[]("expires_at")&.> Time.now + 10
      return token["token"]
    end

    @access_token_map.delete(key)
    return nil unless refresh_token

    # Try to use refresh token to fetch a new access token
    token_response = @core.fetch_token_by_refresh_token(
      client_id: @config.app_id,
      client_secret: @config.app_secret,
      refresh_token: refresh_token,
      resource: resource,
      organization_id: organization_id
    )
    handle_token_response(token_response)
    token_response[:access_token]
  end

  # Get the access token claims for the specified resource and organization ID. If both are nil,
  # an ArgumentError will be raised.
  #
  # @param resource [String, nil] The resource to be accessed.
  # @param organization_id [String, nil] The organization ID to be accessed.
  # @return [LogtoCore::AccessTokenClaims, nil] The access token claims.
  def access_token_claims(resource: nil, organization_id: nil)
    raise ArgumentError, "Resource and organization ID cannot be nil at the same time" if
      resource.nil? && organization_id.nil?
    return nil unless (token = access_token(resource: resource, organization_id: organization_id))
    LogtoUtils.parse_json_safe(
      JWT.decode(token, nil, false).first,
      LogtoCore::AccessTokenClaims
    )
  end

  # Fetch the user information from the OpenID Connect UserInfo endpoint.
  #
  # @return [LogtoCore::UserInfoResponse] The user information.
  def fetch_user_info
    @core.fetch_user_info(access_token: access_token)
  end

  # Get the raw refresh token from the storage.
  #
  # @return [String, nil] The raw refresh token.
  def refresh_token
    @storage.get(STORAGE_KEY[:refresh_token])
  end

  # Check if the client is authenticated by checking if the ID token is present.
  #
  # @return [Boolean] Whether the client is authenticated.
  def is_authenticated?
    id_token ? true : false
  end

  # Clear all the tokens from the storage.
  #
  # It will also clear the access token map cache.
  def clear_all_tokens
    @access_token_map = {}
    @storage.remove(STORAGE_KEY[:access_token_map])
    @storage.remove(STORAGE_KEY[:id_token])
    @storage.remove(STORAGE_KEY[:refresh_token])
  end

  protected

  def handle_token_response(response)
    raise ArgumentError, "Response must be a TokenResponse" unless response.is_a?(LogtoCore::TokenResponse)
    response[:refresh_token] && save_refresh_token(response[:refresh_token])
    response[:id_token] && save_id_token(response[:id_token])
    # The response should have access token
    save_access_token(
      key: LogtoUtils.build_access_token_key(resource: nil),
      token: LogtoCore::AccessToken.new(
        token: response[:access_token],
        scope: response[:scope],
        expires_at: Time.now + response[:expires_in].to_i
      )
    )
  end

  def save_refresh_token(token)
    raise ArgumentError, "Token must be a String" unless token.is_a?(String)
    @storage.set(STORAGE_KEY[:refresh_token], token)
  end

  def save_id_token(token)
    raise ArgumentError, "Token must be a String" unless token.is_a?(String)
    @storage.set(STORAGE_KEY[:id_token], token)
  end

  def save_access_token(key:, token:)
    raise ArgumentError, "Token must be an AccessToken" unless token.is_a?(LogtoCore::AccessToken)
    @access_token_map[key] = token
    @storage.set(STORAGE_KEY[:access_token_map], @access_token_map)
  end

  def save_sign_in_session(data)
    raise ArgumentError, "Data must be a SignInSession" unless data.is_a?(SignInSession)
    @storage.set(STORAGE_KEY[:sign_in_session], data)
  end

  def clear_sign_in_session
    @storage.remove(STORAGE_KEY[:sign_in_session])
  end

  def fetch_jwks(options = {})
    if options[:kid_not_found] && ((@cache&.get("jwks_last_update") || 0) < Time.now.to_i - 300)
      @cache&.remove("jwks")
    end

    jwks_hash = @cache&.get("jwks") || begin
      response = JSON.parse(Net::HTTP.get(URI.parse(@core.oidc_config[:jwks_uri])))
      @cache&.set("jwks", response)
      @cache&.set("jwks_last_update", Time.now.to_i)
      response
    end

    jwks = JWT::JWK::Set.new(jwks_hash)
    jwks.select! { |key| key[:use] == "sig" } # Signing Keys only
    jwks
  end
end
