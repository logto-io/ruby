require_relative "index_constants"
require_relative "index_types"
require_relative "index_storage"
require_relative "errors"

class LogtoClient
  attr_reader :config

  # @param config [LogtoClient::Config] The configuration object for the Logto client.
  # @param navigate [Proc] The navigation function to be used for the sign-in experience.
  # @param storage [LogtoClient::AbstractStorage] The storage object for the Logto client.
  def initialize(config:, navigate:, storage:)
    raise ArgumentError, "Config must be a LogtoClient::Config" unless config.is_a?(LogtoClient::Config)
    raise ArgumentError, "Navigate must be a Proc" unless navigate.is_a?(Proc)
    raise ArgumentError, "Storage must be a LogtoClient::AbstractStorage" unless storage.is_a?(LogtoClient::AbstractStorage)
    @config = config
    @navigate = navigate
    @storage = storage
    @core = LogtoCore.new(endpoint: @config.endpoint)
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

  def handle_sign_in_callback(url:)
    query_params = URI.decode_www_form(URI(url).query).to_h
    data = @storage.get(STORAGE_KEY[:sign_in_session])
    raise SessionNotFoundError, "No sign-in session found" unless data

    error = query_params[LogtoCore::QueryKey[:error]]
    error_description = query_params[LogtoCore::QueryKey[:error_description]]
    raise CallbackErrorFromServer, "Error: #{error}, Description: #{error_description}" if error

    current_session = SignInSession.new(@storage.get(STORAGE_KEY[:sign_in_session]))
    # A loose URI check here
    raise SessionMismatchError, "Redirect URI mismatch" unless url.start_with?(current_session.redirect_uri)
    raise SessionMismatchError, "No state found in query parameters" unless query_params[LogtoCore::QueryKey[:state]]
    raise SessionMismatchError, "Session state mismatch" unless current_session.state == query_params[LogtoCore::QueryKey[:state]]
    raise SessionMismatchError, "No code found in query parameters" unless query_params[LogtoCore::QueryKey[:code]]

    code_response = @core.fetch_token_by_authorization_code(
      client_id: @config.app_id,
      client_secret: @config.app_secret,
      redirect_uri: current_session.redirect_uri,
      code_verifier: current_session.code_verifier,
      code: query_params[LogtoCore::QueryKey[:code]]
    )

    # TODO: Verify ID token

    save_refresh_token(code_response[:refresh_token])
    save_id_token(code_response[:id_token])
    save_access_token(
      key: LogtoUtils.build_access_token_key(resource: nil),
      token: LogtoCore::AccessToken.new(
        token: code_response[:access_token],
        scope: code_response[:scope],
        expires_at: Time.now + code_response[:expires_in].to_i
      )
    )
    clear_sign_in_session

    if data[:post_redirect_uri]
      @navigate.call(data[:post_redirect_uri])
    end
  end

  protected

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

  def clear_all_tokens
    @access_token_map = {}
    @storage.remove(STORAGE_KEY[:access_token_map])
    @storage.remove(STORAGE_KEY[:id_token])
    @storage.remove(STORAGE_KEY[:refresh_token])
  end

  def save_sign_in_session(data)
    raise ArgumentError, "Data must be a SignInSession" unless data.is_a?(SignInSession)
    @storage.set(STORAGE_KEY[:sign_in_session], data)
  end

  def clear_sign_in_session
    @storage.remove(STORAGE_KEY[:sign_in_session])
  end
end
