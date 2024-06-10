require_relative "index_types"

class LogtoClient
  attr_reader :config

  # @param config [LogtoClient::Config] The configuration object for the Logto client.
  # @param navigate [Proc] The navigation function to be used for the sign-in experience.
  # @param storage [LogtoClient::AbstractStorage] The storage object for the Logto client.
  def initialize(config:, navigate:, storage: MemoryStorage.new)
    raise ArgumentError, "Config must be a LogtoClient::Config" unless config.is_a?(LogtoClient::Config)
    raise ArgumentError, "Navigate must be a Proc" unless navigate.is_a?(Proc)
    raise ArgumentError, "Storage must be a LogtoClient::AbstractStorage" unless storage.is_a?(LogtoClient::AbstractStorage)
    @config = config
    @navigate = navigate
    @storage = storage
    @core = LogtoCore.new(endpoint: @config.endpoint)
  end

  # Triggers the sign-in experience.
  #
  # @param redirect_uri [String] The redirect URI that the user will be redirected to after the sign-in experience is completed.
  # @param first_screen [String] The first screen that the user will see in the sign-in experience. Can be `signIn` or `register`.
  # @param login_hint [String] The login hint to be used for the sign-in experience.
  # @param direct_sign_in [Hash] The direct sign-in configuration to be used for the sign-in experience. It should contain the `method` and `target` keys.
  # @param extra_params [Hash] Extra parameters to be used for the sign-in experience.
  def signIn(redirect_uri:, first_screen: nil, login_hint: nil, direct_sign_in: nil, extra_params: nil)
    code_verifier = LogtoUtils.generate_code_verifier
    code_challenge = LogtoUtils.generate_code_challenge(code_verifier)
    state = LogtoUtils.generate_state

    puts "code_verifier: #{code_verifier}"
    puts "code_challenge: #{code_challenge}"

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

    @navigate.call(sign_in_uri)
  end
end
