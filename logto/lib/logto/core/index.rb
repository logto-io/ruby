require "net/http"
require "uri"
require "jwt"
require_relative "index_types"
require_relative "index_constants"
require_relative "utils"
require_relative "errors"

class LogtoCore
  attr_reader :endpoint, :oidc_config

  def initialize(endpoint:, cache: nil)
    @endpoint = endpoint
    @cache = cache
    @oidc_config = fetch_oidc_config
  end

  def revoke_token(client_id:, client_secret:, token:)
    response = Net::HTTP.post_form(
      URI.parse(oidc_config.revocation_endpoint),
      {
        QUERY_KEY[:token] => token,
        QUERY_KEY[:client_id] => client_id,
        QUERY_KEY[:client_secret] => client_secret
      }
    )

    raise LogtoError::RevocationError.new(response.message, response: response) unless
      response.is_a?(Net::HTTPSuccess)
  end

  def fetch_token_by_authorization_code(client_id:, client_secret:, redirect_uri:, code_verifier:, code:, resource: nil)
    parameters = {
      QUERY_KEY[:client_id] => client_id,
      QUERY_KEY[:client_secret] => client_secret,
      QUERY_KEY[:code] => code,
      QUERY_KEY[:code_verifier] => code_verifier,
      QUERY_KEY[:redirect_uri] => redirect_uri,
      QUERY_KEY[:grant_type] => TOKEN_GRANT_TYPE[:authorization_code]
    }
    parameters[QUERY_KEY[:resource]] = resource if resource

    response = Net::HTTP.post_form(
      URI.parse(oidc_config.token_endpoint),
      parameters
    )

    raise LogtoError::TokenError.new(response.message, response: response) unless
      response.is_a?(Net::HTTPSuccess)

    LogtoUtils.parse_json_safe(response.body, TokenResponse)
  end

  def fetch_token_by_refresh_token(client_id:, client_secret:, refresh_token:, resource: nil, organization_id: nil, scopes: nil)
    raise ArgumentError, "Scopes must be an array" if scopes && !scopes.is_a?(Array)

    parameters = {
      QUERY_KEY[:client_id] => client_id,
      QUERY_KEY[:client_secret] => client_secret,
      QUERY_KEY[:refresh_token] => refresh_token,
      QUERY_KEY[:grant_type] => TOKEN_GRANT_TYPE[:refresh_token]
    }
    parameters[QUERY_KEY[:resource]] = resource if resource
    parameters[QUERY_KEY[:organization_id]] = organization_id if organization_id
    parameters[QUERY_KEY[:scope]] = scopes.join(" ") if scopes&.any?

    response = Net::HTTP.post_form(
      URI.parse(oidc_config.token_endpoint),
      parameters
    )

    raise LogtoError::TokenError.new(response.message, response: response) unless
      response.is_a?(Net::HTTPSuccess)
    LogtoUtils.parse_json_safe(response.body, TokenResponse)
  end

  def fetch_user_info(access_token:)
    uri = URI.parse(oidc_config.userinfo_endpoint)
    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = "Bearer #{access_token}"

    response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
      http.request(request)
    end

    raise LogtoError::UserInfoError.new(response.message, response: response) unless
      response.is_a?(Net::HTTPSuccess)
    LogtoUtils.parse_json_safe(response.body, UserInfoResponse)
  end

  def generate_sign_in_uri(
    client_id:,
    redirect_uri:,
    code_challenge:,
    state:,
    scopes: nil,
    resources: nil,
    prompt: nil,
    first_screen: nil,
    identifiers: nil,
    interaction_mode: nil,
    login_hint: nil,
    direct_sign_in: nil,
    extra_params: nil,
    include_reserved_scopes: true
  )
    parameters = {
      QUERY_KEY[:client_id] => client_id,
      QUERY_KEY[:redirect_uri] => redirect_uri,
      QUERY_KEY[:code_challenge] => code_challenge,
      QUERY_KEY[:code_challenge_method] => CODE_CHALLENGE_METHOD[:S256],
      QUERY_KEY[:state] => state,
      QUERY_KEY[:response_type] => "code"
    }

    parameters[QUERY_KEY[:prompt]] = prompt&.any? ? prompt.join(" ") : PROMPT[:consent]

    computed_scopes = include_reserved_scopes ? LogtoUtils.with_reserved_scopes(scopes).join(" ") : scopes&.join(" ")
    parameters[QUERY_KEY[:scope]] = computed_scopes if computed_scopes

    parameters[QUERY_KEY[:login_hint]] = login_hint if login_hint

    if direct_sign_in
      parameters[QUERY_KEY[:direct_sign_in]] = "#{direct_sign_in[:method]}:#{direct_sign_in[:target]}"
    end

    parameters[QUERY_KEY[:resource]] = resources if resources&.any?

    if first_screen
      parameters[QUERY_KEY[:first_screen]] = first_screen
    elsif interaction_mode
      parameters[QUERY_KEY[:interaction_mode]] = interaction_mode
    end

    parameters[QUERY_KEY[:identifier]] = identifiers.join(" ") if identifiers&.any?

    extra_params&.each do |key, value|
      parameters[key] = value
    end

    parameters.each_key do |key|
      raise ArgumentError, "Parameters contain nil key, please check the input" if key.nil?
    end

    uri = URI.parse(oidc_config.authorization_endpoint)
    uri.query = URI.encode_www_form(parameters)
    uri.to_s
  end

  def generate_sign_out_uri(client_id:, post_logout_redirect_uri: nil)
    parameters = {
      QUERY_KEY[:client_id] => client_id
    }
    parameters[QUERY_KEY[:post_logout_redirect_uri]] = post_logout_redirect_uri if post_logout_redirect_uri

    uri = URI.parse(oidc_config.end_session_endpoint)
    uri.query = URI.encode_www_form(parameters)
    uri.to_s
  end

  protected

  # Function to fetch OIDC config from a Logto endpoint
  def fetch_oidc_config
    config_hash = @cache&.get("oidc_config") || begin
      response = Net::HTTP.get(URI.join(endpoint, DISCOVERY_PATH))
      @cache&.set("oidc_config", response)
      response
    end
    LogtoUtils.parse_json_safe(config_hash, OidcConfigResponse)
  end
end
