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

  def revoke(client_id:, token:)
    response = Net::HTTP.post_form(
      URI.parse(oidc_config.revocation_endpoint),
      {
        QueryKey[:token] => token,
        QueryKey[:client_id] => client_id
      }
    )

    raise LogtoRevocationError.new(response.message, response: response) unless
      response.is_a?(Net::HTTPSuccess)
  end

  def fetch_token_by_authorization_code(client_id:, client_secret:, redirect_uri:, code_verifier:, code:, resource: nil)
    parameters = {
      QueryKey[:client_id] => client_id,
      QueryKey[:client_secret] => client_secret,
      QueryKey[:code] => code,
      QueryKey[:code_verifier] => code_verifier,
      QueryKey[:redirect_uri] => redirect_uri,
      QueryKey[:grant_type] => TokenGrantType[:authorization_code]
    }
    parameters[QueryKey[:resource]] = resource if resource

    response = Net::HTTP.post_form(
      URI.parse(oidc_config.token_endpoint),
      parameters
    )

    raise LogtoTokenError.new(response.message, response: response) unless
      response.is_a?(Net::HTTPSuccess)

    LogtoUtils.parse_json_safe(response.body, TokenResponse)
  end

  def fetch_token_by_refresh_token(client_id:, refresh_token:, resource: nil, organization_id: nil, scopes: nil)
    raise ArgumentError, "Scopes must be an array" if scopes && !scopes.is_a?(Array)

    parameters = {
      QueryKey[:client_id] => client_id,
      QueryKey[:refresh_token] => refresh_token,
      QueryKey[:grant_type] => TokenGrantType[:refresh_token]
    }
    parameters[QueryKey[:resource]] = resource if resource
    parameters[QueryKey[:organization_id]] = organization_id if organization_id
    parameters[QueryKey[:scope]] = scopes.join(" ") if scopes&.any?

    response = Net::HTTP.post_form(
      URI.parse(oidc_config.token_endpoint),
      parameters
    )

    raise LogtoTokenError.new(response.message, response: response) unless
      response.is_a?(Net::HTTPSuccess)
    LogtoUtils.parse_json_safe(response.body, TokenResponse)
  end

  def fetch_user_info(access_token:)
    uri = URI.parse(oidc_config.userinfo_endpoint)
    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = "Bearer #{access_token}"

    response = Net::HTTP.start(uri.host, uri.port) do |http|
      http.request(request)
    end

    raise LogtoUserInfoError.new(response.message, response: response) unless
      response.is_a?(Net::HTTPSuccess)
    LogtoUtils.parse_json_safe(response.body, UserInfoResponse)
  end

  def generate_sign_in_uri(client_id:, redirect_uri:, code_challenge:, state:, scopes: nil, resources: nil, prompt: nil, first_screen: nil, interaction_mode: nil, login_hint: nil, direct_sign_in: nil, extra_params: nil, include_reserved_scopes: true)
    parameters = {
      QueryKey[:client_id] => client_id,
      QueryKey[:redirect_uri] => redirect_uri,
      QueryKey[:code_challenge] => code_challenge,
      QueryKey[:code_challenge_method] => CodeChallengeMethod[:S256],
      QueryKey[:state] => state,
      QueryKey[:response_type] => "code"
    }

    parameters[QueryKey[:prompt]] = prompt&.any? ? prompt.join(" ") : Prompt[:consent]

    computed_scopes = include_reserved_scopes ? LogtoUtils.with_reserved_scopes(scopes).join(" ") : scopes&.join(" ")
    parameters[QueryKey[:scope]] = computed_scopes if computed_scopes

    parameters[QueryKey[:login_hint]] = login_hint if login_hint

    if direct_sign_in
      parameters[QueryKey[:direct_sign_in]] = "#{direct_sign_in[:method]}:#{direct_sign_in[:target]}"
    end

    parameters[QueryKey[:resource]] = resources if resources&.any?

    if first_screen
      parameters[QueryKey[:first_screen]] = first_screen
    elsif interaction_mode
      parameters[QueryKey[:interaction_mode]] = interaction_mode
    end

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
      QueryKey[:client_id] => client_id
    }
    parameters[QueryKey[:post_logout_redirect_uri]] = post_logout_redirect_uri if post_logout_redirect_uri

    uri = URI.parse(oidc_config.end_session_endpoint)
    uri.query = URI.encode_www_form(parameters)
    uri.to_s
  end

  protected

  # Function to fetch OIDC config from a Logto endpoint
  def fetch_oidc_config
    config_hash = @cache&.get("oidc_config") || begin
      response = Net::HTTP.get(URI.join(endpoint, DiscoveryPath))
      @cache&.set("oidc_config", response)
      response
    end
    LogtoUtils.parse_json_safe(config_hash, OidcConfigResponse)
  end
end
