require 'net/http'
require 'json'
require_relative 'utils'

class LogtoCore
  OidcConfigResponse = Struct.new(
    :authorization_endpoint,
    :token_endpoint,
    :userinfo_endpoint,
    :end_session_endpoint,
    :revocation_endpoint,
    :jwks_uri,
    :issuer,
    :unknown_keys,
    keyword_init: true
  )

  TokenResponse = Struct.new(
    :access_token,
    :refresh_token,
    :id_token,
    :scope,
    :token_type,
    :expires_in,
    :unknown_keys,
    keyword_init: true
  )
end
