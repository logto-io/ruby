require "net/http"
require "json"
require_relative "utils"

class LogtoCore
  # The non-exhaustive list of keys that return from the {https://openid.net/specs/openid-connect-discovery-1_0.html OpenID Connect Discovery} endpoint.
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

  # The response from the {https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint Token Endpoint} when fetching a token.
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

  # The claims that are returned in the {https://openid.net/specs/openid-connect-core-1_0.html#IDToken ID Token}.
  #
  # @attr [String] iss The issuer of this token.
  # @attr [String] sub The subject (user ID) of this token.
  # @attr [String] aud The audience (client ID) of this token.
  # @attr [Integer] exp The expiration time of this token.
  # @attr [Integer] iat The time at which this token was issued.
  # @attr [String, nil] at_hash The access token hash value.
  # @attr [String, nil] name The full name of the user.
  # @attr [String, nil] username The username of the user.
  # @attr [String, nil] picture The URL of the user's profile picture.
  # @attr [String, nil] email The email address of the user.
  # @attr [Boolean] email_verified Whether the user's email address has been verified.
  # @attr [String, nil] phone_number The phone number of the user.
  # @attr [Boolean] phone_number_verified Whether the user's phone number has been verified.
  # @attr [Array<String>] organizations The organization IDs that the user has membership in.
  # @attr [Array<String>] organization_roles All organization roles that the user has.
  #   The format is `[organizationId]:[roleName]`.
  #
  #   Note that not all organizations are included in this list, only the ones that the user has roles in.
  #   @example
  #     ['org1:admin', 'org2:member'] # The user is an admin of org1 and a member of org2.
  # @attr [Array<String>] roles The roles that the user has for API resources.
  IdTokenClaims = Struct.new(
    :iss, :sub, :aud, :exp, :iat, :at_hash, :name, :username, :picture,
    :email, :email_verified, :phone_number, :phone_number_verified,
    :organizations, :organization_roles, :roles, :unknown_keys,
    keyword_init: true
  )

  # The structured access token.
  #
  # @attr [String] token The access token string.
  # @attr [String] scope The scopes that this token has.
  # @attr [Integer] expires_at The epoch timestamp when this token will expire.
  AccessToken = Struct.new(:token, :scope, :expires_at, keyword_init: true)
end
