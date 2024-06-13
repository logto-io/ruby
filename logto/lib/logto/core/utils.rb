require "json"
require_relative "index_constants"

module LogtoUtils
  # Parses a JSON string and maps it to a given Struct class, handling unknown keys.
  #
  # @param json_str_or_hash [String, Hash] The JSON string or hash to be parsed.
  # @param struct_class [Class] The Struct class to map the JSON data to. The strcut class must have a
  #   `:unknown_keys` member and a `keyword_init: true` keyword argument.
  # @return [Struct] An instance of the given Struct class populated with known keys and a hash of unknown keys.
  def self.parse_json_safe(json_str_or_hash, struct_class)
    data = json_str_or_hash.is_a?(String) ? JSON.parse(json_str_or_hash) : json_str_or_hash
    known_keys = struct_class.members - [:unknown_keys]
    known_data = data.select { |key, _| known_keys.include?(key.to_sym) }
    unknown_data = data.reject { |key, _| known_keys.include?(key.to_sym) }
    struct_class.new(**known_data, unknown_keys: unknown_data)
  end

  # @param scopes [Array<String>, nil] The scopes to be added reserved scopes to.
  # @return [Array<String>] The scopes with reserved scopes added.
  # @example
  #   LogtoUtils.with_reserved_scopes(['foo', 'bar'])
  #   # => ['foo', 'bar', 'openid', 'offline_access', 'profile']
  def self.with_reserved_scopes(scopes)
    unique_scopes = scopes || []
    unique_scopes += LogtoCore::RESERVED_SCOPE.values
    unique_scopes.uniq
  end

  def self.generate_code_verifier
    SecureRandom.urlsafe_base64(32)
  end

  def self.generate_code_challenge(code_verifier)
    Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier)).tr("=", "")
  end

  def self.generate_state
    SecureRandom.urlsafe_base64(32)
  end

  def self.build_access_token_key(resource:, organization_id: nil)
    "#{organization_id ? "##{organization_id}" : ""}:#{resource || "openid"}"
  end
end
