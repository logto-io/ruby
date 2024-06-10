require 'json'
require_relative 'index_constants'

module LogtoUtils
  # Parses a JSON string and maps it to a given Struct class, handling unknown keys.
  # 
  # @param json_str [String] The JSON string to be parsed.
  # @param struct_class [Class] The Struct class to map the JSON data to. The strcut class must have a `:unknown_keys` member.
  # @return [Struct] An instance of the given Struct class populated with known keys and a hash of unknown keys.
  def self.parse_json_safe(json_str, struct_class)
    data = JSON.parse(json_str, symbolize_names: true)
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
    unique_scopes += LogtoCore::ReservedScope.values
    unique_scopes.uniq
  end
end
