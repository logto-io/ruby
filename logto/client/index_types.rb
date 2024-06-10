require_relative "../core"
require_relative "../core/utils"

class LogtoClient
  # The configuration object for the Logto client.
  #
  # @attr [String] endpoint The endpoint for the Logto server, you can get it from the integration guide
  #   or the team settings page of the Logto Console.
  #   @example
  #     'https://foo.logto.app'
  # @attr [String] app_id The client ID of your application, you can get it from the integration guide
  #   or the application details page of the Logto Console.
  # @attr [String] app_secret The client secret of your application, you can get it from the application
  #   details page of the Logto Console.
  # @attr [Array<String>] scopes The scopes (permissions) that your application needs to access.
  #   Scopes that will be added by default: `openid`, `offline_access` and `profile`.
  #   If resources are specified, scopes will be applied to every resource.
  #
  #   See {https://docs.logto.io/quick-starts/rails/#scopes-and-claims Scopes and claims}
  #   for more information of available scopes for user information.
  # @attr [Array<String>] resources The API resources that your application needs to access. You can specify
  #   multiple resources by providing an array of strings.
  #
  #   See {https://docs.logto.io/docs/recipes/rbac RBAC} to learn more about how to use role-based access control (RBAC) to protect API resources.
  # @attr [Array<String>] prompt The prompt parameter to be used for the authorization request.
  class Config
    attr_reader :endpoint, :app_id, :app_secret, :scopes, :resources, :prompt

    # @param endpoint [String] The endpoint for the Logto server.
    # @param app_id [String] The client ID of your application.
    # @param app_secret [String] The client secret of your application.
    # @param scopes [Array<String>] The scopes that your application needs to access.
    # @param resources [Array<String>] The API resources that your application needs to access.
    # @param prompt [String, Array<String>] The prompt parameter to be used for the authorization request.
    # @param include_reserved_scopes [Boolean] Whether to include reserved scopes (`openid`, `offline_access` and `profile`) in the scopes.
    def initialize(endpoint:, app_id:, app_secret:, scopes: [], resources: [], prompt: LogtoCore::Prompt[:consent], include_reserved_scopes: true)
      raise ArgumentError, "Scopes must be an array" if scopes && !scopes.is_a?(Array)
      raise ArgumentError, "Resources must be an array" if resources && !resources.is_a?(Array)

      computed_scopes = include_reserved_scopes ? LogtoUtils.with_reserved_scopes(scopes) : scopes

      @endpoint = endpoint
      @app_id = app_id
      @app_secret = app_secret
      @scopes = computed_scopes
      @resources = computed_scopes.include?(LogtoCore::UserScope[:organizations]) ? ([LogtoCore::ReservedResource[:organization]] + resources).uniq : resources
      @prompt = prompt.is_a?(Array) ? prompt : [prompt]
    end
  end

  # An abstract class for storing data.
  #
  # This class is used by the Logto client to store the session and token data.
  #
  # @abstract
  class AbstractStorage
    def initialize
      raise NotImplementedError
    end

    def get(key)
      raise NotImplementedError
    end

    def set(key, value)
      raise NotImplementedError
    end

    def remove(key)
      raise NotImplementedError
    end
  end

  # A storage class that stores data in memory.
  #
  # WARNING: This storage is not suitable for production use.
  class MemoryStorage < AbstractStorage
    def initialize
      @store = {}
      warn "WARNING: MemoryStorage is not suitable for production use. Replace it with a persistent storage for production."
    end

    def get(key)
      @store[key]
    end

    def set(key, value)
      @store[key] = value
    end

    def remove(key)
      @store.delete(key)
    end
  end
end
