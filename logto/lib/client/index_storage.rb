class LogtoClient
  # :nocov:

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
  # :nocov:

  # A storage class that stores data in Rails session.
  class SessionStorage < AbstractStorage
    def initialize(session, app_id: nil)
      @session = session
      @app_id = app_id
    end

    def get(key)
      @session[getSessionKey(key)]
    end

    def set(key, value)
      @session[getSessionKey(key)] = value
    end

    def remove(key)
      @session.delete(getSessionKey(key))
    end

    protected

    def getSessionKey(key)
      "logto_#{@app_id || "default"}_#{key}"
    end
  end

  class RailsCacheStorage < AbstractStorage
    def initialize(app_id: nil)
      @app_id = app_id
    end

    def get(key)
      Rails.cache.read(getCacheKey(key))
    end

    def set(key, value)
      Rails.cache.write(getCacheKey(key), value, force: true)
    end

    def remove(key)
      Rails.cache.delete(getCacheKey(key))
    end

    protected

    def getCacheKey(key)
      "logto_cache_#{@app_id || "default"}_#{key}"
    end
  end
end
