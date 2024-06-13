require_relative "../core/errors"

class LogtoError
  # Raise when the session is not found in the storage.
  class SessionNotFoundError < LogtoError
  end

  # Raise when the session is found but the parameters are mismatched.
  class SessionMismatchError < LogtoError
  end

  # Raise when the session is found but the callback URI contains an error parameter.
  class ServerCallbackError < LogtoError
  end
end
