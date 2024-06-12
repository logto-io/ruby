require_relative "../core/errors"

class SessionNotFoundError < LogtoError
end

class SessionMismatchError < LogtoError
end

class CallbackErrorFromServer < LogtoError
end
