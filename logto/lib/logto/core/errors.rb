# The base class for all errors in the Logto SDK.
class LogtoError < StandardError
  def initialize(message)
    super
  end

  # The base class for response errors from Logto server.
  #
  # @attr [Net::HTTPResponse, nil] response The response object that caused this error.
  class ResponseError < LogtoError
    attr_reader :response

    def initialize(message, response: nil)
      raise ArgumentError, "response must be a Net::HTTPResponse or nil" unless response.nil? || response.is_a?(Net::HTTPResponse)
      super(message)
      @response = response
    end
  end

  # Raise when token response is invalid.
  class TokenError < ResponseError
  end

  # Raise when revocation response is invalid.
  class RevocationError < ResponseError
  end

  # Raise when the userinfo response is invalid.
  class UserInfoError < ResponseError
  end

  # Raise when the current user is not authenticated but the operation requires authentication.
  class NotAuthenticatedError < LogtoError
  end
end
