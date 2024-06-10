class LogtoError < StandardError
  def initialize(message)
    super(message)
  end
end

class LogtoResponseError < LogtoError
  attr_reader :response

  def initialize(message, response:)
    super(message)
    @response = response
  end
end

class LogtoTokenError < LogtoResponseError
end

class LogtoRevocationError < LogtoResponseError
end
