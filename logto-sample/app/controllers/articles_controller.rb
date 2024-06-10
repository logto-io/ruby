require "../logto/client/index"

class ArticlesController < ApplicationController
  def initialize
    super
    @client = LogtoClient.new(
      config: LogtoClient::Config.new(
        endpoint: "http://localhost:3002",
        app_id: "client_id",
        app_secret: "client_secret"
      ),
      navigate: ->(uri) { redirect_to(uri, allow_other_host: true) }
    )
  end

  def index
  end

  def sign_in
    @client.signIn(redirect_uri: "https://example.com/callback")
  end
end
