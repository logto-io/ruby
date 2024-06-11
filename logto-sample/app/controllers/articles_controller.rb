require "../logto/client/index"

class ArticlesController < ApplicationController
  before_action :initialize_logto_client

  def index
  end

  def sign_in
    @client.sign_in(redirect_uri: ENV["LOGTO_REDIRECT_URI"])
  end

  def callback
    @client.handle_sign_in_callback(url: request.original_url)
  end

  private

  def initialize_logto_client
    @client = LogtoClient.new(
      config: LogtoClient::Config.new(
        endpoint: ENV["LOGTO_ENDPOINT"],
        app_id: ENV["LOGTO_APP_ID"],
        app_secret: ENV["LOGTO_APP_SECRET"]
      ),
      navigate: ->(uri) { redirect_to(uri, allow_other_host: true) },
      storage: LogtoClient::SessionStorage.new(session)
    )
  end
end
