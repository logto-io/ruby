require "logto/client"

class SampleController < ApplicationController
  before_action :initialize_logto_client

  def index
    @is_authenticated = @client.is_authenticated?
    @id_token = @client.id_token
  end

  def sign_in
    @client.sign_in(redirect_uri: request.base_url + "/callback", post_redirect_uri: "/")
  end

  def sign_out
    @client.sign_out(post_logout_redirect_uri: request.base_url)
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
        # Uncomment the following lines to specify the scopes and resources that your application needs to access.
        # resources: ["https://shopping.api/"],
        # scopes: ["read:resource"]
      ),
      navigate: ->(uri) { redirect_to(uri, allow_other_host: true) },
      storage: LogtoClient::SessionStorage.new(session)
    )
  end
end
