require "../logto/core"

class ArticlesController < ApplicationController
  def index
    puts LogtoCore.new(endpoint: 'http://localhost:3002').generate_sign_in_uri(
      client_id: 'client_id',
      redirect_uri: 'http://localhost:3000/auth/logto/callback',
      code_challenge: 'code_challenge',
      state: 'state',
    )
  end
end
