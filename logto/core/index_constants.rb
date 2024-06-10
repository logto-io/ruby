class LogtoCore
  DiscoveryPath = '/oidc/.well-known/openid-configuration'

  ContentType = {
    form_url_encoded: { 'Content-Type' => 'application/x-www-form-urlencoded' }
  }

  QueryKey = {
    client_id: 'client_id',
    token: 'token',
    code: 'code',
    code_verifier: 'code_verifier',
    redirect_uri: 'redirect_uri',
    grant_type: 'grant_type',
    refresh_token: 'refresh_token',
    scope: 'scope',
    state: 'state',
    response_type: 'response_type',
    resource: 'resource',
    organization_id: 'organization_id',
    login_hint: 'login_hint',
    direct_sign_in: 'direct_sign_in',
    first_screen: 'first_screen',
    interaction_mode: 'interaction_mode',
  }

  TokenGrantType = {
    authorization_code: 'authorization_code',
    refresh_token: 'refresh_token',
  }

  CodeChallengeMethod = {
    S256: 'S256',
  }

  Prompt = {
    login: 'login',
    none: 'none',
    consent: 'consent',
    select_account: 'select_account',
  }

  # Scopes that reserved by Logto, which will be added to the auth request automatically.
  ReservedScope = {
    openid: 'openid',
    offline_access: 'offline_access',
    profile: 'profile',
  }
end
