class LogtoCore
  DiscoveryPath = "/oidc/.well-known/openid-configuration"

  ContentType = {
    form_url_encoded: {"Content-Type" => "application/x-www-form-urlencoded"}
  }

  QueryKey = {
    client_id: "client_id",
    token: "token",
    code: "code",
    code_verifier: "code_verifier",
    code_challenge: "code_challenge",
    code_challenge_method: "code_challenge_method",
    prompt: "prompt",
    redirect_uri: "redirect_uri",
    post_logout_redirect_uri: "post_logout_redirect_uri",
    grant_type: "grant_type",
    refresh_token: "refresh_token",
    scope: "scope",
    state: "state",
    response_type: "response_type",
    resource: "resource",
    organization_id: "organization_id",
    login_hint: "login_hint",
    direct_sign_in: "direct_sign_in",
    first_screen: "first_screen",
    interaction_mode: "interaction_mode"
  }

  TokenGrantType = {
    authorization_code: "authorization_code",
    refresh_token: "refresh_token"
  }

  CodeChallengeMethod = {
    S256: "S256"
  }

  Prompt = {
    login: "login",
    none: "none",
    consent: "consent",
    select_account: "select_account"
  }

  # Scopes that reserved by Logto, which will be added to the auth request automatically.
  ReservedScope = {
    openid: "openid",
    offline_access: "offline_access",
    profile: "profile"
  }

  # Scopes for ID Token and Userinfo Endpoint.
  UserScope = {
    # Scope for basic user ingo.
    profile: "profile",
    # Scope for email address.
    email: "email",
    # Scope for phone number.
    phone: "phone",
    # Scope for user's custom data.
    custom_data: "custom_data",
    # Scope for user's social identity details.
    identities: "identities",
    # Scope for user's roles.
    roles: "roles",
    # Scope for user's organization IDs and perform organization token grant per {https://github.com/logto-io/rfcs RFC 0001}.
    organizations: "urn:logto:scope:organizations",
    # Scope for user's organization roles per {https://github.com/logto-io/rfcs RFC 0001}.
    organization_roles: "urn:logto:scope:organization_roles"
  }

  # Resources that reserved by Logto, which cannot be defined by users.
  ReservedResource = {
    # The resource for organization template per {https://github.com/logto-io/rfcs RFC 0001}.
    organization: "urn:logto:resource:organizations"
  }
end
