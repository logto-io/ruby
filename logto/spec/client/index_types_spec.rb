require "rspec"
require "./lib/client/index_types"

RSpec.describe LogtoClient::Config do
  it "initializes with the correct values" do
    config = LogtoClient::Config.new(
      endpoint: "https://example.com",
      app_id: "app_id",
      app_secret: "app_secret",
      scopes: ["openid"],
      resources: ["resource"],
      prompt: "prompt"
    )

    expect(config.endpoint.to_s).to eq("https://example.com")
    expect(config.app_id).to eq("app_id")
    expect(config.app_secret).to eq("app_secret")
    expect(config.scopes).to eq(["openid", "offline_access", "profile"])
    expect(config.resources).to eq(["resource"])
    expect(config.prompt).to eq(["prompt"])
  end

  it "initializes with the correct resources when organizations scope is included" do
    config = LogtoClient::Config.new(
      endpoint: "https://example.com",
      app_id: "app_id",
      app_secret: "app_secret",
      scopes: ["openid", LogtoCore::UserScope[:organizations]],
      resources: ["resource"]
    )

    expect(config.resources).to eq([LogtoCore::ReservedResource[:organization], "resource"])
    expect(config.scopes).to eq(["openid", LogtoCore::UserScope[:organizations], "offline_access", "profile"])
  end

  it "initializes with the correct values when no prompt is provided and include_reserved_scopes is false" do
    config = LogtoClient::Config.new(
      endpoint: "https://example.com",
      app_id: "app_id",
      app_secret: "app_secret",
      scopes: ["openid"],
      resources: ["resource"],
      include_reserved_scopes: false
    )

    expect(config.prompt).to eq(["consent"])
    expect(config.scopes).to eq(["openid"])
  end

  it "raises an error when scopes or resources are not arrays" do
    expect {
      LogtoClient::Config.new(
        endpoint: "https://example.com",
        app_id: "app_id",
        app_secret: "app_secret",
        scopes: "openid"
      )
    }.to raise_error(ArgumentError)

    expect {
      LogtoClient::Config.new(
        endpoint: "https://example.com",
        app_id: "app_id",
        app_secret: "app_secret",
        resources: "resource"
      )
    }.to raise_error(ArgumentError)
  end
end
