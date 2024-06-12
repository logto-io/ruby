require "rspec"
require "./lib/core/utils"

RSpec.describe "#with_reserved_scopes" do
  it "includes custom scope" do
    expect(LogtoUtils.with_reserved_scopes(["custom_scope"])).to eq(["custom_scope", "openid", "offline_access", "profile"])
  end

  it "handles nil input" do
    expect(LogtoUtils.with_reserved_scopes(nil)).to eq(["openid", "offline_access", "profile"])
  end

  it "removes duplicate scopes" do
    expect(LogtoUtils.with_reserved_scopes(["openid", "offline_access", "profile"])).to eq(["openid", "offline_access", "profile"])
  end
end
