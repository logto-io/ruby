require "rspec"
require "./lib/core/utils"

RSpec.describe LogtoUtils do
  describe "#with_reserved_scopes" do
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

  describe "#generate_code_verifier" do
    it "generates a code verifier" do
      expect(LogtoUtils.generate_code_verifier.size).to eq(43)
    end
  end

  describe "#generate_code_challenge" do
    it "generates a code challenge" do
      expect(LogtoUtils.generate_code_challenge("code_verifier")).to eq("73oehA2tBul5grZPhXUGQwNAjxh69zNES8bu2bVD0EM")
    end
  end

  describe "#generate_state" do
    it "generates a state" do
      expect(LogtoUtils.generate_state.size).to eq(43)
    end
  end

  describe "#build_access_token_key" do
    it "builds a key without resource and organization ID" do
      expect(LogtoUtils.build_access_token_key(resource: nil)).to eq(":openid")
    end

    it "builds a key with resource and organization ID" do
      expect(LogtoUtils.build_access_token_key(resource: "resource", organization_id: "organization_id")).to eq("#organization_id:resource")
    end

    it "builds a key with resource and without organization ID" do
      expect(LogtoUtils.build_access_token_key(resource: "resource")).to eq(":resource")
    end

    it "builds a key without resource and with organization ID" do
      expect(LogtoUtils.build_access_token_key(resource: nil, organization_id: "organization_id")).to eq("#organization_id:openid")
    end
  end
end
