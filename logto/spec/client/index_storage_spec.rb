require "rspec"
require "./lib/client/index_storage"

RSpec.describe LogtoClient::SessionStorage do
  let(:session) { {} }
  let(:app_id) { "app_id" }
  let(:storage) { LogtoClient::SessionStorage.new(session, app_id: app_id) }

  it "sets and gets the value" do
    storage.set("key", "value")
    expect(storage.get("key")).to eq("value")
    expect(session["logto_#{app_id}_key"]).to eq("value")
  end

  it "removes the value" do
    storage.set("key", "value")
    storage.remove("key")
    expect(storage.get("key")).to be_nil
  end
end

RSpec.describe LogtoClient::RailsCacheStorage do
  let(:app_id) { "app_id" }
  let(:storage) { LogtoClient::RailsCacheStorage.new(app_id: app_id) }

  before do
    cached_data = {}
    @cache = double("cache")
    allow(@cache).to receive(:read) { |key| cached_data[key] }
    allow(@cache).to receive(:write) { |key, value, force: false| cached_data[key] = value }
    allow(@cache).to receive(:delete) { |key| cached_data.delete(key) }
    Rails = double("Rails", cache: @cache)
  end

  it "sets and gets the value" do
    storage.set("key", "value")
    expect(storage.get("key")).to eq("value")
    expect(@cache).to have_received(:write).with("logto_cache_#{app_id}_key", "value", force: true)
  end

  it "removes the value" do
    storage.set("key", "value")
    storage.remove("key")
    expect(storage.get("key")).to be nil
    expect(@cache).to have_received(:delete).with("logto_cache_#{app_id}_key")
  end
end
