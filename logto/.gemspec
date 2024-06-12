Gem::Specification.new do |s|
  s.name = "logto"
  s.version = "0.1.0"
  s.licenses = ["MIT"]
  s.summary = "The Logto SDK for Ruby."
  s.description = "Logto is an open-source Auth0 alternative designed for modern apps and SaaS products."
  s.authors = ["Silverhand Inc."]
  s.email = "contact@logto.io"
  s.files = ["lib/core.rb", "lib/client.rb"]
  s.homepage = "https://logto.io/"
  s.metadata = {"source_code_uri" => "https://github.com/logto-io/ruby"}
  s.add_runtime_dependency "jwt", "~> 2.8"
end
