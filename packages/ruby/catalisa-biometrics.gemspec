# frozen_string_literal: true

require_relative "lib/catalisa/biometrics/version"

Gem::Specification.new do |spec|
  spec.name = "catalisa-biometrics"
  spec.version = Catalisa::Biometrics::VERSION
  spec.authors = ["Catalisa"]
  spec.email = ["contato@catalisa.app"]

  spec.summary = "Catalisa Biometrics SDK — liveness and face-match sessions, signed evidence and webhook verification"
  spec.description = "Ruby client for Catalisa Biometrics: opens verification sessions, reads the decision with its score and threshold, verifies the signed receipt offline and the webhook signature. Standard library only."
  spec.homepage = "https://docs.catalisa.app"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata = {
    "source_code_uri" => "https://github.com/catalisaio/catalisa-biometrics-sdk/tree/main/packages/ruby",
    "bug_tracker_uri" => "https://github.com/catalisaio/catalisa-biometrics-sdk/issues",
    "documentation_uri" => "https://docs.catalisa.app/blocks/biometrics/",
    "rubygems_mfa_required" => "true",
  }

  spec.files = Dir["lib/**/*.rb", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]
end
