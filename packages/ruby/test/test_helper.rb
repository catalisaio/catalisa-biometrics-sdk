# frozen_string_literal: true

require "json"
require "minitest/autorun"
require_relative "../lib/catalisa/biometrics"

module VectorHelper
  # The vectors are shared by every SDK in this repository and were produced by
  # the building block's own signing code, so "it passes here" means the same
  # thing in each language.
  def vectors
    @vectors ||= JSON.parse(File.read(File.expand_path("../../../vectors/vectors.json", __dir__)))
  end
end
