# frozen_string_literal: true

module CisAuditPolicy

  #
  # Normalize audit policy values into a consistent array
  #
  def self.normalize(value)
    return [] if value.nil?

    Array(value)
      .map(&:to_s)
      .map(&:strip)
      .map(&:capitalize)
  end

  #
  # Check if audit policy matches expected values
  #
  def self.expected?(actual, expected)
    normalize(actual).sort == normalize(expected).sort
  end

end
