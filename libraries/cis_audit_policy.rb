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

# Ensure controls can always resolve constants, regardless of InSpec load context.
if defined?(Object) && defined?(self)
  constants.each do |c|
    next if Object.const_defined?(c)
    Object.const_set(c, const_get(c))
  end
end

# Ensure controls can always resolve the constant, regardless of InSpec load context.
Object.const_set(:CisAuditPolicy, CisAuditPolicy) unless Object.const_defined?(:CisAuditPolicy)
