# frozen_string_literal: true

module CisHelpers
  def cis_password_age_days(value)
    return nil if value.nil?
    return value if value.is_a?(Integer) && value < 5000
    (value.to_i / 86_400)
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
Object.const_set(:CisHelpers, CisHelpers) unless Object.const_defined?(:CisHelpers)