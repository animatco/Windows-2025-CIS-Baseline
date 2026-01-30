# frozen_string_literal: true

#
# CIS helper: Convert MaximumPasswordAge from seconds → days
#
# Windows registry stores MaximumPasswordAge in SECONDS.
# CIS benchmarks expect DAYS.
#
# Example:
#   cis_password_age_days(7776000)  # => 90
#

module CisHelpers
  def cis_password_age_days(value)
    return nil if value.nil?

    # If secedit export succeeded, value is already in days (integer)
    return value if value.is_a?(Integer) && value < 5000

    # If registry fallback was used, value is in seconds
    # Convert seconds → days (rounded down)
    (value.to_i / 86_400)
  end
end

# Make helper available to all controls
Inspec::Resource.register_helper(CisHelpers)
