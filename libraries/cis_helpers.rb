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
  #
  # Convert MaximumPasswordAge from seconds → days
  #
  # - secedit export returns days already
  # - registry fallback returns seconds
  #
  def cis_password_age_days(value)
    return nil if value.nil?

    # If already in days (secedit), return as-is
    return value if value.is_a?(Integer) && value < 5000

    # Registry fallback: seconds → days
    (value.to_i / 86_400)
  end
end
