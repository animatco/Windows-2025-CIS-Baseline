# frozen_string_literal: true

module CisHelpers
  def cis_password_age_days(value)
    return nil if value.nil?

    # secedit export returns days already
    return value if value.is_a?(Integer) && value < 5000

    # registry fallback: seconds → days
    (value.to_i / 86_400)
  end
end
