# frozen_string_literal: true

module CisPasswordPolicy

  SECONDS_PER_DAY = 86_400
  SECONDS_PER_MINUTE = 60

  def self.max_age_days(value)
    return nil if value.nil?
    return value if value.is_a?(Integer) && value < 5000
    (value.to_i / SECONDS_PER_DAY)
  end

  def self.min_age_days(value)
    return nil if value.nil?
    return value if value.is_a?(Integer) && value < 5000
    (value.to_i / SECONDS_PER_DAY)
  end

  def self.lockout_minutes(value)
    return nil if value.nil?
    (value.to_i / SECONDS_PER_MINUTE)
  end

  def self.reset_lockout_minutes(value)
    return nil if value.nil?
    (value.to_i / SECONDS_PER_MINUTE)
  end

  def self.lockout_threshold(value)
    return nil if value.nil?
    value.to_i
  end

  def self.complexity_enabled?(value)
    value.to_i == 1
  end

  def self.reversible_encryption_disabled?(value)
    value.to_i == 0
  end

  def self.admin_lockout_enabled?(value)
    value.to_i == 1
  end

end
