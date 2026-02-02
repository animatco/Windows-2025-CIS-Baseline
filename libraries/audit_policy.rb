
# frozen_string_literal: true

class AuditPolicy < Inspec.resource(1)
  name 'audit_policy'
  desc 'Reads Windows Audit Policy categories via auditpol command.'
  supports platform: 'windows'

  def initialize
    super()
    @cache = nil
  end

  #
  # Get audit policy settings for a specific category
  #
  def category(category_name)
    return nil if category_name.nil?

    policies = parse_audit_policy
    policies[category_name.to_s]
  end

  #
  # Get all audit policies
  #
  def policies
    parse_audit_policy
  end

  def to_s
    'Audit Policy'
  end

  private

  #
  # Parse auditpol output and return hash of categories and their settings
  #
  def parse_audit_policy
    return @cache if @cache

    @cache = {}

    # Use auditpol to get audit policy settings
    ps = 'auditpol /get /category:* /r | ConvertFrom-Csv | Select-Object -Property "Category", "Subcategory", "Inclusion Setting"'
    cmd = inspec.command("powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"#{ps}\"")

    return @cache unless cmd.exit_status == 0

    output = cmd.stdout.to_s
    return @cache if output.empty?

    # Parse CSV output and group by category
    lines = output.split("\n").reject(&:empty?)

    lines.each do |line|
      parts = line.split(',')
      next unless parts.length >= 3

      category = parts[0].to_s.strip
      # inclusion_setting = parts[2].to_s.strip
      inclusion_setting = parts[2].to_s.strip.gsub('"', '')

      # Store unique inclusion settings per category
      if @cache[category].nil?
        @cache[category] = inclusion_setting
      else
        # If category has multiple subcategories with different settings, combine them
        existing = @cache[category].to_s
        current = inclusion_setting.to_s

        # Keep track of all unique settings for this category
        unless existing.include?(current)
          @cache[category] = "#{existing} and #{current}"
        end
      end
    end

    @cache
  end
end

# Ensure controls can always resolve the constant, regardless of InSpec load context.
Object.const_set(:AuditPolicy, AuditPolicy) unless Object.const_defined?(:AuditPolicy)
