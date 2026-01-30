# frozen_string_literal: true

# Resource: auditpol_subcategory('{GUID}')
# Provides: inclusion_setting

class AuditpolSubcategory < Inspec.resource(1)
  name 'auditpol_subcategory'
  desc 'Reads Advanced Audit Policy subcategory settings via auditpol.'
  supports platform: 'windows'

  def initialize(guid)
    super()
    @guid = guid.to_s
  end

  def inclusion_setting
    ps = %(powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "AuditPol /get /subcategory:'#{@guid}' -r | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'")
    cmd = inspec.command(ps)
    return nil unless cmd.exit_status == 0
    cmd.stdout.to_s.strip
  end

  def to_s
    "AuditPol subcategory #{@guid}"
  end
end

# Ensure controls can always resolve constants, regardless of InSpec load context.
if defined?(Object) && defined?(self)
  constants.each do |c|
    next if Object.const_defined?(c)
    Object.const_set(c, const_get(c))
  end
end

