require 'thor'
require 'json'

module Bundler
  module Audit
    class CLI < ::Thor
      module Formats
        module Json

          #
          # Prints any findings as JSON.
          #
          # @param [Report] report
          #   The results from the {Scanner}.
          #
          # @param [IO] output
          #   Optional output stream.
          #
          def print_report(report, output=$stdout)
            data = {vulnerable: false, insecure_sources: [], advisories: []}

            report.each do |result|
              case result
              when Results::InsecureSource
                data[:insecure_sources] << {url: result.source}
              when Results::UnpatchedGem
                gem = result.gem
                advisory = result.advisory
                advisory_item = {
                  name: gem.name,
                  version: gem.version,
                  advisory: advisory.cve ? "CVE-#{advisory.cve}" : advisory.osvdb,
                  criticality: advisory.criticality ? advisory.criticality.to_s.capitalize : 'Unknown',
                  url: advisory.url,
                  description: advisory.description,
                  title: advisory.title,
                  solution: advisory.patched_versions.empty? ? 'remove or disable this gem until a patch is available!' : "upgrade to #{advisory.patched_versions.join(', ')}"
                }
                data[:vulnerable] = true
                data[:advisories] << advisory_item
              end
            end

            output.puts JSON.pretty_generate(data)

          end
        end

        Formats.register :json, Json
      end
    end
  end
end
