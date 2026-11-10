#!/usr/bin/env ruby
# frozen_string_literal: true

# Local checker for PHP2Shell, the CVE-2026-109618/CVE-2026-109619 RCE pair in PHP.
# Both give unauthenticated remote code execution, CVSS v4.0 9.2, fixed 2026-10-21.
# It runs locally only: no network, no exploitation, just version and patch checks.
#
# Usage:
#   ruby php2shell_check.rb                 # check every PHP binary on PATH
#   ruby php2shell_check.rb /usr/bin/php8.3 # check one specific binary
#
# Exit codes:
#   0  everything found is patched
#   1  at least one install is vulnerable
#   2  manual review needed, or no PHP found

require "English"
require "zlib"
require "shellwords"

module Php2shell
  # Advisory facts: the CVE IDs, the first fixed release per branch, and the match pattern.
  module Advisory
    CVES = %w[CVE-2026-109618 CVE-2026-109619].freeze
    FIXED = {
      "8.2" => "8.2.35",
      "8.3" => "8.3.36",
      "8.4" => "8.4.27",
      "8.5" => "8.5.12",
    }.freeze
    HIGHEST_BRANCH = "8.5"
    PATTERN = /CVE-2026-10961[89]/

    def self.fixed_for(branch)
      FIXED[branch]
    end

    def self.supported_branch?(branch)
      FIXED.key?(branch)
    end

    # Changelogs can carry non-UTF-8 bytes, so scrub before matching.
    def self.mentions_cve?(text)
      return false if text.nil?

      text.dup.force_encoding("UTF-8").scrub("").match?(PATTERN)
    end
  end

  # Looks up executables on PATH.
  module Command
    def self.available?(name)
      dirs.any? { |dir| File.executable?(File.join(dir, name)) }
    end

    def self.dirs
      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR)
    end
  end

  # Wraps text in ANSI color, only on a TTY.
  module Ansi
    CODES = { green: "32", red: "31", yellow: "33", blue: "34" }.freeze

    def self.paint(io, text, color)
      io.tty? ? "\e[#{CODES.fetch(color)}m#{text}\e[0m" : text
    end
  end

  # One PHP install we found.
  Install = Struct.new(:path, :version, :sapi, keyword_init: true) do
    def readable?
      !version.nil?
    end

    def branch
      version.split(".").first(2).join(".")
    end

    def label
      [version || "unknown", sapi && "(#{sapi})"].compact.join(" ")
    end
  end

  # One verdict: a status and a human-readable reason.
  Verdict = Struct.new(:status, :detail, keyword_init: true)

  # Finds candidate PHP executables on PATH.
  class BinaryFinder
    BASE_NAMES = %w[php php-fpm php-cgi].freeze
    BRANCHES = (2..9).map { |minor| "8.#{minor}" }.freeze

    def paths
      names.flat_map { |name| executables_named(name) }.uniq { |path| real(path) }.sort
    end

    private

    def names
      BASE_NAMES + BRANCHES.flat_map { |branch| ["php#{branch}", "php-fpm#{branch}"] }
    end

    def executables_named(name)
      Command.dirs.map { |dir| File.join(dir, name) }.select { |path| runnable?(path) }
    end

    def runnable?(path)
      File.file?(path) && File.executable?(path)
    end

    def real(path)
      File.realpath(path)
    rescue StandardError
      path
    end
  end

  # Reads version and SAPI out of a single binary via `php -v`.
  class VersionReader
    def initialize(path)
      @path = path
    end

    def install
      output = capture
      Install.new(path: @path, version: version_in(output), sapi: sapi_in(output))
    end

    private

    def capture
      output = `#{Shellwords.escape(@path)} -v 2>&1`
      $CHILD_STATUS.success? ? output : nil
    rescue StandardError
      nil
    end

    def version_in(output)
      output&.slice(/^PHP\s+(\d+\.\d+\.\d+)/, 1)
    end

    def sapi_in(output)
      output&.slice(/\(([a-z\-]+)\)/, 1)
    end
  end

  # Checks the package manager for a backported fix: :fixed, :unfixed, or :unknown.
  # Distro builds keep the old version string, so the changelog is the real signal.
  class PackageAudit
    def state
      states = [debian_state, rpm_state]
      return :fixed if states.include?(:fixed)
      return :unfixed if states.include?(:unfixed)

      :unknown
    end

    private

    def debian_state
      texts = debian_packages.flat_map { |package| changelogs_for(package) }.compact
      verdict_from(texts)
    end

    def rpm_state
      return :unknown if rpm_packages.empty?

      verdict_from([rpm_changelog(rpm_packages)])
    end

    def verdict_from(texts)
      return :unknown if texts.empty?

      texts.any? { |text| Advisory.mentions_cve?(text) } ? :fixed : :unfixed
    end

    def debian_packages
      return [] unless Command.available?("dpkg-query")

      lines(`dpkg-query -W -f='${Package}\n' 'php*' 2>/dev/null`)
    end

    def rpm_packages
      return [] unless Command.available?("rpm")

      lines(`rpm -qa 'php*' 2>/dev/null`)
    end

    def changelogs_for(package)
      Dir.glob("/usr/share/doc/#{package}/changelog*").map { |path| read(path) }
    end

    def rpm_changelog(packages)
      `rpm -q --changelog #{packages.shelljoin} 2>/dev/null`
    end

    def read(path)
      path.end_with?(".gz") ? Zlib::GzipReader.open(path, &:read) : File.read(path)
    rescue StandardError
      nil
    end

    def lines(output)
      output.split("\n").map(&:strip).reject(&:empty?)
    end
  end

  # Turns one install (plus the package audit) into a verdict.
  class Assessment
    def initialize(install, audit: PackageAudit.new)
      @install = install
      @audit = audit
    end

    def verdict
      return unreadable unless @install.readable?
      return newer_than_data if beyond_known_branches?
      return supported_branch_verdict if Advisory.supported_branch?(branch)

      eol_branch_verdict
    end

    private

    def unreadable
      review("could not read a version from this binary; check it by hand")
    end

    def supported_branch_verdict
      fixed = Advisory.fixed_for(branch)
      return patched("#{version} is at or above the upstream fix #{fixed}") if at_least?(fixed)

      below_fix_verdict(fixed)
    end

    def below_fix_verdict(fixed)
      case @audit.state
      when :fixed
        patched("#{version} is below upstream #{fixed}, but the OS package changelog names the CVE (backported fix)")
      when :unfixed
        vulnerable("#{version} is below the upstream fix #{fixed} and no package changelog names the CVE")
      else
        review("#{version} is below the upstream fix #{fixed}; this is not a distro-managed package, " \
               "so a Homebrew/source/manual build at this version is vulnerable. Verify how PHP was installed")
      end
    end

    def eol_branch_verdict
      if @audit.state == :fixed
        patched("branch #{branch} is end-of-life upstream, but the OS package changelog names the CVE " \
                "(backported fix). Plan a move to a supported branch anyway")
      else
        vulnerable("branch #{branch} is end-of-life and unpatched upstream. Upgrade to a supported, " \
                   "patched branch (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)")
      end
    end

    def newer_than_data
      review("#{version} is on branch #{branch}, newer than this checker knows about " \
             "(last known branch #{Advisory::HIGHEST_BRANCH}); confirm the advisory for that branch")
    end

    def branch
      @install.branch
    end

    def version
      @install.version
    end

    def at_least?(target)
      Gem::Version.new(version) >= Gem::Version.new(target)
    end

    def beyond_known_branches?
      Gem::Version.new(branch) > Gem::Version.new(Advisory::HIGHEST_BRANCH)
    rescue ArgumentError
      false
    end

    def patched(detail)
      Verdict.new(status: :patched, detail: detail)
    end

    def vulnerable(detail)
      Verdict.new(status: :vulnerable, detail: detail)
    end

    def review(detail)
      Verdict.new(status: :review, detail: detail)
    end
  end

  # Prints the Metasploit-style report: [*]/[+]/[-]/[!] lines and CheckCode verdicts.
  class Reporter
    # msf marks: the print_good / print_status / print_error / print_warning set.
    MARKS = {
      good: ["[+]", :green],
      info: ["[*]", :blue],
      bad: ["[-]", :red],
      warn: ["[!]", :yellow],
    }.freeze
    CHECKCODE = {
      vulnerable: "The target is vulnerable.",
      patched: "The target is not exploitable.",
      review: "Cannot reliably check exploitability.",
    }.freeze
    MARK_FOR = { vulnerable: :good, patched: :info, review: :info }.freeze

    def initialize(io: $stdout)
      @io = io
      @scanned = 0
    end

    def header
      info("Checking for PHP2Shell (#{Advisory::CVES.join(", ")})")
      info("Local check only. No network traffic, no exploitation.")
      info("Enumerating PHP binaries...")
    end

    def result(install, verdict)
      @scanned += 1
      info("#{install.path} - PHP #{install.label}")
      line("#{install.path} - #{CHECKCODE.fetch(verdict.status)} #{verdict.detail}", MARK_FOR.fetch(verdict.status))
    end

    def summary(status)
      info("Scanned #{@scanned} of #{@scanned} targets (100% complete)")
      OVERALL.fetch(status).each { |mark, text| line(text, mark) }
      info("PHP2Shell check completed")
    end

    def no_php
      line("No PHP binary found on PATH.", :bad)
      info("Pass a path explicitly, e.g. ruby #{File.basename($PROGRAM_NAME)} /usr/bin/php8.3")
    end

    private

    OVERALL = {
      vulnerable: [
        [:good, "PHP2Shell present: at least one target is vulnerable."],
        [:info, "Fix: update to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, then restart PHP-FPM and the web server."],
      ],
      review: [[:warn, "Manual review needed for at least one target."]],
      patched: [[:info, "All targets patched against PHP2Shell."]],
    }.freeze

    def info(text)
      line(text, :info)
    end

    def line(text, mark)
      glyph, color = MARKS.fetch(mark)
      @io.puts("#{Ansi.paint(@io, glyph, color)} #{text}")
    end
  end

  # Wires the pieces together and returns a process exit code.
  class CLI
    EXIT_CODES = { patched: 0, vulnerable: 1, review: 2 }.freeze
    SEVERITY = %i[patched review vulnerable].freeze

    def initialize(argv, reporter: Reporter.new)
      @argv = argv
      @reporter = reporter
    end

    def run
      @reporter.header
      return no_php if installs.empty?

      verdicts = installs.map { |install| report(install) }
      conclude(verdicts)
    end

    private

    def installs
      @installs ||= targets.map { |path| VersionReader.new(path).install }
    end

    def targets
      @argv.empty? ? BinaryFinder.new.paths : @argv
    end

    def report(install)
      verdict = Assessment.new(install).verdict
      @reporter.result(install, verdict)
      verdict
    end

    def conclude(verdicts)
      status = worst(verdicts)
      @reporter.summary(status)
      EXIT_CODES.fetch(status)
    end

    def worst(verdicts)
      verdicts.map(&:status).max_by { |status| SEVERITY.index(status) }
    end

    def no_php
      @reporter.no_php
      EXIT_CODES.fetch(:review)
    end
  end
end

exit(Php2shell::CLI.new(ARGV).run) if $PROGRAM_NAME == __FILE__
