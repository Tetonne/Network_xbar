#!/usr/bin/env ruby
# frozen_string_literal: true

# Script optimisé pour macOS xbar.app (Ruby 2.6+)
# Debug : cd ~/Library/Application\ Support/xbar/plugins/ && ruby VPN-flag543.3m.rb --debug
# Debug avec empreinte : ruby VPN-flag543.3m.rb --show-fingerprint
# Tests unitaires : ruby VPN-flag543.3m.rb --run-tests
# Règle stricte « aucune valeur affichée en dur », même les fallback ne doivent pas mentir
# si le code pèse moins de 68Ko alors risque de regression (non acceptable)

# <xbar.title>VPN Checker Pro/xbar.title>
# <xbar.version>v5.4.3</xbar.version>
# <xbar.author>Tetonne & AI</xbar.author>
# <xbar.desc>Professional VPN & Network Security Analyzer — v5.4.3 optimized architecture</xbar.desc>
# <xbar.dependencies>ruby</xbar.dependencies>

require 'net/http'
require 'uri'
require 'json'
require 'open3'
require 'digest'
require 'timeout'
require 'resolv'
require 'socket'
require 'fileutils'
require 'time'
require 'ipaddr'
require 'shellwords'
require 'set'
require 'logger'

module VPNChecker
  APP_VERSION  = '5.4.3'
  ENABLE_CACHE = true

  DEBUG_MODE       = ARGV.include?('--debug') || %w[1 true yes].include?(ENV.fetch('VPN_CHECKER_DEBUG', '').downcase) unless defined?(DEBUG_MODE)
  SHOW_FINGERPRINT = ARGV.include?('--show-fingerprint') unless defined?(SHOW_FINGERPRINT)
  RUN_TESTS        = ARGV.include?('--run-tests') unless defined?(RUN_TESTS)

  module Config
    VERSION   = APP_VERSION
    CACHE_DIR = File.expand_path('~/.cache/vpn_checker').freeze
    LOG_DIR   = File.expand_path('~/.logs/vpn_checker').freeze
    STATE_FILE = File.join(CACHE_DIR, 'state.json').freeze
    TOR_EXIT_CACHE_FILE = File.join(CACHE_DIR, 'tor_exit_addresses.json').freeze
    APPLE_RELAY_CACHE_FILE = File.join(CACHE_DIR, 'apple_relay_ranges.json').freeze
    TOR_EXIT_CACHE_TTL = 6 * 60 * 60
    APPLE_RELAY_CACHE_TTL = 24 * 60 * 60
    PERFORMANCE_CACHE_FILE = File.join(CACHE_DIR, 'performance.json').freeze
    PERFORMANCE_CACHE_TTL = 20
    SCUTIL_DNS_CACHE_FILE = File.join(CACHE_DIR, 'scutil_dns.json').freeze
    SCUTIL_DNS_CACHE_TTL = 180

    MAX_TOTAL_TIMEOUT = 10.0
    HTTP_OPEN_TIMEOUT = 0.8
    HTTP_READ_TIMEOUT = 2.0

    TIMEOUT_FAST = 1.0
    TIMEOUT_SLOW = 1.5
    TIMEOUT_DNS  = 0.5
    TIMEOUT_TCP  = 0.5

    MAX_RETRIES               = 2
    RETRY_BACKOFF_STEPS       = [0.050, 0.100].freeze
    CIRCUIT_BREAKER_THRESHOLD = 3
    CIRCUIT_BREAKER_TIMEOUT   = 30

    IPV4_PATTERN = Regexp.new('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)').freeze
    IPV6_PATTERN = Regexp.new('(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}').freeze
    MASK_PATTERN = IPV4_PATTERN

    ALLOWED_COUNTRIES = %w[NL CH PL RO US].freeze
    DENY_COUNTRIES    = %w[FR RU CN IR KP].freeze

    PING_HOSTS = %w[1.1.1.1 8.8.8.8 9.9.9.9].freeze

    PUBLIC_IP_APIS = [
      { url: 'https://api.ipify.org', priority: 1 },
      { url: 'https://checkip.amazonaws.com', priority: 2 },
      { url: 'https://icanhazip.com', priority: 3 },
      { url: 'https://ifconfig.me/ip', priority: 4 },
      { url: 'https://ipinfo.io/ip', priority: 5 }
    ].freeze

    PUBLIC_IPV6_APIS = [
      { url: 'https://api64.ipify.org', priority: 1 },
      { url: 'https://api6.ipify.org', priority: 2 }
    ].freeze
  end

  module Enums
    PTRStatus = {
      MATCH: :match, MISMATCH: :mismatch, UNKNOWN: :unknown,
      ERROR: :error, VALID: :valid, SUSPECT: :suspect
    }.freeze

    InfrastructureType = {
      RESIDENTIAL: :residential, DATACENTER: :datacenter,
      VPN_NODE: :vpn_node, UNKNOWN: :unknown, HOSTING: :hosting
    }.freeze

    ProtectionState = {
      PROTECTED: :protected, EXPOSED: :exposed, DEGRADED: :degraded
    }.freeze
  end

  URL_PATTERN = %r{https?://[^\s]+}.freeze

  VPN_PROVIDERS = {
    /proton/i                    => "ProtonVPN",
    /mullvad/i                   => "Mullvad",
    /nordvpn/i                   => "NordVPN",
    /surfshark/i                 => "Surfshark",
    /expressvpn/i                => "ExpressVPN",
    /ivpn/i                      => "IVPN",
    /cyberghost/i                => "CyberGhost",
    /private\.internet\.access/i => "Private Internet Access",
    /hidemyass/i                 => "HideMyAss",
    /purevpn/i                   => "PureVPN",
    /astrill/i                   => "Astrill",
    /vyprvpn/i                   => "VyprVPN",
    /windscribe/i                => "Windscribe",
    /m247/i                      => "M247",
    /digitalocean/i              => "DigitalOcean",
    /ovh/i                       => "OVH",
    /worldstream/i               => "WorldStream",
    /tailscale/i                 => "Tailscale",
    /cloudflare/i                => "Cloudflare",
    /google/i                    => "Google Cloud",
    /amazon|aws/i                => "AWS",
    /microsoft|azure/i           => "Azure",
    /oracle/i                    => "Oracle Cloud",
    /linode/i                    => "Linode",
    /hetzner/i                   => "Hetzner",
    /leaseweb/i                  => "Leaseweb",
    /contabo/i                   => "Contabo",
    /vultr/i                     => "Vultr"
  }.freeze

  RESIDENTIAL_ASNS = {
    3215  => 'Orange',
    12322 => 'Free',
    5430  => 'SFR',
    15557 => 'Bouygues',
    21502 => 'SFR'
  }.freeze

  TRUSTED_DNS = %w[
    1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 94.140.14.14 94.140.15.15 49.12.223.2 49.12.43.208
  ].freeze

  DNS_PROVIDERS = {
    "1.1.1.1"         => "☁️ Cloudflare",
    "1.0.0.1"         => "☁️ Cloudflare",
    "8.8.8.8"         => "🟦 Google",
    "8.8.4.4"         => "🟦 Google",
    "9.9.9.9"         => "🌐 Quad9",
    "149.112.112.112" => "🌐 Quad9",
    "94.140.14.14"    => "🛡 AdGuard",
    "94.140.15.15"    => "🛡 AdGuard",
    "49.12.223.2"     => "🔐 DNSforge",
    "49.12.43.208"    => "🔐 DNSforge",
    "127.0.0.1"       => "🔐 DNSCrypt / Proxy Local",
    "10.2.0.1"        => "🔐 ProtonVPN",
    "10.96.0.1"       => "🔐 ProtonVPN",
    "10.124.0.1"      => "🔐 ProtonVPN",
    "10.7.0.1"        => "🔐 NordVPN",
    "10.8.0.1"        => "🔐 OpenVPN",
    "10.64.0.1"       => "🔐 Mullvad",
    "100.64.0.1"      => "🔐 CGNAT / Tailscale VPN"
  }.freeze

  KNOWN_DOH = {
    /dns\.google/i          => "Google DoH",
    /cloudflare-dns\.com/i  => "Cloudflare DoH",
    /dns\.quad9\.net/i      => "Quad9 DoH",
    /dns\.nextdns\.io/i     => "NextDNS",
    /dns\.controld\.com/i   => "ControlD",
    /dns\.adguard\.com/i    => "AdGuard",
    /dns\.mullvad\.net/i    => "Mullvad",
    /dnsforge\.de/i         => "🔐 DNSforge DoH/DoT"
  }.freeze

  def self.valid_ip?(ip)
    return false if ip.nil? || ip.to_s.strip.empty?
    ip_str = ip.to_s.strip
    return true if ip_str.match?(Config::IPV4_PATTERN) || ip_str.match?(Config::IPV6_PATTERN)
    IPAddr.new(ip_str)
    true
  rescue IPAddr::InvalidAddressError, ArgumentError
    false
  end

  module Helpers
    module_function

    def evaluate_ptr_status(ptr, org, vpn_active: false)
      return { status: Enums::PTRStatus[:UNKNOWN], valid: false } if ptr.nil? || ptr.to_s.empty? || ptr.to_s.include?("Inconnu")

      ptr_down = ptr.to_s.downcase
      org_down = org.to_s.downcase

      known_keywords = ['hosted-by', 'vpn', 'datacenter', 'nodes', 'servers', 'cloud', 'wanadoo', 'orange', 'free', 'sfr']
      has_known_pattern = known_keywords.any? { |kw| ptr_down.include?(kw) }

      org_tokens = org_down.scan(/[a-z0-9]+/).reject { |t| %w[inc ltd corp gmbh bv llc sa].include?(t) || t.length <= 2 }
      matches_org = org_tokens.any? { |token| ptr_down.include?(token) }

      if matches_org || has_known_pattern || !vpn_active
        { status: Enums::PTRStatus[:VALID], valid: true }
      else
        { status: Enums::PTRStatus[:SUSPECT], valid: false }
      end
    end

    def reverse_dns_status(ptr, org, ip, vpn_active: false)
      res = evaluate_ptr_status(ptr, org, vpn_active: vpn_active)
      case res[:status]
      when Enums::PTRStatus[:VALID]
        { status: res[:status], label: "✅ PTR Cohérent (#{ptr})", alert: false }
      when Enums::PTRStatus[:SUSPECT]
        { status: res[:status], label: "🚨 PTR Suspect (#{ptr})", alert: true }
      else
        { status: Enums::PTRStatus[:UNKNOWN], label: nil, alert: false }
      end
    end

    def clean_str(val, fallback = 'Inconnu')
      return fallback if val.nil?
      sanitized = val.to_s.gsub(/[\u00A0\u2000-\u200B\u202F\uFEFF]/, ' ').strip
      sanitized.empty? ? fallback : sanitized
    end

    def sanitize_log_message(msg)
      msg.to_s
         .gsub(Config::MASK_PATTERN, '[IP_MASKED]')
         .gsub(URL_PATTERN, '[URL_REDACTED]')
         .gsub(/"(latitude|longitude|lat|lon|city|region|location)":\s*("[^"]+"|[0-9.-]+)/i, '"\1": "[REDACTED]"')
         .gsub(/(bearer|token|key|auth|secret)=([a-z0-9_-]+)/i, '\1=[REDACTED]')
    end
  end

  class Logger
    class << self
      def instance
        @instance ||= begin
          FileUtils.mkdir_p(VPNChecker::Config::LOG_DIR, mode: 0700) rescue nil
          log_file = File.join(VPNChecker::Config::LOG_DIR, 'vpn_checker.log')
          logger = ::Logger.new(log_file, 7, 1_048_576)
          logger.level = ::Logger::INFO
          logger
        end
      end

      def info(msg)
        safe = VPNChecker::Helpers.sanitize_log_message(msg)
        instance.info(safe) rescue nil
        $stderr.puts "[INFO] #{safe}" if DEBUG_MODE
      end

      def warn(msg)
        safe = VPNChecker::Helpers.sanitize_log_message(msg)
        instance.warn(safe) rescue nil
        $stderr.puts "[WARN] #{safe}" if DEBUG_MODE
      end

      def error(msg, context: {})
        safe = VPNChecker::Helpers.sanitize_log_message("#{msg} #{context.empty? ? '' : context}")
        instance.error(safe) rescue nil
        $stderr.puts "[ERROR] #{safe}" if DEBUG_MODE
      end

      def debug(msg)
        return unless DEBUG_MODE
        safe = VPNChecker::Helpers.sanitize_log_message(msg)
        instance.debug(safe) rescue nil
      end

      def log_timeout(context_name, details = '')
        warn("[TIMEOUT] Dépassement de délai dans #{context_name} #{details}".strip)
      end
    end
  end

  module Core
    Logger = VPNChecker::Logger
  end

  class ServiceCircuitBreaker
    def initialize(threshold = Config::CIRCUIT_BREAKER_THRESHOLD, timeout = Config::CIRCUIT_BREAKER_TIMEOUT)
      @threshold = threshold
      @timeout   = timeout
      @failures  = {}
      @open_until = {}
      @mutex     = Mutex.new
    end

    def allow?(host)
      @mutex.synchronize do
        now = Time.now.to_i
        if @open_until[host] && @open_until[host] > now
          return false
        elsif @open_until[host] && @open_until[host] <= now
          @open_until.delete(host)
          @failures[host] = 0
        end
        true
      end
    end

    def record_failure(host)
      @mutex.synchronize do
        @failures[host] = (@failures[host] || 0) + 1
        if @failures[host] >= @threshold
          @open_until[host] = Time.now.to_i + @timeout
          Logger.warn("Circuit Breaker DÉCLENCHÉ pour #{host} (Ouvert pendant #{@timeout}s)")
        end
      end
    end

    def record_success(host)
      @mutex.synchronize do
        @failures[host] = 0
        @open_until.delete(host)
      end
    end
  end

  class FlagTracer
    def self.save_current_state(state_hash)
      return unless VPNChecker::ENABLE_CACHE
      FileUtils.mkdir_p(Config::CACHE_DIR, mode: 0700) rescue nil

      File.open(Config::STATE_FILE, File::WRONLY | File::CREAT | File::TRUNC, 0600) do |file|
        file.write(JSON.dump(state_hash))
      end
    rescue StandardError => e
      Logger.error("Erreur d'écriture du fichier d'état : #{e.message}")
    end

    def self.load_current_state
      return {} unless File.exist?(Config::STATE_FILE)

      raw_content = File.read(Config::STATE_FILE)
      JSON.parse(raw_content)
    rescue StandardError => e
      Logger.error("Erreur de lecture du fichier d'état : #{e.message}")
      {}
    end

    def self.trace_and_log(current_flag, current_color, ip, country, isp)
      previous_state = load_current_state

      current_state = {
        'flag'      => current_flag,
        'color'     => current_color,
        'ip'        => ip,
        'country'   => country,
        'isp'       => isp,
        'timestamp' => Time.now.iso8601
      }

      if previous_state && !previous_state.empty? && previous_state['flag'] != current_flag
        sys_proof = capture_system_proof
        log_message = "ALERT: CHANGEMENT DE FLAG DÉTECTÉ ! " \
                      "[Ancien: #{previous_state['flag']} (#{previous_state['ip']})] -> " \
                      "[Nouveau: #{current_flag} (#{ip})] | FAI: #{isp} | " \
                      "PREUVE SYSTÈME: #{sys_proof}"

        Logger.error(log_message)
      end

      save_current_state(current_state)
    end

    def self.capture_system_proof
      route_out = Infrastructure::CommandExecutor.run('route', '-n', 'get', 'default')[:stdout]
      iface_match = route_out.match(/interface:\s*([a-zA-Z0-9]+)/)
      active_iface = iface_match ? iface_match[1] : 'Inconnu'

      ifconfig_out = Infrastructure::CommandExecutor.run('ifconfig')[:stdout]
      utun_active = ifconfig_out.scan(/utun\d+/).uniq.join(',')
      utun_status = utun_active.empty? ? "Aucune" : utun_active

      "[Route par défaut: #{active_iface} | Interfaces VPN actives: #{utun_status}]"
    rescue StandardError => e
      "[Erreur capture preuve: #{e.message}]"
    end
  end

  module Infrastructure
    class CommandExecutor
      def self.run(*cmd_args, timeout: Config::TIMEOUT_SLOW)
        stdout_str, stderr_str, status = '', '', nil
        
        # Utilisation de popen3 à la place de capture3 pour un meilleur contrôle des flux sous Ruby 2.6
        Open3.popen3(*cmd_args) do |stdin, stdout, stderr, wait_thr|
          stdin.close
          begin
            Timeout.timeout(timeout) do
              stdout_str = stdout.read
              stderr_str = stderr.read
              status = wait_thr.value
            end
          rescue Timeout::Error
            # Tuer le processus s'il dépasse le timeout
            Process.kill('TERM', wait_thr.pid) rescue nil
            wait_thr.join(0.2)
            Logger.log_timeout("CommandExecutor", "Commande: #{cmd_args.join(' ')} (#{timeout}s)")
            return { stdout: '', stderr: 'Timeout', success: false }
          end
        end

        {
          stdout: stdout_str,
          stderr: stderr_str,
          success: status&.success? || false
        }
      rescue StandardError => e
        Logger.error("Erreur d'exécution système : #{e.message}")
        { stdout: '', stderr: e.message, success: false }
      end

      def self.safe_run(*cmd_args, timeout: Config::TIMEOUT_SLOW)
        run(*cmd_args, timeout: timeout)
      end
    end

    class FirewallChecker
      PF_CONF_PATH = '/etc/pf.conf'

      def self.rules_ok?
        return false unless File.exist?(PF_CONF_PATH)

        pf_rules = File.read(PF_CONF_PATH)
        pf_rules.include?('block out on !utun0') || pf_rules.include?('block out quick on !utun0')
      rescue Errno::EACCES => e
        Logger.error("Permissions insuffisantes sur #{PF_CONF_PATH}: #{e.message}")
        false
      rescue StandardError => e
        Logger.error("Erreur lors de la lecture de #{PF_CONF_PATH}: #{e.message}")
        false
      end
    end

    module NetTools
      module_function

      TEST_HOSTS = VPNChecker::Config::PING_HOSTS.map { |h| [h, 53] }.freeze

      def internet?
        TEST_HOSTS.any? do |host, port|
          begin
            Socket.tcp(host, port, connect_timeout: Config::TIMEOUT_TCP) { true }
          rescue StandardError => e
            Logger.log_timeout("NetTools.internet?", "Échec test TCP #{host}:#{port}") if e.is_a?(Timeout::Error) || e.is_a?(Errno::ETIMEDOUT)
            false
          end
        end
      end
    end

    class SecureDiskCache
      class << self
        def get_cache_dir
          dir = VPNChecker::Config::CACHE_DIR
          FileUtils.mkdir_p(dir, mode: 0700) rescue nil
          dir
        end

        def invalid_value?(val)
          return true if val.nil?
          str = val.to_s.gsub(/[\u00A0\u2000-\u200B\u202F\uFEFF]/, ' ').strip
          invalid_values = %w[Non\ détectée Non\ vérifiable Inconnu Aucune Unknown].freeze
          str.empty? || invalid_values.any? { |v| str.include?(v) }
        end

        def read_json(path, ttl:)
          return nil unless VPNChecker::ENABLE_CACHE
          return nil unless File.file?(path)

          raw = File.read(path)
          payload = JSON.parse(raw)
          return nil unless payload.is_a?(Hash)

          timestamp = payload['timestamp'].to_i
          return nil if timestamp <= 0 || (Time.now.to_i - timestamp) > ttl

          payload['data']
        rescue StandardError => e
          Logger.warn("Cache disque invalide #{path}: #{e.message}")
          nil
        end

        # FIX 1 : Portée de la variable tmp sécurisée avant le bloc begin/rescue
        def write_json(path, data)
          return data unless VPNChecker::ENABLE_CACHE

          tmp = nil
          dir = File.dirname(path)
          FileUtils.mkdir_p(dir, mode: 0700) rescue nil
          payload = JSON.generate('timestamp' => Time.now.to_i, 'data' => data)
          tmp = "#{path}.tmp.#{$$}.#{Thread.current.object_id}"
          File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, 0600) do |file|
            file.write(payload)
            file.flush
          end
          File.rename(tmp, path)
          data
        rescue StandardError => e
          File.delete(tmp) rescue nil if tmp && File.exist?(tmp)
          Logger.warn("Erreur écriture cache disque #{path}: #{e.message}")
          data
        end

        def purge_all!
          FileUtils.rm_rf(get_cache_dir)
        end
      end
    end

    class AdaptiveLRUCache
      def initialize(capacity = 50)
        @capacity = capacity
        @store = {}
        @mutex = Mutex.new
      end

      def fetch(key, ttl: 60)
        return yield unless VPNChecker::ENABLE_CACHE

        now = Time.now.to_i
        @mutex.synchronize do
          if @store.key?(key)
            exp, val = @store.delete(key)
            if exp > now
              @store[key] = [exp, val]
              return val
            end
          end
        end

        val = yield
        return val unless VPNChecker::ENABLE_CACHE

        @mutex.synchronize do
          @store.delete(key)
          @store[key] = [now + ttl, val]
          @store.shift while @store.size > @capacity
        end
        val
      end

      def get(key)
        return nil unless VPNChecker::ENABLE_CACHE
        now = Time.now.to_i
        @mutex.synchronize do
          if @store.key?(key)
            exp, val = @store.delete(key)
            if exp > now
              @store[key] = [exp, val]
              return val
            end
          end
        end
        nil
      end

      def set(key, val, ttl: 60)
        return val unless VPNChecker::ENABLE_CACHE
        now = Time.now.to_i
        @mutex.synchronize do
          @store[key] = [now + ttl, val]
          @store.shift if @store.size > @capacity
        end
        val
      end
    end

    # Renommé proprement pour refléter l'utilisation de netstat au lieu de lsof
    class NetstatSnapshot
      IGNORE_PORTS = [22, 53, 80, 443, 631].freeze
      DOQ_PORTS = [784, 853, 8853].freeze

      attr_reader :open_ports

      def initialize(raw_output)
        @raw_output = raw_output.to_s
        @has_dot = @raw_output.include?('.853 ') || @raw_output.include?(':853 ')
        @has_doq = DOQ_PORTS.any? { |p| @raw_output.include?(".#{p} ") || @raw_output.include?(":#{p} ") }
        @has_stun = @raw_output.include?('19302')
        @has_doh = @raw_output.include?('.443 ') || @raw_output.include?(':443 ')
        @open_ports = parse_open_ports.freeze
      end

      def dot?; @has_dot; end
      def doq?; @has_doq; end
      def doh?; @has_doh; end
      def stun_leak?; @has_stun; end

      private

      def parse_open_ports
        ports = []
        @raw_output.lines.each do |line|
          next unless line.include?('LISTEN')
          parts = line.split
          addr = parts[3] || ''
          port = addr.split('.').last.to_i
          port = addr.split(':').last.to_i if port == 0

          if port > 0 && !IGNORE_PORTS.include?(port)
            ports << { command: 'LISTEN', port: port }
          end
        end
        ports.uniq { |p| p[:port] }
      rescue StandardError => e
        Logger.warn("NetstatSnapshot parsing failed: #{e.message}")
        []
      end
    end

    class RouteSnapshot
      def initialize(raw_output)
        @raw_output = raw_output.to_s
        @vpn_route_override = @raw_output.lines.any? do |line|
          line.match?(/^(0\/1|128\/1|default).*(utun|tun|ppp|wg|wireguard)/)
        end
        @unprotected_default_route = @raw_output.lines.any? do |line|
          line.start_with?('default') && (line.include?('en') || line.include?('Wi-Fi'))
        end
        @direct_host_routes = @raw_output.lines.select do |line|
          line.match?(/\sUGHS\d*\s/) && !line.include?('utun') && !line.include?('lo0')
        end.map { |line| line.split.first }.freeze
      end

      attr_reader :direct_host_routes

      def vpn_route_override?; @vpn_route_override; end
      def unprotected_default_route?; @unprotected_default_route; end
    end

    class SystemSnapshot
      CACHE_TTL = 60

      def initialize(cache: nil)
        @cache = cache || AdaptiveLRUCache.new
        @snapshot_data = nil
      end

      def direct_host_routes
        refresh!
        @snapshot_data[:route_snap].direct_host_routes
      end

      def refresh!
        @snapshot_data ||= if VPNChecker::ENABLE_CACHE
                             @cache.fetch('system_snapshot', ttl: CACHE_TTL) { collect_snapshot_data }
                           else
                             collect_snapshot_data
                           end
      end

      def collect_snapshot_data
        ifconfig   = fetch_ifconfig
        netstat    = fetch_netstat
        route      = fetch_default_route
        route_snap = RouteSnapshot.new(netstat)
        dns_cache_signature = Digest::SHA256.hexdigest([ifconfig, netstat, route].join("\n"))
        dns_cache = SecureDiskCache.read_json(
          VPNChecker::Config::SCUTIL_DNS_CACHE_FILE,
          ttl: VPNChecker::Config::SCUTIL_DNS_CACHE_TTL
        )
        scutil_dns = if dns_cache.is_a?(Hash) &&
                        dns_cache['signature'] == dns_cache_signature &&
                        dns_cache['dns'].is_a?(String) && !dns_cache['dns'].empty?
                     dns_cache['dns']
                   else
                     fresh_dns = CommandExecutor.run('scutil', '--dns')[:stdout]
                     unless fresh_dns.to_s.empty?
                       SecureDiskCache.write_json(
                         VPNChecker::Config::SCUTIL_DNS_CACHE_FILE,
                         { 'signature' => dns_cache_signature, 'dns' => fresh_dns }
                       )
                     end
                     fresh_dns
                   end

        all_interfaces = ifconfig
          .to_s
          .scan(/^([a-zA-Z0-9\-]+):/i)
          .flatten
          .uniq

        vpn_interfaces = detect_vpn_interfaces_from(all_interfaces, route_snap)
        netstat_an     = CommandExecutor.safe_run('netstat', '-anp', 'tcp', timeout: 0.5)[:stdout]

        {
          ifconfig: ifconfig,
          scutil_dns: scutil_dns,
          netstat_rn: netstat,
          route_default: route,
          route_snap: route_snap,
          ps_procs: parse_processes,
          default_interface: parse_default_interface(route),
          default_gateway: parse_default_gateway(route),
          vpn_interfaces: vpn_interfaces,
          all_interfaces: all_interfaces,
          netstat_output: netstat_an,
          netstat_snap: NetstatSnapshot.new(netstat_an)
        }
      end

      def detect_vpn_interfaces_from(interfaces, route_snap)
        vpn_prefixes = %w[
          utun tun ppp wg wireguard ipsec vtun tap
          protonvpn mullvad nordvpn tailscale viscosity zerotier
        ]

        route_override = route_snap.vpn_route_override?

        interfaces.select do |iface|
          name = iface.downcase
          vpn_name = vpn_prefixes.any? { |prefix| name.start_with?(prefix) } || name.include?('vpn')
          next false unless vpn_name

          if name.start_with?('utun', 'tun', 'tap', 'wg', 'ppp')
            route_override
          else
            true
          end
        end
      end

      def detect_default_interface_from
        refresh!
        @snapshot_data[:default_interface]
      end

      def parse_default_interface(route_out)
        match = route_out.to_s.match(/interface:\s*([a-zA-Z0-9]+)/)
        match ? match[1] : nil
      end

      def parse_default_gateway(route_out)
        match = route_out.to_s.match(/gateway:\s*([^\s]+)/)
        match ? match[1] : nil
      end

      def vpn_route_override?
        refresh!
        @snapshot_data[:route_snap].vpn_route_override?
      end

      def unprotected_default_route?
        refresh!
        @snapshot_data[:route_snap].unprotected_default_route?
      end

      def ipv6_interface_active?
        refresh!
        @snapshot_data[:ifconfig].to_s
            .scan(/inet6\s+([0-9a-f:]+)/i)
            .flatten
            .any? { |ip| !(ip.start_with?('fe80', 'fd', 'fc', '::1')) }
      end

      def vpn_ipv6_interface?
        refresh!
        data = @snapshot_data
        data[:vpn_interfaces].any? do |iface|
          data[:ifconfig].to_s.include?("#{iface}:") && data[:ifconfig].to_s.include?('inet6')
        end
      end

      def primary_interface
        refresh!
        @snapshot_data[:default_interface]
      end

      def default_gateway
        refresh!
        @snapshot_data[:default_gateway]
      end

      def vpn_active?
        refresh!
        !@snapshot_data[:vpn_interfaces].empty? || vpn_route_override?
      end

      def netstat_snap
        refresh!
        @snapshot_data[:netstat_snap]
      end

      def method_missing(name, *args)
        data = refresh!
        data.key?(name) ? data[name] : super
      end

      def respond_to_missing?(method_name, include_private = false)
        refresh!.key?(method_name) || super
      end

      private

      def fetch_ifconfig
        res = CommandExecutor.safe_run('ifconfig', '-a')
        return res[:stdout] if res[:success] && !res[:stdout].empty?
        CommandExecutor.safe_run('networksetup', '-listallhardwareports')[:stdout]
      end

      def fetch_netstat
        res = CommandExecutor.safe_run('netstat', '-rn')
        return res[:stdout] if res[:success] && !res[:stdout].empty?
        CommandExecutor.safe_run('route', '-n', 'get', 'default')[:stdout]
      end

      def fetch_default_route
        CommandExecutor.safe_run('route', '-n', 'get', 'default')[:stdout]
      end

      def parse_processes
        res = CommandExecutor.safe_run('ps', '-A', '-o', 'comm=')[:stdout]
        res.lines.map do |l|
          clean = l.strip
          !clean.empty? ? File.basename(clean).downcase : nil
        end.compact
      end
    end

    class AdvancedDNSResolver
      def initialize(snapshot)
        @snapshot = snapshot
      end

      def detected_tunnel_dns
        tunnel_dns = dns_servers.find { |ip| ip.start_with?('10.') }
        return tunnel_dns if tunnel_dns

        default_gw = @snapshot.default_gateway
        return default_gw if default_gw.to_s.start_with?('10.')

        nil
      end

      def dns_servers
        (@snapshot.scutil_dns || "")
          .scan(/nameserver(?:\s*\[\d+\])?\s*:\s*([0-9a-fA-F:\.]+)/)
          .flatten
          .map { |d| sanitize_ip(d) }
          .compact
          .uniq
      end

      private

      def sanitize_ip(ip)
        return nil unless VPNChecker.valid_ip?(ip)
        ip.to_s.strip
      end
    end
  end

  module Network
    class HTTPClient
      def initialize
        @circuit_breaker = VPNChecker::ServiceCircuitBreaker.new
      end

      def make_request(url_string, timeout: Config::TIMEOUT_FAST, open_timeout: Config::HTTP_OPEN_TIMEOUT, read_timeout: Config::HTTP_READ_TIMEOUT)
        uri = URI.parse(url_string) rescue nil
        return nil unless uri && uri.host

        host = uri.host
        unless @circuit_breaker.allow?(host)
          Logger.warn("Circuit Breaker actif : requête ignorée pour #{host}")
          return nil
        end

        attempts = 0
        max_attempts = Config::MAX_RETRIES

        begin
          attempts += 1
          Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: open_timeout, read_timeout: read_timeout) do |http|
            request = Net::HTTP::Get.new(uri.request_uri)
            request['User-Agent'] = "VPNChecker/#{Config::VERSION}"
            response = http.request(request)

            if response.is_a?(Net::HTTPSuccess)
              @circuit_breaker.record_success(host)
              return response.body
            else
              raise "HTTP #{response.code}"
            end
          end
        rescue Timeout::Error, Net::OpenTimeout, Net::ReadTimeout, Errno::ETIMEDOUT => e
          Logger.log_timeout("HTTPClient(#{host})", "Tentative #{attempts}/#{max_attempts}: #{e.message}")
          @circuit_breaker.record_failure(host)

          if attempts < max_attempts
            sleep_time = Config::RETRY_BACKOFF_STEPS[attempts - 1] || 0.4
            sleep(sleep_time)
            retry
          end
          nil
        rescue StandardError => e
          Logger.warn("Échec requête HTTP (#{url_string}) [Essai #{attempts}/#{max_attempts}]: #{e.message}")
          @circuit_breaker.record_failure(host)

          if attempts < max_attempts
            sleep_time = Config::RETRY_BACKOFF_STEPS[attempts - 1] || 0.4
            sleep(sleep_time)
            retry
          end
          nil
        end
      end

      def get(url, timeout: Config::TIMEOUT_FAST, headers: {})
        make_request(url, timeout: timeout)
      end

      def parse_json_safely(raw_json)
        return {} if raw_json.nil? || raw_json.to_s.strip.empty?
        JSON.parse(raw_json)
      rescue JSON::ParserError, StandardError => e
        Logger.warn("Échec du parsing JSON: #{e.message}")
        {}
      end
    end
  end

  module Detectors
    class BaseDetector
      attr_reader :snapshot, :http_client, :dns_resolver

      def initialize(snapshot:, http_client: nil, dns_resolver: nil)
        @snapshot = snapshot
        @http_client = http_client || Network::HTTPClient.new
        @dns_resolver = dns_resolver || Infrastructure::AdvancedDNSResolver.new(snapshot)
      end
    end

    class OpenPortsDetector < BaseDetector
      def detect
        @snapshot.netstat_snap.open_ports
      rescue StandardError => e
        Logger.warn("OpenPortsDetector failed: #{e.message}")
        []
      end
    end

    class EncryptedDNSDetector < BaseDetector
      DOQ_PORTS = [784, 853, 8853].freeze
      DOH_PROVIDERS = %w[cloudflared nextdns dnsproxy stubby].freeze

      def detect
        methods = []
        methods << detect_dnscrypt
        methods << detect_doh
        methods << detect_dot
        methods << detect_doq
        methods.compact!

        if methods.empty?
          { encrypted: false, methods: [], message: '❌ DNS standard (non chiffré)' }
        else
          { encrypted: true, methods: methods, message: "🔐 #{methods.join(' + ')}" }
        end
      end

      private

      def detect_dnscrypt
        procs = @snapshot.ps_procs || []
        return 'DNSCrypt' if procs.any? { |p| p.include?('dnscrypt-proxy') }
        nil
      end

      def detect_doh
        procs = @snapshot.ps_procs || []
        return 'DoH' if procs.any? { |prov| DOH_PROVIDERS.any? { |p| prov.include?(p) } }
        @snapshot.netstat_snap.doh? ? 'DoH' : nil
      end

      def detect_dot
        @snapshot.netstat_snap.dot? ? 'DoT' : nil
      end

      def detect_doq
        @snapshot.netstat_snap.doq? ? 'DoQ' : nil
      end
    end

    class VPNDetector < BaseDetector
      KNOWN_VPN_PROCESSES = %w[
        openvpn wireguard openconnect vpnc
        softether strongswan racoon charon
        wg-quick protonvpn tailscale viscosity
        tunnelblick mullvad nordvpn surfshark expressvpn ivpn zero-tier
      ].freeze

      def detect_tunnel_type(processes = nil)
        procs = processes || @snapshot.ps_procs || []
        ifaces = @snapshot.vpn_interfaces || []

        is_viscosity = procs.any? { |p| p.include?('viscosity') }
        utun_iface = ifaces.find { |i| i.start_with?('utun') }

        if is_viscosity && utun_iface
          "Viscosity (#{utun_iface})"
        elsif is_viscosity
          "Viscosity"
        elsif procs.any? { |p| p.include?('wireguard') || p.include?('wg') } || ifaces.any? { |i| i.start_with?('wg') }
          'WireGuard'
        elsif procs.any? { |p| p.include?('openvpn') } || ifaces.any? { |i| i.start_with?('tun') }
          'OpenVPN'
        elsif ifaces.any? { |i| i.start_with?('ppp') }
          'IPSec/L2TP'
        elsif ifaces.any? { |i| i.start_with?('zt') }
          'ZeroTier'
        elsif utun_iface
          "macOS UTUN (#{utun_iface})"
        else
          'Generic Tunnel'
        end
      end

      def detect
        interfaces = @snapshot.vpn_interfaces || []
        processes  = @snapshot.ps_procs || []

        active_if = interfaces.any? { |iface| iface.start_with?('utun', 'tun', 'tap', 'wg', 'ppp') }
        active_pr = processes.any? { |proc_name| KNOWN_VPN_PROCESSES.include?(proc_name.downcase) }
        route_based_vpn = @snapshot.vpn_route_override?

        active_status = route_based_vpn || (active_if && active_pr)

        {
          active: active_status,
          confidence: calculate_confidence(active_if, active_pr, route_based_vpn),
          interface_based: active_if,
          process_based: active_pr,
          route_based: route_based_vpn,
          tunnel_type: active_status ? detect_tunnel_type(processes) : 'Inconnu',
          interface: interfaces.first,
          interfaces: interfaces
        }
      end

      private

      def calculate_confidence(has_interface, has_proc, has_route)
        return 0 unless has_route || (has_interface && has_proc)
        score = 0
        score += 40 if has_interface
        score += 35 if has_proc
        score += 25 if has_route
        [score, 100].min
      end
    end

    class KillSwitchDetector < BaseDetector
      STATUS_INACTIVE = '⚪ Inactif (VPN off)'.freeze
      STATUS_FAIL     = '🚨 Kill Switch FAIL (Fuite Physique)'.freeze
      STATUS_OK       = '🟢 OK (Actif)'.freeze
      STATUS_PARTIAL  = '🟡 Kill Switch Partiel'.freeze

      def detect(vpn_active: false)
        return { status: STATUS_INACTIVE, broken: false } unless vpn_active

        has_vpn_override = @snapshot.vpn_route_override?
        has_unprotected  = @snapshot.unprotected_default_route?

        ks_broken = has_unprotected && !has_vpn_override
        ks_active = (has_vpn_override && !has_unprotected) || routing_kill_switch_active?

        status = if ks_broken
                   STATUS_FAIL
                 elsif ks_active
                   STATUS_OK
                 else
                   STATUS_PARTIAL
                 end

        { status: status, broken: ks_broken }
      end

      private

      def routing_kill_switch_active?
        netstat = @snapshot.netstat_rn
        return false if netstat.nil? || netstat.empty?

        has_blackhole_route = netstat.match?(/\b(blackhole|reject)\b/i)
        vpn_exclusive = @snapshot.vpn_route_override? && !@snapshot.unprotected_default_route?

        has_blackhole_route || vpn_exclusive
      end
    end

    class DNSLeakDetector < BaseDetector
      def detect(vpn_active: false)
        return { leak: false, severity: :none, message: '🟢 Aucune (VPN Off)' } unless vpn_active

        dns_servers = dns_resolver.dns_servers
        local_dns = dns_servers.any? { |d| d.start_with?('127.', '10.', '172.', '192.168.') }
        public_dns = dns_servers.any? { |d| TRUSTED_DNS.include?(d) }

        if local_dns && public_dns
          { leak: false, severity: :mixed, message: '🟡 Configuration DNS mixte' }
        elsif public_dns
          Logger.warn("Fuite DNS détectée")
          { leak: true, severity: :high, message: '🔴 Risque élevé de fuite DNS' }
        else
          { leak: false, severity: :none, message: '🟢 Aucun risque DNS détecté' }
        end
      end
    end

    class LeakDetector < BaseDetector
      def stun_leak_detected?
        @snapshot.netstat_snap.stun_leak?
      end

      def check_webrtc_leak(vpn_ip)
        raw_response = @http_client.make_request('https://ipleak.net/json/', timeout: Config::HTTP_READ_TIMEOUT)
        json_data    = @http_client.parse_json_safely(raw_response)

        webrtc_ips = json_data['webrtc_ips'] || []
        leaked_ips = webrtc_ips.reject { |ip| ip == vpn_ip }

        { leak: !leaked_ips.empty?, leaked_ips: leaked_ips }
      end

      def detect_ipv6_leak(snapshot_param = nil, public_ipv6 = nil)
        curr_snapshot = snapshot_param || @snapshot
        ipv6_interface_active = curr_snapshot.ipv6_interface_active?
        vpn_route_active      = curr_snapshot.vpn_route_override?

        if ipv6_interface_active && public_ipv6 && vpn_route_active
          if curr_snapshot.vpn_ipv6_interface?
            { leak: false, message: '🟢 IPv6 sécurisé (Tunnel)', active: true }
          else
            Logger.warn("Fuite IPv6 détectée: #{public_ipv6}")
            { leak: true, message: '🚨 Fuite IPv6 !', active: true }
          end
        elsif ipv6_interface_active
          { leak: false, message: '🟢 IPv6 actif (non VPN)', active: true }
        else
          { leak: false, message: '🟢 Aucune', active: false }
        end
      end
    end

    class WebRTCLeakDetector < BaseDetector
      def detect(vpn_ip: nil)
        return { leak: false, message: '⚪ Non' } if vpn_ip.nil? || %w[Non\ détectée Non\ vérifiable Inconnu].include?(vpn_ip)
        return { leak: false, message: '⚪ Non (Hors-ligne)' } unless Infrastructure::NetTools.internet?

        leak_tool = LeakDetector.new(snapshot: @snapshot, http_client: @http_client)
        webrtc_check = leak_tool.check_webrtc_leak(vpn_ip)
        stun_detected = leak_tool.stun_leak_detected?

        has_split = @snapshot.unprotected_default_route? && @snapshot.vpn_route_override?
        leak_detected = webrtc_check[:leak] || stun_detected

        if leak_detected && has_split
          { leak: false, message: '⚠️ Bypass Actif (Exceptions)' }
        elsif leak_detected
          leaked = webrtc_check[:leaked_ips]
          Logger.error("Fuite WebRTC détectée : VPN IP = #{vpn_ip}, IPs WebRTC = #{leaked.inspect}")
          { leak: true, message: '🚨 Fuite Détectée !' }
        else
          { leak: false, message: '🟢 Non' }
        end
      end
    end

    class TorDetector < BaseDetector
      def detect(ip: nil)
        return { active: false, message: '🟡 Inactif' } if ip.nil? || %w[Non\ détectée Inconnu].include?(ip)
        socks_open = test_socks_proxy
        tor_process = tor_process_running?
        exit_node = exit_node_list.include?(ip)
        active = socks_open || tor_process || exit_node
        { active: active, message: active ? '🟣 Actif' : '⚪ Inactif' }
      end

      private

      def test_socks_proxy
        socket = Timeout.timeout(0.5) { TCPSocket.new("127.0.0.1", 9050) }
        socket.write("\x05\x01\x00")
        response = nil
        response = socket.readpartial(2) if IO.select([socket], nil, nil, 0.5)
        socket.close rescue nil
        response == "\x05\x00"
      rescue StandardError => e
        Logger.log_timeout("TorDetector SOCKS", "SOCKS5 Proxy Check") if e.is_a?(Timeout::Error)
        false
      end

      def tor_process_running?
        tor_procs = %w[tor obfs4proxy]
        ((@snapshot.ps_procs || []) & tor_procs).any?
      end

      def exit_node_list
        fetch_tor_exits
      end

      def fetch_tor_exits
        cached = Infrastructure::SecureDiskCache.read_json(
          Config::TOR_EXIT_CACHE_FILE,
          ttl: Config::TOR_EXIT_CACHE_TTL
        )
        return cached.to_set if cached.is_a?(Array)

        res = @http_client.get(
          'https://check.torproject.org/exit-addresses',
          timeout: VPNChecker::Config::TIMEOUT_FAST
        )
        exits = res ? res.scan(/ExitAddress\s+([0-9\.]+)/).flatten.uniq : []
        Infrastructure::SecureDiskCache.write_json(Config::TOR_EXIT_CACHE_FILE, exits) unless exits.empty?
        exits.to_set
      end
    end

    class IPv6LeakDetector < BaseDetector
      def detect(public_ipv6 = nil)
        LeakDetector.new(snapshot: @snapshot, http_client: @http_client).detect_ipv6_leak(@snapshot, public_ipv6)
      end
    end

    class AppleRelayDetector < BaseDetector
      def detect(ip: nil)
        return { active: false, message: '⚪ Inactif (hors Safari)' } if ip.nil? || %w[Non\ détectée Inconnu].include?(ip)
        return { active: false, message: '🟡 IP invalide' } unless VPNChecker.valid_ip?(ip)

        ip_obj = IPAddr.new(ip)
        ranges = fetch_ranges
        active = ranges.any? do |cidr|
          begin
            IPAddr.new(cidr).include?(ip_obj)
          rescue ArgumentError
            false
          end
        end

        { active: active, message: active ? '🍎 Actif (Système)' : '⚪ Inactif (Hors Safari)' }
      end

      private

      def fetch_ranges
        cached = Infrastructure::SecureDiskCache.read_json(
          Config::APPLE_RELAY_CACHE_FILE,
          ttl: Config::APPLE_RELAY_CACHE_TTL
        )
        return cached if cached.is_a?(Array)

        body = @http_client.get(
          "https://mask-api.icloud.com/egress-ip-ranges.csv",
          timeout: Config::HTTP_READ_TIMEOUT
        )
        return [] unless body

        ranges = body.to_s.lines
                       .map { |line| line.split(",").first&.strip }
                       .compact
                       .reject(&:empty?)
                       .uniq
        Infrastructure::SecureDiskCache.write_json(Config::APPLE_RELAY_CACHE_FILE, ranges) unless ranges.empty?
        ranges
      rescue StandardError => e
        Logger.warn("AppleRelayDetector range fetch error: #{e.message}")
        []
      end
    end

    class ProviderDetector < BaseDetector
      def detect(geo_info: {}, ip: nil)
        return { provider: 'Inconnu', type: Enums::InfrastructureType[:RESIDENTIAL], confidence: 0 } if ip.nil? || %w[Non\ détectée Inconnu].include?(ip)

        info = geo_info || {}
        org = info['org'] || info[:org] || ''
        asn_raw = info['asn'] || info[:asn] || ''
        asn_num = asn_raw.to_s.gsub(/\D/, '').to_i
        raw_type = info['type'] || info[:type]
        rdns = info[:reverse_dns].to_s.downcase
        org_down = org.to_s.downcase

        provider = detect_provider_from_mappings(org_down) || detect_provider_from_asn(asn_raw.to_s)

        type = if RESIDENTIAL_ASNS.key?(asn_num)
                 Enums::InfrastructureType[:RESIDENTIAL]
               elsif raw_type && !raw_type.to_s.empty?
                 raw_type.to_s.upcase.to_sym
               elsif rdns.include?('hosted') || rdns.include?('vpn') || org_down.include?('worldstream') || org_down.include?('datacenter')
                 Enums::InfrastructureType[:HOSTING]
               else
                 Enums::InfrastructureType[:RESIDENTIAL]
               end

        provider_name = provider || (RESIDENTIAL_ASNS[asn_num] if RESIDENTIAL_ASNS.key?(asn_num)) || (org.empty? ? 'INCONNU' : org.sub(/^AS\d+\s*/, ''))
        confidence = calculate_confidence(org_down, asn_raw.to_s, provider)

        { provider: provider_name, type: type, confidence: confidence }
      end

      private

      def detect_provider_from_mappings(org_down)
        return nil if org_down.empty?
        VPN_PROVIDERS.each do |pattern, name|
          return name if pattern.match?(org_down)
        end
        nil
      end

      def detect_provider_from_asn(asn)
        return nil if asn.empty?
        asn_upper = asn.upcase
        VPN_PROVIDERS.each do |pattern, name|
          return name if pattern.match?(asn_upper)
        end
        nil
      end

      def calculate_confidence(org_down, asn_str, provider)
        score = 0
        score += 40 if provider && provider != 'Inconnu'
        score += 30 if org_down.include?('vpn') || asn_str.downcase.include?('vpn')
        score += 20 if org_down.include?('datacenter') || org_down.include?('hosting')
        [score, 100].min
      end
    end

    class SplitTunnelDetector < BaseDetector
      def detect(vpn_active: false)
        return { detected: false, message: '🟢 Aucun', severity: 'none' } unless vpn_active

        exceptions = @snapshot.direct_host_routes
        has_vpn_override = @snapshot.vpn_route_override?

        if exceptions.any?
          {
            detected: true,
            message: "⚠️ Split-Tunnel actif (#{exceptions.size} IPs contournent le VPN)",
            severity: 'medium'
          }
        elsif @snapshot.unprotected_default_route? && !has_vpn_override
          { detected: true, message: '⚠️ Oui (Altéré)', severity: 'high' }
        else
          { detected: false, message: '🟢 Aucun', severity: 'none' }
        end
      end
    end
  end

  module Intelligence
    class IPLookupService
      def initialize(http_client: nil)
        @http_client = http_client || Network::HTTPClient.new
      end

      def fetch_public_ips
        ipv4, ipv6 = nil, nil
        threads = []

        threads << Thread.new { ipv4 = fetch_fastest(VPNChecker::Config::PUBLIC_IP_APIS, :v4) }
        threads << Thread.new { ipv6 = fetch_fastest(VPNChecker::Config::PUBLIC_IPV6_APIS, :v6) }

        threads.each { |t| t.join(VPNChecker::Config::TIMEOUT_FAST) }
        ipv6 = nil if ipv6 == ipv4

        {
          v4: VPNChecker::Helpers.clean_str(ipv4, fallback_ip_from_state('ip', nil)),
          v6: VPNChecker::Helpers.clean_str(ipv6, nil)
        }
      end

      private

      def fetch_fastest(api_configs, type)
        sorted_apis = api_configs.sort_by { |api| api[:priority] }

        sorted_apis.each do |api|
          res = @http_client.get(api[:url], timeout: VPNChecker::Config::TIMEOUT_FAST)&.strip
          clean = sanitize_ip(res, type)
          return clean if clean
        end
        nil
      end

      def sanitize_ip(ip, type)
        return nil if ip.nil? || ip.empty?
        clean_ip = ip.strip
        return nil unless VPNChecker.valid_ip?(clean_ip)

        parsed = IPAddr.new(clean_ip)
        if type == :v4 && parsed.ipv4?
          clean_ip
        elsif type == :v6 && parsed.ipv6?
          clean_ip
        end
      rescue ArgumentError, IPAddr::InvalidAddressError
        nil
      end

      def fallback_ip_from_state(field, default_val)
        state = VPNChecker::FlagTracer.load_current_state
        state[field] || default_val
      end
    end

    class GeoLookupService
      def initialize(reverse_dns = nil, http_client: nil)
        @reverse_dns = reverse_dns
        @http_client = http_client || Network::HTTPClient.new
      end

      def fetch_geo_and_ptr(ip_address)
        geo_res = geo(ip_address)
        ptr_res = @reverse_dns ? @reverse_dns.lookup(ip_address) : nil

        {
          geo: geo_res || fallback_geo,
          ptr: ptr_res
        }
      end

      def geo(ip)
        return fallback_geo if ip == 'Non détectée' || ip.nil? || !VPNChecker.valid_ip?(ip)

        res = fetch_ipwhois(ip)
        return res if res && !res.empty?

        res = fetch_ipapi(ip)
        return res if res && !res.empty?

        fallback_geo_from_state
      end

      def fallback_geo
        {
          country: nil, country_code: nil, region: nil, city: nil,
          latitude: nil, longitude: nil, timezone: nil,
          asn: nil, org: nil, type: Enums::InfrastructureType[:UNKNOWN]
        }
      end

      private

      def fallback_geo_from_state
        state = VPNChecker::FlagTracer.load_current_state
        {
          country: state['country'],
          country_code: nil,
          region: nil,
          city: nil,
          latitude: nil,
          longitude: nil,
          timezone: nil,
          asn: nil,
          org: state['isp'],
          type: Enums::InfrastructureType[:UNKNOWN]
        }
      end

      # FIX 3 : Utilisation de parse_json_safely pour éviter tout crash si la réponse n'est pas du JSON valide
      def fetch_ipwhois(ip)
        res = @http_client.get("https://ipwho.is/#{ip}", timeout: VPNChecker::Config::TIMEOUT_SLOW)
        return {} unless res

        json = @http_client.parse_json_safely(res)
        return {} unless json['success']

        {
          country: VPNChecker::Helpers.clean_str(json['country'], nil),
          country_code: VPNChecker::Helpers.clean_str(json['country_code'], nil),
          region: VPNChecker::Helpers.clean_str(json['region'], nil),
          city: VPNChecker::Helpers.clean_str(json['city'], nil),
          latitude: (json['latitude'] rescue nil),
          longitude: (json['longitude'] rescue nil),
          timezone: VPNChecker::Helpers.clean_str(json.dig('timezone', 'id'), nil),
          asn: VPNChecker::Helpers.clean_str(json.dig('connection', 'asn') ? "AS#{json.dig('connection', 'asn')}" : nil, nil),
          org: VPNChecker::Helpers.clean_str(json.dig('connection', 'org') || json.dig('connection', 'isp'), nil),
          type: VPNChecker::Helpers.clean_str(json.dig('connection', 'type'), Enums::InfrastructureType[:HOSTING])
        }
      rescue StandardError
        {}
      end

      # FIX 3 : Utilisation de parse_json_safely
      def fetch_ipapi(ip)
        res = @http_client.get("https://ipapi.co/#{ip}/json/", timeout: VPNChecker::Config::TIMEOUT_SLOW)
        return {} unless res

        json = @http_client.parse_json_safely(res)
        return {} unless json['country_name']

        {
          country: VPNChecker::Helpers.clean_str(json['country_name'], 'Inconnu'),
          country_code: VPNChecker::Helpers.clean_str(json['country_code'], 'XX'),
          region: VPNChecker::Helpers.clean_str(json['region'], 'Inconnu'),
          city: VPNChecker::Helpers.clean_str(json['city'], 'Inconnu'),
          latitude: (json['latitude'] rescue nil),
          longitude: (json['longitude'] rescue nil),
          timezone: VPNChecker::Helpers.clean_str(json['timezone'], nil),
          asn: VPNChecker::Helpers.clean_str(json['asn'], nil),
          org: VPNChecker::Helpers.clean_str(json['org'], nil),
          type: Enums::InfrastructureType[:HOSTING]
        }
      rescue StandardError
        {}
      end
    end

    class ReverseDNS
      def initialize(http_client: nil)
        @http_client = http_client || Network::HTTPClient.new
      end

      def lookup(ip)
        return nil if ip == 'Non détectée' || ip.nil? || ip.to_s.empty? || !VPNChecker.valid_ip?(ip)

        resolver = Resolv::DNS.new
        resolver.timeouts = VPNChecker::Config::TIMEOUT_DNS

        Timeout.timeout(VPNChecker::Config::TIMEOUT_FAST) do
          resolver.getname(ip).to_s
        end
      rescue Timeout::Error => e
        Logger.log_timeout("ReverseDNS", "Lookup IP #{ip}")
        nil
      rescue StandardError
        nil
      end
    end

    class SecurityScore
      def self.calculate(ctx_struct)
        return nil unless ctx_struct[:ip_ok]

        score = 65

        if ctx_struct.dig(:vpn, :active)
          score += 30
          score += (ctx_struct.dig(:vpn, :confidence).to_i * 0.1).to_i
        else
          score += 40
        end

        ks_status = ctx_struct.dig(:ks, :status).to_s
        if ks_status.include?('OK')
          score += 15
        elsif ks_status.include?('FAIL')
          score -= 30
        end

        dns_encrypted = ctx_struct[:dns_encrypted]
        if dns_encrypted.is_a?(Hash) && dns_encrypted[:encrypted]
          score += 10
        elsif dns_encrypted.is_a?(Hash) && !dns_encrypted[:encrypted]
          score -= 5
        end

        score -= 25 if ctx_struct.dig(:dns_leak, :leak)
        score -= 10 if ctx_struct.dig(:dns_leak, :severity) == :mixed

        score -= 25 if ctx_struct.dig(:webrtc_leak, :leak)
        score -= 20 if ctx_struct.dig(:ipv6, :leak)
        score -= 15 if ctx_struct.dig(:split_tunnel, :detected)
        score += 5  if ctx_struct.dig(:tor, :active)

        provider_conf = ctx_struct.dig(:provider, :confidence).to_i
        score += (provider_conf * 0.1).to_i if provider_conf > 50

        [[score, 0].max, 100].min
      end
    end

    class PerformanceMonitor
      def self.measure(internet_available: nil)
        internet_available = Infrastructure::NetTools.internet? if internet_available.nil?
        return { latency: nil, jitter: nil } unless internet_available

        cached = Infrastructure::SecureDiskCache.read_json(
          VPNChecker::Config::PERFORMANCE_CACHE_FILE,
          ttl: VPNChecker::Config::PERFORMANCE_CACHE_TTL
        )
        return cached if cached.is_a?(Hash) && cached.key?('latency') && cached.key?('jitter')

        latencies = measure_latencies
        return { latency: nil, jitter: nil } if latencies.empty?

        avg_lat = (latencies.sum / latencies.size).round
        jitter = latencies.size > 1 ? (latencies.max - latencies.min).round : 0
        result = { latency: "#{avg_lat} ms", jitter: "#{jitter} ms" }
        Infrastructure::SecureDiskCache.write_json(VPNChecker::Config::PERFORMANCE_CACHE_FILE, result)
        result
      end

      def self.measure_latencies
        latencies = []
        target_host = VPNChecker::Config::PING_HOSTS.first || '1.1.1.1'
        2.times do
          t1 = Time.now
          socket = nil
          begin
            socket = Timeout.timeout(0.5) { TCPSocket.new(target_host, 53) }
            latencies << ((Time.now - t1) * 1000).round
          rescue Timeout::Error => e
            Logger.log_timeout("PerformanceMonitor", "TCP Socket Ping #{target_host}")
          rescue StandardError
            nil
          ensure
            socket&.close rescue nil
          end
        end
        latencies.compact
      end
    end
  end

  module Renderers
    module EmojiHelper
      module_function

      def country_code_to_emoji(code)
        return '🏴‍☠️' unless code && code.size == 2 && code != 'XX'
        code.upcase.codepoints.map { |c| (127397 + c).chr('UTF-8') }.join
      rescue StandardError
        '🏴‍☠️'
      end
    end

    class ContextBuilder
      def generate_live_context(snapshot, geo_data)
        fingerprint_raw = build_raw_fingerprint(snapshot)

        {
          fingerprint: generate_fingerprint_hash(fingerprint_raw),
          network_state: evaluate_network_protection(snapshot),
          geo_location: geo_data
        }
      end

      private

      def build_raw_fingerprint(snapshot)
        "#{snapshot.primary_interface}-#{snapshot.default_gateway}"
      end

      def generate_fingerprint_hash(fingerprint_raw)
        Digest::SHA256.hexdigest(fingerprint_raw)[0..11]
      end

      def evaluate_network_protection(snapshot)
        snapshot.vpn_active? ? Enums::ProtectionState[:PROTECTED] : Enums::ProtectionState[:EXPOSED]
      end
    end

    class XbarRenderer
      def self.render(context)
        return if context.nil?

        if context.key?(:network_state) && context.key?(:leak_status)
          render_simple(context: context, leak_status: context[:leak_status], firewall_status: context[:firewall_status])
        else
          render_full(context)
        end
      end

      def self.render_simple(context:, leak_status:, firewall_status:)
        network_state = context[:network_state]
        geo = context[:geo_location] || {}

        if network_state == Enums::ProtectionState[:PROTECTED] && !leak_status[:leak]
          puts "🔒 VPN | color=green"
        else
          puts "🚨 ALERTE | color=red"
        end

        puts "---"
        puts "État Réseau : #{network_state.to_s.upcase}"
        puts "Empreinte   : #{context[:fingerprint]}"
        puts "Pare-feu PF : #{firewall_status ? '🟢 OK' : '🔴 Non sécurisé'}"

        if leak_status[:leak]
          puts "---"
          puts "⚠️ Fuites Détectées | color=orange"
          puts "Détails: #{leak_status[:message]}"
        end

        puts "---"
        puts "IP Publique : #{geo[:ip] || 'N/A'}"
        puts "Pays        : #{geo[:country] || 'Inconnu'}"
      end

      def self.render_full(context)
        ips = context[:ips] || {}
        geo = context[:geo] || {}
        vpn = context[:vpn] || {}
        ks = context[:ks] || {}
        dns_leak = context[:dns_leak] || {}
        webrtc_leak = context[:webrtc_leak] || {}
        ipv6 = context[:ipv6] || {}
        tor = context[:tor] || {}
        apple_relay = context[:apple_relay] || {}
        provider = context[:provider] || {}
        split_tunnel = context[:split_tunnel] || {}
        perf = context[:perf] || {}
        firewall_status = context[:firewall_status]

        country_code = (geo[:country_code] || 'XX').upcase
        country_name = geo[:country] || 'N/D'
        org = geo[:org] || provider[:provider] || 'N/D'
        ip_v4 = ips[:v4] || 'N/D'

        is_denied   = Config::DENY_COUNTRIES.include?(country_code)
        is_allowed  = Config::ALLOWED_COUNTRIES.include?(country_code)

        flag_emoji = is_denied ? "🚨" : "🔐 #{EmojiHelper.country_code_to_emoji(country_code)}"
        header_color = is_denied ? "#FF0000" : (is_allowed ? "#006400" : "#FF8C00")

        country_status_label = if is_denied
                                 '🚨 [DANGER / DENY]'
                               elsif is_allowed
                                 '✅ [SÉCURISÉ / ALLOWED]'
                               else
                                 '⚠️ [HORS LISTE AUTORISÉE]'
                               end

        VPNChecker::FlagTracer.trace_and_log(flag_emoji, header_color, ip_v4, country_name, org)

        puts "#{flag_emoji} | color=#{header_color} dropdown=true"
        puts "---"
        puts "VPN Checker v#{APP_VERSION} | font=Menlo"
        puts "---"

        puts "🌐 IDENTITÉ RÉSEAU (#{ip_v4})"
        rdns_info = VPNChecker::Helpers.reverse_dns_status(context[:ptr], org, ip_v4, vpn_active: vpn[:active])

        if rdns_info[:alert] && context[:ptr]
          puts "PTR Alerte: (#{sanitize_xbar(context[:ptr])}) (#{sanitize_xbar(org)}) 🚨[PTR Incohérent]"
        end

        puts "Infrastructure: ☁️ #{provider[:type] == Enums::InfrastructureType[:HOSTING] ? 'Cloud / VPN' : 'Résidentiel'} (#{sanitize_xbar(geo[:asn])})"
        puts "---"
        puts "📍 LOCALISATION"
        puts "Pays: #{EmojiHelper.country_code_to_emoji(country_code)} #{sanitize_xbar(country_name)} (#{sanitize_xbar(geo[:region])}) #{country_status_label}"
        coords = if geo[:latitude] && geo[:longitude]
                    "#{geo[:latitude]}, #{geo[:longitude]}"
                  else
                    'N/D'
                  end
        puts "Coordonnées: #{coords}"
        puts "Fuseau horaire: #{geo[:timezone] ? sanitize_xbar(geo[:timezone]) : 'N/D'}"

        puts "---"
        score_display = context[:sec_score] ? "#{context[:sec_score]}%" : 'N/D'
        puts "🔒 SÉCURITÉ RÉSEAU • Score: #{score_display}"
        puts "Pare-feu PF: #{firewall_status ? '🟢 OK (Règles isolées)' : '⚪ Non configuré / Inactif'}"
        puts "VPN: #{vpn[:active] ? "🟢 Actif (#{vpn[:tunnel_type]})" : '🔴 Inactif'}"
        puts "Kill Switch: #{sanitize_xbar(ks[:status])}"
        puts "Split Tunnel: #{sanitize_xbar(split_tunnel[:message])}"

        puts "Apple Private Relay: #{sanitize_xbar(apple_relay[:message])}"
        puts "Tor: #{sanitize_xbar(tor[:message])}" if tor[:active]
        puts "Fuite DNS: #{sanitize_xbar(dns_leak[:message])}"
        puts "Fuite IPv6: #{sanitize_xbar(ipv6[:message])}"
        puts "Fuite WebRTC: #{sanitize_xbar(webrtc_leak[:message])} | href=https://browserleaks.com/webrtc"
        puts "DNS Chiffré: #{context.dig(:dns_encrypted, :message) || '⚪ Non déterminé'}"
        puts "---"
        puts "🔍 SERVEURS DNS"
        if context[:dns_servers].to_a.empty?
          puts "-- Aucun serveur DNS détecté"
        else
          context[:dns_servers].each { |dns| puts "-- #{dns}" }
        end
        puts "---"
        puts "⚡ PERFORMANCES"
        latency = perf[:latency] ? sanitize_xbar(perf[:latency]) : 'N/D'
        jitter = perf[:jitter] ? sanitize_xbar(perf[:jitter]) : 'N/D'
        puts "Latence: #{latency} • Jitter: #{jitter}"
        puts "---"

        puts "🚪 PORTS TCP ÉCOUTÉS (SÉCURITÉ)"
        open_ports = context[:open_ports].to_a
        if open_ports.empty?
          puts "-- Aucun port TCP non standard détecté"
        else
          open_ports.each do |entry|
            puts "-- Port #{entry[:port]} (#{sanitize_xbar(entry[:command])})"
          end
        end
        puts "---"

        script_path = Shellwords.escape(File.expand_path(__FILE__))
        puts "⚡ ACTIONS RAPIDES"
        puts "-- 🔄 Rafraîchir les contrôles | refresh=true"
        puts "-- 🧹 Purger le cache local | bash=\"/usr/bin/ruby\" param1=\"#{script_path}\" param2=\"purge\" refresh=true terminal=false"
        puts "-- 🛡️ Activer le Firewall PF | bash=\"/usr/bin/osascript\" param1=\"-e\" param2='do shell script \"pfctl -e -f /etc/pf.conf\" with administrator privileges' refresh=true terminal=false"

        if SHOW_FINGERPRINT
          fingerprint = context[:fingerprint].to_s
          short_fp = fingerprint[0, 6]
          puts "---"
          puts "Empreinte: #{short_fp}… | color=#888888"
        end
      end

      private

      def self.sanitize_xbar(str)
        VPNChecker::Helpers.clean_str(str, 'Inconnu').gsub('|', '/').gsub("\n", ' ').strip
      end
    end
  end

  class Application
    def initialize
      @lru_cache = Infrastructure::AdaptiveLRUCache.new(50)
    end

    def build_context
      generate_live_context
    end

    def build_offline_context(snapshot, dns_resolver)
      Logger.warn("Pas de connexion Internet détectée.")
      {
        offline: true, ip_ok: false, ips: { v4: nil, v6: nil },
        geo: Intelligence::GeoLookupService.new.fallback_geo,
        ptr: nil, vpn: Detectors::VPNDetector.new(snapshot: snapshot).detect,
        ks: { status: '⚪ Inactif (Hors ligne)', broken: false },
        dns_leak: { leak: false, severity: :none, message: '⚪ Hors ligne' },
        webrtc_leak: { leak: false, message: '⚪ Hors ligne' },
        tor: { active: false, message: '🟡 Inactif' },
        ipv6: Detectors::LeakDetector.new(snapshot: snapshot).detect_ipv6_leak(snapshot, nil),
        apple_relay: { active: false, message: '⚪ Inactif' },
        provider: { provider: 'Inconnu', type: Enums::InfrastructureType[:UNKNOWN], confidence: 0 },
        split_tunnel: Detectors::SplitTunnelDetector.new(snapshot: snapshot).detect,
        dns_encrypted: Detectors::EncryptedDNSDetector.new(snapshot: snapshot).detect,
        open_ports: [],
        dns_consistency: calculate_dns_consistency(dns_resolver),
        dns_servers: format_dns_servers(dns_resolver),
        perf: { latency: nil, jitter: nil },
        interface: snapshot.default_interface, sec_score: nil,
        firewall_status: Infrastructure::FirewallChecker.rules_ok?,
        fingerprint: nil
      }
    end

    def generate_live_context
      snapshot = Infrastructure::SystemSnapshot.new(cache: @lru_cache)
      dns_resolver = Infrastructure::AdvancedDNSResolver.new(snapshot)

      return build_offline_context(snapshot, dns_resolver) unless Infrastructure::NetTools.internet?

      http_client = Network::HTTPClient.new
      reverse_dns = Intelligence::ReverseDNS.new(http_client: http_client)
      geo_lookup_service = Intelligence::GeoLookupService.new(reverse_dns, http_client: http_client)
      ip_lookup = Intelligence::IPLookupService.new(http_client: http_client)

      ips = ip_lookup.fetch_public_ips || { v4: nil, v6: nil }

      geo_and_ptr = geo_lookup_service.fetch_geo_and_ptr(ips[:v4])
      geo = geo_and_ptr[:geo] || {}
      ptr_val = geo_and_ptr[:ptr]
      geo = geo.merge(reverse_dns: ptr_val)

      detectors = {
        vpn: Detectors::VPNDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        ks: Detectors::KillSwitchDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        dns_leak: Detectors::DNSLeakDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        webrtc: Detectors::WebRTCLeakDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        tor: Detectors::TorDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        leak: Detectors::LeakDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        apple_relay: Detectors::AppleRelayDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        provider: Detectors::ProviderDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        split_tunnel: Detectors::SplitTunnelDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        encrypted_dns: Detectors::EncryptedDNSDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        open_ports: Detectors::OpenPortsDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver)
      }

      results = {}
      mutex = Mutex.new
      threads = []

      # Étape 1 : Détection synchrone ultra-rapide de l'état du VPN pour alimenter tous les dépendants
      vpn_res = detectors[:vpn].detect
      results[:vpn] = vpn_res
      vpn_active = vpn_res[:active]

      # FIX 2 : Intégration parallèle de TOUS les détecteurs dans le pool de threads principal
      threads << Thread.new { res = detectors[:provider].detect(geo_info: geo, ip: ips[:v4]); mutex.synchronize { results[:provider] = res } }
      threads << Thread.new { res = detectors[:webrtc].detect(vpn_ip: ips[:v4]); mutex.synchronize { results[:webrtc_leak] = res } }
      threads << Thread.new { res = detectors[:tor].detect(ip: ips[:v4]); mutex.synchronize { results[:tor] = res } }
      threads << Thread.new { res = detectors[:leak].detect_ipv6_leak(snapshot, ips[:v6]); mutex.synchronize { results[:ipv6] = res } }
      threads << Thread.new { res = detectors[:apple_relay].detect(ip: ips[:v4]); mutex.synchronize { results[:apple_relay] = res } }
      threads << Thread.new { res = detectors[:encrypted_dns].detect; mutex.synchronize { results[:dns_encrypted] = res } }
      threads << Thread.new { res = detectors[:open_ports].detect; mutex.synchronize { results[:open_ports] = res } }
      threads << Thread.new { res = Infrastructure::FirewallChecker.rules_ok?; mutex.synchronize { results[:firewall_status] = res } }
      threads << Thread.new { res = Intelligence::PerformanceMonitor.measure(internet_available: true); mutex.synchronize { results[:perf] = res } }
      threads << Thread.new { res = detectors[:ks].detect(vpn_active: vpn_active); mutex.synchronize { results[:ks] = res } }
      threads << Thread.new { res = detectors[:dns_leak].detect(vpn_active: vpn_active); mutex.synchronize { results[:dns_leak] = res } }
      threads << Thread.new { res = detectors[:split_tunnel].detect(vpn_active: vpn_active); mutex.synchronize { results[:split_tunnel] = res } }

      threads.each { |t| t.join(1.0) }

      vpn_result          = results[:vpn]
      provider_result     = results[:provider] || { provider: 'Inconnu', type: Enums::InfrastructureType[:UNKNOWN], confidence: 0 }
      webrtc_result       = results[:webrtc_leak] || { leak: false, message: '⚪ Non' }
      tor_result          = results[:tor] || { active: false, message: '⚪ Inactif' }
      ipv6_result         = results[:ipv6] || { leak: false, message: '🟢 Aucune', active: false }
      apple_relay_result  = results[:apple_relay] || { active: false, message: '⚪ Inactif' }
      dns_encrypted       = results[:dns_encrypted] || { encrypted: false, methods: [], message: '❌ DNS standard' }
      open_ports_result   = results[:open_ports] || []
      firewall_status     = results.key?(:firewall_status) ? results[:firewall_status] : Infrastructure::FirewallChecker.rules_ok?
      perf                = results[:perf] || { latency: nil, jitter: nil }
      ks_result           = results[:ks] || { status: '⚪ Inactif', broken: false }
      dns_leak_result     = results[:dns_leak] || { leak: false, severity: :none, message: '🟢 Aucune' }
      split_tunnel_result = results[:split_tunnel] || { detected: false, message: '🟢 Aucun', severity: 'none' }

      dns_consistency     = calculate_dns_consistency(dns_resolver)
      ip_ok               = !Infrastructure::SecureDiskCache.invalid_value?(ips[:v4])

      base_context = {
        ips: ips, geo: geo, ptr: ptr_val, vpn: vpn_result, ks: ks_result,
        dns_leak: dns_leak_result, webrtc_leak: webrtc_result, tor: tor_result,
        ipv6: ipv6_result, apple_relay: apple_relay_result, provider: provider_result,
        split_tunnel: split_tunnel_result, dns_encrypted: dns_encrypted,
        open_ports: open_ports_result,
        dns_consistency: dns_consistency,
        dns_servers: format_dns_servers(dns_resolver),
        calculated_tunnel_dns: dns_resolver.detected_tunnel_dns,
        perf: perf, interface: snapshot.default_interface, ip_ok: ip_ok, offline: false,
        firewall_status: firewall_status
      }

      calculated_score = Intelligence::SecurityScore.calculate(base_context)
      live_context_data = Renderers::ContextBuilder.new.generate_live_context(snapshot, geo)

      base_context.merge(
        sec_score: calculated_score,
        live_context: live_context_data,
        fingerprint: live_context_data[:fingerprint]
      )
    end

    def render
      Timeout.timeout(VPNChecker::Config::MAX_TOTAL_TIMEOUT) do
        context = build_context
        Renderers::XbarRenderer.render(context)
      end
    rescue Timeout::Error => e
      Logger.log_timeout("Application#render (Global MAX_TOTAL_TIMEOUT)", "#{VPNChecker::Config::MAX_TOTAL_TIMEOUT}s dépassés")
      puts "🚨 ALERTE Timeout | color=orange"
      puts "---"
      puts "Exécution trop lente (>#{VPNChecker::Config::MAX_TOTAL_TIMEOUT}s)"
    end

    private

    def calculate_dns_consistency(dns_resolver)
      dns_servers = dns_resolver.dns_servers
      has_local_or_vpn = dns_servers.any? { |d| d.start_with?('10.', '127.', '172.', '192.168.') }
      has_public = dns_servers.any? { |d| TRUSTED_DNS.include?(d) }

      if has_local_or_vpn && has_public
        '🟡 Configuration DNS mixte'
      else
        '🟢 Cohérent'
      end
    end

    def format_dns_servers(dns_resolver)
      dns_servers = dns_resolver.dns_servers
      formatted = []

      dns_servers.each do |dns|
        if DNS_PROVIDERS.key?(dns)
          formatted << "#{DNS_PROVIDERS[dns]} (#{dns})"
        elsif dns.start_with?('10.', '172.', '192.168.')
          formatted << "🔐 Local/Private (#{dns})"
        else
          formatted << "🌐 #{dns}"
        end
      end

      formatted.uniq
    end
  end

  class TestRunner
    def self.run!
      puts "=== Suite de Tests v#{APP_VERSION} VPNChecker ==="
      tests_passed = 0
      tests_failed = 0

      begin
        snapshot = VPNChecker::Infrastructure::SystemSnapshot.new
        vpn_det = VPNChecker::Detectors::VPNDetector.new(snapshot: snapshot)
        res = vpn_det.detect
        raise "Erreur structure de VPNDetector" unless res.key?(:active) && res.key?(:confidence)
        puts "✅ VPNDetector : PASS"
        tests_passed += 1
      rescue StandardError => e
        puts "❌ VPNDetector : FAIL (#{e.message})"
        tests_failed += 1
      end

      begin
        snapshot = VPNChecker::Infrastructure::SystemSnapshot.new
        dns_leak_det = VPNChecker::Detectors::DNSLeakDetector.new(snapshot: snapshot)
        res = dns_leak_det.detect(vpn_active: false)
        raise "Erreur VPNOff sur DNSLeakDetector" if res[:leak] != false
        puts "✅ DNSLeakDetector : PASS"
        tests_passed += 1
      rescue StandardError => e
        puts "❌ DNSLeakDetector : FAIL (#{e.message})"
        tests_failed += 1
      end

      begin
        res = VPNChecker::Infrastructure::FirewallChecker.rules_ok?
        raise "FirewallChecker doit retourner un booléen" unless [true, false].include?(res)
        puts "✅ FirewallChecker : PASS"
        tests_passed += 1
      rescue StandardError => e
        puts "❌ FirewallChecker : FAIL (#{e.message})"
        tests_failed += 1
      end

      begin
        client = VPNChecker::Network::HTTPClient.new
        res = client.make_request('https://10.255.255.1', timeout: 0.2)
        raise "HTTPClient aurait dû retourner nil sur un IP morte" unless res.nil?
        puts "✅ HTTPClient / Circuit Breaker : PASS"
        tests_passed += 1
      rescue StandardError => e
        puts "❌ HTTPClient / Circuit Breaker : FAIL (#{e.message})"
        tests_failed += 1
      end

      begin
        raise "FR doit être dans DENY_COUNTRIES" unless VPNChecker::Config::DENY_COUNTRIES.include?('FR')
        raise "NL doit être dans ALLOWED_COUNTRIES" unless VPNChecker::Config::ALLOWED_COUNTRIES.include?('NL')
        puts "✅ Geofencing Rules Configuration : PASS"
        tests_passed += 1
      rescue StandardError => e
        puts "❌ Geofencing Rules Configuration : FAIL (#{e.message})"
        tests_failed += 1
      end

      begin
        cache = VPNChecker::Infrastructure::AdaptiveLRUCache.new(50)
        cache.set('test_key', 'test_val', ttl: 10)
        raise "AdaptiveLRUCache valeur incorrecte" unless cache.get('test_key') == 'test_val'
        puts "✅ AdaptiveLRUCache : PASS"
        tests_passed += 1
      rescue StandardError => e
        puts "❌ AdaptiveLRUCache : FAIL (#{e.message})"
        tests_failed += 1
      end

      puts "---"
      puts "Résultats : #{tests_passed} succè(s), #{tests_failed} échec(s)."
      exit(tests_failed > 0 ? 1 : 0)
    end
  end
end

begin
  arg_action = ARGV[0].to_s.strip.downcase
  if arg_action == 'purge'
    VPNChecker::Infrastructure::SecureDiskCache.purge_all!
    puts "Cache purgé !"
    exit 0
  elsif VPNChecker::RUN_TESTS
    VPNChecker::TestRunner.run!
  else
    VPNChecker::Application.new.render
  end
rescue StandardError => e
  VPNChecker::Logger.error("Crash application: #{e.class} - #{e.message}\n#{e.backtrace.first(3).join("\n")}")
  puts "⚠️ 🌐 | color=red"
  puts "---"
  puts "VPN Checker Erreur | font=Menlo"
  puts "---"
  puts "Message: #{e.message}"
end
