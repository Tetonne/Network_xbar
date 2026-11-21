#!/usr/bin/env ruby
# frozen_string_literal: true

# <xbar.title>VPN Checker Pro</xbar.title>
# <xbar.version>v6.1.9</xbar.version>
# <xbar.author>Tetonne & AI</xbar.author>
# <xbar.desc>Professional VPN & Network Security Analyzer — v6.1.9</xbar.desc>
# <xbar.dependencies>ruby</xbar.dependencies>
# =============================================================================
# VPN Checker Pro — v6.1.9 (macOS / xbar, Ruby cible 2.6+) — VERSION USER
# Version allégée : core code seul. Charte, historique et tests intégrés :
# voir VPN-flag619.dev.4m.rb (version dev) ou le dossier de développement.
#
# COMMANDES (depuis le dossier du plugin ; 6.1.9 -> 619 dans le nom du fichier) :
#   ruby -c VPN-flag619.4m.rb                  # Vérification syntaxique
#   ruby VPN-flag619.4m.rb --debug > /tmp/out.txt 2>/tmp/err.txt; tail -n 200 /tmp/out.txt
#   ruby VPN-flag619.4m.rb dnscrypt-block-probe|dns-stack-audit|dns-diag|dns-probe
#   ruby VPN-flag619.4m.rb --show-fingerprint / --commands
#   ruby VPN-flag619.dev.4m.rb --run-tests     # Tests intégrés (version dev)
#
# RÈGLE CARDINALE : PREUVE INSUFFISANTE -> UNKNOWN. Garde-fous P0 : zéro sudo,
# lecture seule, écart ≠ fuite, décisions arbitrées intouchables.
# =============================================================================

#!/usr/bin/env ruby
# frozen_string_literal: true

# <xbar.title>VPN Checker Pro</xbar.title>
# <xbar.version>v6.1.9</xbar.version>
# <xbar.author>Tetonne & AI</xbar.author>
# <xbar.desc>Professional VPN & Network Security Analyzer — v6.1.9</xbar.desc>
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
require 'strscan'
require 'tmpdir'

module VPNChecker
  APP_VERSION  = '6.1.9'
  ENABLE_CACHE = true

  DEBUG_MODE       = ARGV.include?('--debug') || %w[1 true yes].include?(ENV.fetch('VPN_CHECKER_DEBUG', '').downcase) unless defined?(DEBUG_MODE)
  SHOW_FINGERPRINT = ARGV.include?('--show-fingerprint') unless defined?(SHOW_FINGERPRINT)
  RUN_TESTS        = ARGV.include?('--run-tests') unless defined?(RUN_TESTS)

  # Nom de fichier attendu : 3 chiffres de version sans points (5.9.9 > 599).
  def self.expected_file_name
    "VPN-flag#{APP_VERSION.delete('.')}.4m.rb"
  end

  # Actions xbar : lien ~/.xbar-plugins -> ~/Library/Application Support/xbar/plugins
  # (terminal=true perd les guillemets sur l'espace). Méthode pure.
  def self.action_script_path
    "#{Dir.home}/.xbar-plugins/#{expected_file_name}"
  end

  # Commandes de contrôle, avec le nom de fichier donné (réel ou attendu).
  def self.control_commands(file_name = expected_file_name)
    escaped = Shellwords.escape(file_name.to_s)
    [
      "ruby -c #{escaped}",
      "ruby #{escaped} --run-tests",
      "ruby #{escaped} --debug > /tmp/out.txt 2>/tmp/err.txt; echo \"exit=$?\"; tail -n 200 /tmp/out.txt",
      "ruby #{escaped} --show-fingerprint"
    ]
  end

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

    MAX_TOTAL_TIMEOUT = 10.0
    HTTP_OPEN_TIMEOUT = 0.8
    HTTP_READ_TIMEOUT = 2.0

    TIMEOUT_FAST = 1.0
    TIMEOUT_SLOW = 1.5
    TIMEOUT_DNS  = 0.5
    THREADS_DEADLINE = 2.5
    TIMEOUT_TCP  = 0.5

    MAX_RETRIES               = 2
    RETRY_BACKOFF_STEPS       = [0.050, 0.100].freeze
    CIRCUIT_BREAKER_THRESHOLD = 3
    CIRCUIT_BREAKER_TIMEOUT   = 30

    IPV4_PATTERN = Regexp.new('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)').freeze
    IPV6_PATTERN = Regexp.new(
      '(?:' \
      '(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}' \
      '|(?:::[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}' \
      '|(?:[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}' \
      '|(?:[0-9a-fA-F]{1,4}:){1,2}:?(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}' \
      '|(?:[0-9a-fA-F]{1,4}:){1,3}:?(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}' \
      '|(?:[0-9a-fA-F]{1,4}:){1,4}:?(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}' \
      '|(?:[0-9a-fA-F]{1,4}:){1,5}:?(?:[0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}' \
      '|(?:[0-9a-fA-F]{1,4}:){1,6}:?(?:[0-9a-fA-F]{1,4})?' \
      '|::(?:ffff:)?(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' \
      '|::' \
      ')'
    ).freeze
    MASK_PATTERN = IPV4_PATTERN

    DEFAULT_ALLOWED_COUNTRIES = %w[NL CH PL RO US].freeze
    DEFAULT_DENY_COUNTRIES    = %w[FR RU CN IR KP].freeze

    def self.load_country_lists
      config_file = File.expand_path('~/.config/vpn_checker/countries.json')
      return [DEFAULT_ALLOWED_COUNTRIES, DEFAULT_DENY_COUNTRIES] unless File.file?(config_file)

      begin
        json = JSON.parse(File.read(config_file))
        raise ArgumentError, 'la racine JSON doit être un objet' unless json.is_a?(Hash)

        normalize = lambda do |key, defaults|
          value = json[key]
          # Clé absente/invalide -> liste par défaut, jamais de désactivation silencieuse.
          unless value.is_a?(Array) && value.all? { |item| item.is_a?(String) && item.match?(/\A[a-z]{2}\z/i) }
            next defaults
          end
          value.map(&:upcase).uniq.freeze
        end

        [normalize.call('allowed', DEFAULT_ALLOWED_COUNTRIES),
         normalize.call('deny', DEFAULT_DENY_COUNTRIES)]
      rescue StandardError => e
        # Config est évalué avant VPNChecker::Logger : ne pas appeler Logger ici.
        Kernel.warn("[VPNChecker] countries.json ignoré (#{e.class}) ; valeurs par défaut utilisées")
        [DEFAULT_ALLOWED_COUNTRIES, DEFAULT_DENY_COUNTRIES]
      end
    end

    ALLOWED_COUNTRIES, DENY_COUNTRIES = load_country_lists

    # Remplacement anticipé de 9.9.9.9 par FDN (80.67.169.12) pour éviter les blocages en France
    PING_HOSTS = %w[1.1.1.1 8.8.8.8 80.67.169.12].freeze

    VPN_BRAND_TOKENS = %w[protonvpn mullvad nordvpn surfshark expressvpn
                          ivpn tailscale viscosity zerotier].freeze

    VPN_GENERIC_PROCESS_KEYWORDS = %w[openvpn wireguard openconnect vpnc softether
                                       strongswan racoon charon wg-quick tunnelblick].freeze

    VPN_INTERFACE_PREFIXES = (%w[utun tun tap wg ppp ipsec vtun] + VPN_BRAND_TOKENS).freeze
    VPN_PROCESS_KEYWORDS = (VPN_GENERIC_PROCESS_KEYWORDS + VPN_BRAND_TOKENS).freeze

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

  # Liste blanche nettoyée des domaines et IP de confiance pour les exceptions / Split Tunnel
  TRUSTED_WHITELIST = %w[
    cic.fr
    ants.gouv.fr
    impots.gouv.fr
    lassuranceretraite.fr
    info-retraite.fr
    service-public.fr
    ameli.fr
    agirc-arrco.fr
    franceconnect.gouv.fr
    credit-agricole.fr
    thefork.fr
    ecoledirecte.com
    fr.igraal.com
    fr.hotels.com
    login.live.com
  ].freeze

  TRUSTED_IPS = %w[
    192.168.0.1
  ].freeze

  def self.whitelisted_domain?(host)
    return false unless host
    clean_host = host.to_s.downcase.strip
    TRUSTED_WHITELIST.any? { |domain| clean_host == domain || clean_host.end_with?(".#{domain}") }
  end

  # Comparaison par IPAddr, pas par chaîne.
  def self.whitelisted_ip?(ip)
    return false unless ip
    begin
      addr = IPAddr.new(ip.to_s.strip)
    rescue IPAddr::InvalidAddressError, ArgumentError
      return false
    end
    TRUSTED_IPS.any? do |trusted|
      begin
        addr == IPAddr.new(trusted)
      rescue IPAddr::InvalidAddressError, ArgumentError
        false
      end
    end
  end

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
    1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 80.67.169.12 9.9.9.9 149.112.112.112 94.140.14.14 94.140.15.15 49.12.223.2 49.12.43.208
  ].freeze

  DNS_PROVIDERS = {
    "1.1.1.1"         => "☁️ Cloudflare",
    "1.0.0.1"         => "☁️ Cloudflare",
    "8.8.8.8"         => "🟦 Google",
    "8.8.4.4"         => "🟦 Google",
    "80.67.169.12"    => "🌐 FDN",
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
    return false if ip.nil?

    ip_str = ip.to_s.strip
    return false if ip_str.empty? || ip_str.include?('/')

    # IPAddr accepte CIDR/masque : rejeter tout sauf une adresse seule.
    addr = IPAddr.new(ip_str)
    return false if addr.to_s != ip_str && addr.to_string != ip_str.downcase
    # IPv6 non canonique admis (régression 5.50), CIDR refusé.

    true
  rescue StandardError
    false
  end

  module Helpers
    module_function

    def evaluate_ptr_status(ptr, org, vpn_active: false)
      return { status: Enums::PTRStatus[:UNKNOWN], valid: false } if ptr.nil? || ptr.to_s.empty? || ptr.to_s.include?("Inconnu")

      ptr_down = ptr.to_s.downcase
      org_down = org.to_s.downcase

      has_known_pattern = vpn_related_keywords?(ptr_down) || ptr_down.include?('hosted-by')

      org_tokens = org_down.scan(/[a-z0-9]+/).reject { |t| %w[inc ltd corp gmbh bv llc sa].include?(t) || t.length <= 2 }
      matches_org = org_tokens.any? { |token| ptr_down.include?(token) }

      if matches_org || has_known_pattern
        { status: Enums::PTRStatus[:VALID], valid: true }
      elsif vpn_active
        { status: Enums::PTRStatus[:SUSPECT], valid: false }
      else
        { status: Enums::PTRStatus[:UNKNOWN], valid: false }
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
      sanitized = val.to_s
                 .gsub(/[\u00A0\u2000-\u200B\u202F\uFEFF]/, ' ')
                 .gsub(/[\u202A-\u202E\u2066-\u2069]/, '') # Suppression des marques Bidi
                 .gsub(/\p{Cc}|\p{Cf}/, '')                 # Suppression des caractères de contrôle et de format
                 .strip
      sanitized.empty? ? fallback : sanitized
    end

    # Matching centralisé des fournisseurs VPN ; retourne le nom ou nil.
    def detect_vpn_provider(text)
      return nil if text.nil? || text.empty?
      text_down = text.to_s.downcase
      VPNChecker::VPN_PROVIDERS.each do |pattern, name|
        return name if pattern.match?(text_down)
      end
      nil
    end

    # Check if text contains VPN-related keywords (for PTR evaluation)
    def vpn_related_keywords?(text)
      return false if text.nil? || text.empty?
      text_down = text.to_s.downcase
      VPNChecker::Config::VPN_BRAND_TOKENS.any? { |token| text_down.include?(token) } ||
        text_down.include?('vpn') ||
        text_down.include?('datacenter') ||
        text_down.include?('hosting') ||
        text_down.include?('nodes') ||
        text_down.include?('servers') ||
        text_down.include?('cloud')
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
        now = monotonic_now
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
          @open_until[host] = monotonic_now + @timeout
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

    private

    # Une horloge monotone ne recule pas lorsque l'heure système est corrigée.
    def monotonic_now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end

  class FlagTracer
    def self.save_current_state(state_hash)
      return unless VPNChecker::ENABLE_CACHE
    
      dir = Config::CACHE_DIR
      FileUtils.mkdir_p(dir, mode: 0700) rescue nil
    
      begin
        File.chmod(0700, dir) if (File.stat(dir).mode & 0777) != 0700
      rescue StandardError
        nil
      end

      previous_umask = File.umask(0o077)

       begin
         tmp = File.join(
           dir,
           "state.tmp.#{$$}.#{Thread.current.object_id}"
         )

         flags = File::WRONLY | File::CREAT | File::TRUNC
         flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)

         File.open(tmp, flags, 0600) do |file|
           file.write(JSON.dump(state_hash))
           file.flush
           file.fsync
         end

         File.rename(tmp, Config::STATE_FILE)
       rescue StandardError => e
         File.delete(tmp) rescue nil if tmp && File.exist?(tmp)
         Logger.error("Erreur d'écriture sécurisée du fichier d'état : #{e.message}")
       ensure
         File.umask(previous_umask) unless previous_umask.nil?
       end
    end

    def self.load_current_state
      path = Config::STATE_FILE
      return {} unless File.exist?(path) || File.symlink?(path)
      stat = File.lstat(path)
      return {} unless stat.file? && !stat.symlink?
      return {} unless (stat.mode & 0o077).zero?
      return {} if stat.size > 65_536

      parsed = JSON.parse(File.read(path))
      parsed.is_a?(Hash) ? parsed : {}
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
      route_out = Infrastructure::CommandExecutor.run('/sbin/route', '-n', 'get', 'default')[:stdout]
      iface_match = route_out.match(/interface:\s*([a-zA-Z0-9]+)/)
      active_iface = iface_match ? iface_match[1] : 'Inconnu'

      ifconfig_out = Infrastructure::CommandExecutor.run('/sbin/ifconfig')[:stdout]
      utun_active = ifconfig_out.scan(/utun\d+/).uniq.join(',')
      utun_status = utun_active.empty? ? "Aucune" : utun_active

      "[Route par défaut: #{active_iface} | Interfaces VPN actives: #{utun_status}]"
    rescue StandardError => e
      "[Erreur capture preuve: #{e.message}]"
    end
  end

  module Infrastructure
    class CommandExecutor
      # PATH déterministe : outils système par chemin absolu ; PATH enfant =
      # répertoires système en tête, puis reste (outils tiers vpnb, tor...).
      SYSTEM_PATH = '/usr/bin:/bin:/usr/sbin:/sbin'.freeze
      SYSTEM_TOOLS = {
        'scutil' => '/usr/sbin/scutil',
        'ifconfig' => '/sbin/ifconfig',
        'route' => '/sbin/route',
        'dig' => '/usr/bin/dig',
        'netstat' => '/usr/sbin/netstat',
        'lsof' => '/usr/sbin/lsof',
        'ps' => '/bin/ps',
        'pfctl' => '/sbin/pfctl',
        'sw_vers' => '/usr/bin/sw_vers',
        'systemextensionsctl' => '/usr/bin/systemextensionsctl'
      }.freeze

      # Remplace le nom nu d'un outil système par son chemin absolu, s'il existe.
      def self.resolve_command(cmd_args, exists: nil)
        exists ||= ->(path) { File.executable?(path) }
        args = Array(cmd_args).dup
        tool = args.first
        if tool.is_a?(String) && SYSTEM_TOOLS.key?(tool) && exists.call(SYSTEM_TOOLS[tool])
          args[0] = SYSTEM_TOOLS[tool]
        end
        args
      end

      def self.child_env(base_path = ENV['PATH'])
        extra = base_path.to_s.split(File::PATH_SEPARATOR).reject(&:empty?)
        { 'PATH' => (SYSTEM_PATH.split(File::PATH_SEPARATOR) + extra).uniq.join(File::PATH_SEPARATOR) }
      end

      def self.run(*cmd_args, timeout: Config::TIMEOUT_SLOW)
        stdout_str = ''
        stderr_str = ''
        status = nil
        timed_out = false
        readers = []

        Open3.popen3(child_env, *resolve_command(cmd_args)) do |stdin, stdout, stderr, wait_thr|
          stdin.close
          readers = [stdout, stderr].map do |io|
            thread = Thread.new do
              begin
                # Lecture jusqu'à EOF ; rescue limité aux erreurs de flux du nettoyage,
                io.read
              rescue IOError, Errno::EBADF
                ''
              rescue StandardError => e
                # Log unexpected thread errors for debugging (they would be silent with report_on_exception=false)
                VPNChecker::Logger.error("CommandExecutor reader thread error: #{e.class} - #{e.message}")
                ''
              end
            end
            # Keep default report_on_exception=true so unhandled errors surface in logs
            thread
          end

          # Attendre le processus, pas les lecteurs (les pipes sont drainés
          # en continu, évitant le blocage stderr/stdout plein).
          unless wait_thr.join([timeout.to_f, 0.01].max)
            timed_out = true
            terminate_process(wait_thr)
          end

          status = wait_thr.value unless wait_thr.alive?

          # Un descendant peut hériter un descripteur : joins bornés, cleanup borné.
          readers.each { |thread| thread.join(1.5) }
          if readers.any?(&:alive?)
            close_streams(stdout, stderr)
            readers.each { |thread| thread.join(0.5) }
          end
          readers.each do |thread|
            next unless thread.alive?
            thread.kill
            thread.join(0.1)
          end

          stdout_str = readers[0].value.to_s rescue ''
          stderr_str = readers[1].value.to_s rescue ''
        ensure
          close_streams(stdin, stdout, stderr)
        end

        if timed_out
          Logger.log_timeout('CommandExecutor', "Commande: #{cmd_args.join(' ')} (#{timeout}s)")
          return { stdout: stdout_str, stderr: stderr_str.empty? ? 'Timeout' : "Timeout: #{stderr_str}", success: false }
        end

        {
          stdout: stdout_str,
          stderr: stderr_str,
          success: status ? status.success? : false
        }
      rescue StandardError => e
        Logger.error("Erreur d'exécution système : #{e.message}")
        { stdout: stdout_str.to_s, stderr: e.message, success: false }
      end

      def self.terminate_process(wait_thr)
        return unless wait_thr.alive?

        Process.kill('TERM', wait_thr.pid) rescue nil
        return if wait_thr.join(0.25)

        Process.kill('KILL', wait_thr.pid) rescue nil if wait_thr.alive?
        wait_thr.join(0.5)
      rescue Errno::ESRCH
        wait_thr.join(0.1)
      end
      private_class_method :terminate_process

      def self.close_streams(*streams)
        streams.compact.each do |stream|
          begin
            stream.close unless stream.closed?
          rescue IOError, Errno::EBADF
            # Déjà fermé pendant la fin normale ou le nettoyage.
          end
        end
      end
      private_class_method :close_streams

      def self.safe_run(*cmd_args, timeout: Config::TIMEOUT_SLOW)
        run(*cmd_args, timeout: timeout)
      end
    end

    class FirewallChecker
      PF_CONF_PATH = '/etc/pf.conf'

      # API historique conservée : true / false / :unauthorized.
      def self.rules_ok?
        check_result[:firewall_status]
      end

      # Contrat additif : :firewall_status reprend la valeur historique de rules_ok?.
      def self.check_result
        info = CommandExecutor.safe_run('pfctl', '-s', 'info', timeout: Config::TIMEOUT_FAST)
        evaluate(
          info,
          -> { CommandExecutor.safe_run('pfctl', '-sr', timeout: Config::TIMEOUT_FAST) },
          -> { CommandExecutor.safe_run('ifconfig', '-l', timeout: Config::TIMEOUT_FAST)[:stdout].to_s }
        )
      rescue Errno::EACCES
        pf_result(:unauthorized, state: :unknown, confidence: 0, detected: nil, severity: :unknown,
                  reason: 'Accès refusé à pfctl : état du pare-feu PF non vérifiable.',
                  evidence: ['Errno::EACCES'])
      rescue StandardError => e
        Logger.error("Vérification PF : #{e.message}")
        pf_result(false, state: :error, confidence: 0, detected: nil, severity: :unknown,
                  reason: 'Erreur interne vérification PF ; statut « non sécurisé » conservé.',
                  evidence: ["error: #{e.class.name}"], error: e.class.name, unknown: true)
      end

      # Logique pure : providers appelés paresseusement, même ordre qu'avant.
      def self.evaluate(info, rules_provider, ifaces_provider)
        unless info[:success]
          return pf_result(:unauthorized, state: :unknown, confidence: 0, detected: nil, severity: :unknown,
                           reason: 'pfctl -s info a échoué (droits/commande indisponible) : état PF non vérifiable.',
                           evidence: ['pfctl -s info: échec'], unknown: true)
        end

        unless info[:stdout].to_s.match?(/Status:\s+Enabled/i)
          return pf_result(false, state: :warning, confidence: 80, detected: false, severity: :unknown,
                           reason: 'PF désactivé (pfctl -s info) : aucun blocage hors tunnel appliqué.',
                           evidence: ['pf: statut différent de Enabled'])
        end

        rules = rules_provider.call
        unless rules[:success]
          return pf_result(:unauthorized, state: :unknown, confidence: 0, detected: nil, severity: :unknown,
                           reason: 'pfctl -sr a échoué (droits/commande indisponible) : règles PF non vérifiables.',
                           evidence: ['pfctl -sr: échec'], unknown: true)
        end

        vpn_ifaces = ifaces_provider.call.to_s.split.grep(/\A(?:utun|tun|tap|wg|ppp)\d*\z/i)
        if vpn_ifaces.empty?
          return pf_result(false, state: :not_applicable, confidence: 80, detected: nil, severity: :none,
                           reason: 'Aucune interface tunnel : blocage hors tunnel non évaluable.',
                           evidence: ['interfaces_tunnel: aucune'])
        end

        active_rules = rules[:stdout].to_s
        protected_by = vpn_ifaces.find do |iface|
          active_rules.lines.any? do |line|
            line.match?(/\bblock\b.*\bout\b.*!\s*#{Regexp.escape(iface)}\b/i)
          end
        end

        if protected_by
          # Indice seulement : anchors non inspectés, coupure non testée.
          # :firewall_status conserve true (historique), état normalisé :unknown.
          pf_result(true, state: :unknown, confidence: 35, detected: true, severity: :unknown,
                    reason: "Règle PF de blocage hors de #{protected_by} détectée, mais protection non validée (anchors et coupure VPN non testés).",
                    evidence: ["pf: règle block out hors #{protected_by}", 'protection_effective: non_verifiee'],
                    unknown: true)
        else
          pf_result(false, state: :warning, confidence: 70, detected: false, severity: :unknown,
                    reason: 'PF actif sans blocage hors tunnel dans le jeu principal (anchors non inspectés).',
                    evidence: ['pf: statut Enabled', "interfaces_tunnel: #{vpn_ifaces.join(',')}"])
        end
      end

      def self.pf_result(firewall_status, state:, confidence:, reason:, evidence: [], detected: nil, severity: nil, **extra)
        VPNChecker::Detectors::BaseDetector.normalize_result(
          {
            firewall_status: firewall_status, state: state, confidence: confidence,
            evidence: evidence, reason: reason, detected: detected, severity: severity
          }.merge(extra)
        )
      end
    end

    module NetTools
      module_function

      # TCP/443 : indicateur IP plus représentatif que TCP/53, sans preuve absolue.
      TEST_HOSTS = VPNChecker::Config::PING_HOSTS.map { |h| [h, 443] }.freeze

      def internet?(hosts: TEST_HOSTS, connector: nil)
        connect = connector || lambda do |host, port|
          Socket.tcp(host, port, connect_timeout: Config::TIMEOUT_TCP) { true }
        end
        Array(hosts).any? do |host, port|
          begin
            !!connect.call(host, port)
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
          return nil if File.symlink?(path)
          return nil unless File.file?(path)

          stat = File.stat(path)
          return nil unless stat.file?
          # Les caches sont privés à l'utilisateur : aucune permission groupe/autres.
          return nil unless (stat.mode & 0o077).zero?

          raw = File.read(path)
          payload = JSON.parse(raw)
          return nil unless payload.is_a?(Hash)

          timestamp = Integer(payload['timestamp']) rescue nil
          return nil unless timestamp && timestamp.positive?

          age = Time.now.to_i - timestamp
          return nil if age.negative? || age > ttl

          payload['data']
        rescue StandardError => e
          Logger.warn("Cache disque invalide #{path}: #{e.message}")
          nil
        end

        def write_json(path, data)
          return data unless VPNChecker::ENABLE_CACHE

          tmp = nil
          dir = File.dirname(path)

          FileUtils.mkdir_p(dir, mode: 0700)

          payload = JSON.generate(
            'timestamp' => Time.now.to_i,
            'data' => data
          )

          # Fichier temporaire exclusif : pas d'écrasement, refus des symlinks.
          flags = File::WRONLY | File::CREAT | File::EXCL
          flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)

          5.times do
            candidate = "#{path}.tmp.#{$$}.#{Thread.current.object_id}.#{rand(1_000_000)}"

            begin
              File.open(candidate, flags, 0600) do |file|
                tmp = candidate
                file.write(payload)
                file.flush
                file.fsync
              end
              break
            rescue Errno::EEXIST
              next
            end
          end

          raise IOError, 'Impossible de créer le fichier temporaire du cache' unless tmp

          File.rename(tmp, path)
          tmp = nil
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

    class NetstatSnapshot
      IGNORE_PORTS = [22, 53, 80, 443, 631].freeze
      DOQ_PORTS = [784, 853, 8853].freeze
      # DoH often runs on 443 (ignored), 8443, 5053, 8053, 1053, 4433
      DOH_PORTS = [8443, 5053, 8053, 1053, 4433].freeze

      attr_reader :open_ports

      def initialize(raw_output)
        @raw_output = raw_output.to_s
        ports_list = parse_open_ports

        @has_dot = ports_list.any? { |p| p[:port] == 853 }
        @has_doq = ports_list.any? { |p| DOQ_PORTS.include?(p[:port]) }
        @has_doh = ports_list.any? { |p| DOH_PORTS.include?(p[:port]) }
        @has_stun = ports_list.any? { |p| [3478, 3479, 19302].include?(p[:port]) }

        @open_ports = ports_list.freeze
      end

      def dot?; @has_dot; end
      def doq?; @has_doq; end
      def doh?; @has_doh; end
      def stun_service_detected?; @has_stun; end

      # false si netstat n'a rien renvoyé (échec / délai) : liste vide ≠ aucun port.
      def available?
        !@raw_output.strip.empty?
      end

      private

      def parse_open_ports
        ports = {}
        @raw_output.lines.each do |line|
          next unless line.include?('LISTEN')
          parts = line.split
          addr = parts[3] || ''
          port = addr.split('.').last.to_i
          port = addr.split(':').last.to_i if port == 0
          next unless port > 0 && !IGNORE_PORTS.include?(port)

          bind = bind_scope(addr)
          entry = ports[port]
          if entry.nil?
            ports[port] = { command: 'LISTEN', port: port, bind: bind, address: addr }
          elsif bind == :all && entry[:bind] != :all
            # Un même port écouté en loopback ET sur toutes les interfaces est exposé.
            ports[port] = entry.merge(bind: :all, address: addr)
          end
        end
        ports.values
      rescue StandardError => e
        Logger.warn("NetstatSnapshot parsing failed: #{e.message}")
        []
      end

      # :all (toutes interfaces), :loopback (local uniquement), :interface (adresse précise).
      def bind_scope(addr)
        host = addr.to_s.sub(/[.:]\d+\z/, '')
        if host == '*' || host == '0.0.0.0' || host == '::'
          :all
        elsif host.start_with?('127.') || host == '::1' || host == 'localhost'
          :loopback
        else
          :interface
        end
      end
    end

    # Attribution des processus : :process ajouté seulement si colonne `pid`
    # (ou `process:pid`) reconnue dans l'en-tête `netstat -anv`.
    class PortProcessResolver
      # { recognized: Boolean, listeners: { port => { pid:, name: } } }
      # Format non reconnu ≠ aucune écoute : table vide ne prouve rien.
      def self.parse_listeners_with_status(text)
        pid_column = nil
        process_column = nil
        recognized = false
        mapping = {}

        text.to_s.each_line do |line|
          tokens = line.split
          next if tokens.empty?

          if tokens.first == 'Proto'
            header = line.gsub('Local Address', 'Local_Address').gsub('Foreign Address', 'Foreign_Address').split
            pid_column = header.index('pid')
            process_column = pid_column ? nil : header.index { |token| token.start_with?('process') }
            recognized = true if pid_column || process_column
            next
          end

          next unless line.include?('LISTEN') && (pid_column || process_column)

          addr = tokens[3].to_s
          port = addr.split('.').last.to_i
          port = addr.split(':').last.to_i if port.zero?
          next unless port > 0

          pid = nil
          name = nil
          if pid_column
            raw = tokens[pid_column].to_s
            pid = raw.to_i if raw.match?(/\A\d+\z/)
          else
            match = tokens[process_column].to_s.match(/\A(.+):(\d+)\z/)
            if match
              name = match[1]
              pid = match[2].to_i
            end
          end
          next if pid.nil?

          mapping[port] ||= { pid: pid, name: name }
        end
        { recognized: recognized, listeners: mapping }
      end

      # => { port => { pid: Integer, name: String|nil } }
      def self.parse_listeners(text)
        parse_listeners_with_status(text)[:listeners]
      end

      # => { pid => nom court } d'après `ps -p ... -o pid=,comm=`
      def self.parse_ps(text)
        names = {}
        text.to_s.each_line do |line|
          match = line.match(/\A\s*(\d+)\s+(.+?)\s*\z/)
          names[match[1].to_i] = File.basename(match[2]) if match
        end
        names
      end

      # { port => 'nom' | :unidentified | :no_listener } ; :no_listener = table lue
      # et reconnue, aucune écoute TCP (UDP non couvert). Hash vide sinon : aucune
      # affirmation.
      def self.listener_status(ports, netstat_runner: nil, ps_runner: nil)
        wanted = Array(ports).uniq
        return {} if wanted.empty?

        netstat_runner ||= lambda do
          CommandExecutor.run('/usr/sbin/netstat', '-anv', '-p', 'tcp', timeout: Config::TIMEOUT_SLOW)
        end
        ps_runner ||= lambda do |pids|
          CommandExecutor.run('/bin/ps', '-p', pids.join(','), '-o', 'pid=,comm=', timeout: Config::TIMEOUT_FAST)
        end

        netstat = netstat_runner.call
        return {} unless netstat[:success]

        table = parse_listeners_with_status(netstat[:stdout])
        return {} unless table[:recognized]

        listeners = table[:listeners]
        pids = wanted.map { |port| listeners.dig(port, :pid) }.compact.uniq
        names = {}
        unless pids.empty?
          ps = ps_runner.call(pids)
          names = parse_ps(ps[:stdout]) if ps[:success]
        end

        wanted.each_with_object({}) do |port, status|
          info = listeners[port]
          status[port] = if info.nil?
                           :no_listener
                         else
                           info[:name] || names[info[:pid]] || :unidentified
                         end
        end
      rescue StandardError => e
        Logger.warn("PortProcessResolver#listener_status: #{e.class}")
        {}
      end

      # Format `lsof -nP -iTCP -sTCP:LISTEN` ; retour { port => [owners...] }.
      # lsof échappe les octets non imprimables (\\x20 = espace).
      def self.decode_lsof_name(value)
        value.to_s.gsub(/(?:\\x\h\h)+/) do |match|
          match.scan(/\h\h/).map(&:hex).pack('C*').force_encoding(Encoding::UTF_8).scrub('?')
        end
      rescue StandardError
        value.to_s
      end

      def self.parse_lsof_listeners(text)
        result = Hash.new { |hash, key| hash[key] = [] }
        text.to_s.each_line do |line|
          next if line.start_with?('COMMAND')
          tokens = line.strip.split
          next if tokens.size < 9
          command = decode_lsof_name(tokens[0])
          pid = tokens[1].to_i
          type = tokens[4]
          name = tokens[-1] == '(LISTEN)' ? tokens[-2] : tokens[-1]
          next unless pid.positive? && type.to_s.start_with?('IPv')
          next unless line.include?('(LISTEN)')
          match = name.match(/\A(.+):(\d+)\z/)
          next unless match
          address = match[1]
          port = match[2].to_i
          host = address.sub(/^\[(.*)\]$/, '\1')
          bind_detail = if host == '*' && type == 'IPv4' || host == '0.0.0.0'
                          :wildcard_ipv4
                        elsif host == '*' && type == 'IPv6' || host == '::'
                          :wildcard_ipv6
                        elsif host == '127.0.0.1'
                          :loopback_ipv4
                        elsif host == '::1'
                          :loopback_ipv6
                        else
                          :interface
                        end
          bind = %i[wildcard_ipv4 wildcard_ipv6].include?(bind_detail) ? :all :
                 (%i[loopback_ipv4 loopback_ipv6].include?(bind_detail) ? :loopback : :interface)
          result[port] << { pid: pid, process: command, family: type, address: address,
                            bind: bind, bind_detail: bind_detail, endpoint: name }
        end
        result.each_value { |owners| owners.uniq! { |owner| [owner[:pid], owner[:family], owner[:endpoint]] } }
        result
      rescue StandardError => e
        Logger.warn("PortProcessResolver#parse_lsof_listeners: #{e.class}")
        {}
      end

      # Analyse `lsof -nP -i` (TCP/UDP) ; propriété = PID affiché, pas le client amont.
      def self.parse_lsof_network_sockets(text)
        sockets = []
        text.to_s.each_line do |line|
          tokens = line.strip.split
          next if tokens.empty? || tokens.first == 'COMMAND' || tokens.size < 9
          pid = tokens[1].to_s.to_i
          family = tokens[4]
          next unless pid.positive? && %w[IPv4 IPv6].include?(family)
          # Format lsof : ... IPv4 DEVICE SIZE/OFF NODE TCP|UDP NAME [STATE]
          proto_index = tokens.index { |token| %w[TCP UDP].include?(token) }
          next unless proto_index && tokens[proto_index + 1]
          protocol = tokens[proto_index]
          endpoint = tokens[proto_index + 1]
          state = tokens[proto_index + 2].to_s[/\(([^)]+)\)/, 1]
          local, remote = endpoint.split('->', 2).map(&:strip)
          local ||= endpoint
          parse_endpoint = lambda do |value|
            match = value.to_s.match(/\A(?:\[([^\]]+)\]|(.+)):(\d+|\*)\z/)
            match && { host: (match[1] || match[2]), port: (match[3] == '*' ? nil : match[3].to_i) }
          end
          local_ep = parse_endpoint.call(local)
          next unless local_ep
          remote_ep = remote ? parse_endpoint.call(remote) : nil
          command = decode_lsof_name(tokens[0])
          owner = command.downcase.include?('littlesnitch') ||
                  command.downcase.include?('networkextension') ?
                    :network_extension : :process
          dns_class = if local_ep[:port] == 53 || remote_ep&.dig(:port) == 53
                        :dns_classic_socket
                      elsif local_ep[:port] == 443 || remote_ep&.dig(:port) == 443
                        :port_443_protocol_unknown
                      else
                        :other
                      end
          sockets << {
            pid: pid, process: command, family: family, protocol: protocol,
            local: local, local_host: local_ep[:host], local_port: local_ep[:port],
            remote: remote, remote_host: remote_ep && remote_ep[:host],
            remote_port: remote_ep && remote_ep[:port], state: state,
            bind: (local_ep[:host] == '*' || local_ep[:host] == '0.0.0.0' || local_ep[:host] == '::' ? :all : ((local_ep[:host].start_with?('127.') || local_ep[:host] == '::1') ? :loopback : :interface)),
            owner_class: owner, dns_class: dns_class
          }
        end
        sockets
      rescue StandardError => e
        Logger.warn("PortProcessResolver#parse_lsof_network_sockets: #{e.class}")
        []
      end

      # Échec/lecture partielle lsof ≠ absence de sockets (fréquent sans root).
      def self.lsof_collection_status(result, parsed_count: nil)
        return :unavailable unless result.is_a?(Hash) && result[:success]
        stdout = result[:stdout].to_s
        stderr = result[:stderr].to_s
        return :permission_limited if stderr.match?(/operation not permitted|permission denied|not permitted/i)
        lines = stdout.lines.map(&:strip).reject(&:empty?)
        return :empty if lines.empty? || (lines.size == 1 && lines.first.start_with?('COMMAND'))
        return :incomplete if parsed_count == 0 || !lines.first.start_with?('COMMAND')
        :observed
      rescue StandardError
        :unavailable
      end

      # Parse une sortie `dig` sans lancer de commande. AD = marqueur DNSSEC
      # (indépendant du chiffrement amont).
      def self.parse_dig_result(text)
        source = text.to_s
        status = source[/\bstatus:\s*([A-Z]+)/i, 1]
        flags = source[/\bflags:\s*([^;]+)/i, 1].to_s.split
        query_time = source[/;;\s*Query time:\s*(\d+)\s*msec/i, 1]
        server = source[/;;\s*SERVER:\s*([^\s]+)/i, 1]
        timeout = source.match?(/connection timed out|no servers could be reached|communications error/i)
        rrsig_present = source.match?(/\bRRSIG\b/i)
        answer_count = source[/\bANSWER:\s*(\d+)/i, 1]
        {
          responded: !status.nil?, status: status,
          noerror: status == 'NOERROR',
          timeout: timeout,
          outcome: status ? (status == 'NOERROR' ? :noerror : (status == 'REFUSED' ? :refused : (status == 'SERVFAIL' ? :servfail : :dns_error))) : (timeout ? :timeout : :no_response),
          dnssec_ad: flags.include?('ad'), rrsig_present: rrsig_present,
          answer_count: answer_count && answer_count.to_i,
          flags: flags,
          query_time_ms: query_time && query_time.to_i,
          server: server,
          encrypted_upstream: nil
        }
      rescue StandardError
        { responded: false, status: nil, noerror: false, timeout: false,
          outcome: :no_response, dnssec_ad: nil, rrsig_present: false,
          answer_count: nil, flags: [], query_time_ms: nil, server: nil, encrypted_upstream: nil }
      end

      def self.enrich(ports, netstat_runner: nil, ps_runner: nil, lsof_runner: nil)
        return ports if ports.nil? || ports.empty?

        # lsof = source de référence (conserve propriétaires/endpoints). Si un
        # runner netstat est injecté, ne pas lancer lsof pour garder le test isolé.
        use_lsof = !lsof_runner.nil? || netstat_runner.nil?
        if use_lsof
          lsof_runner ||= lambda do
            CommandExecutor.run('/usr/sbin/lsof', '-nP', '-iTCP', '-sTCP:LISTEN', timeout: Config::TIMEOUT_SLOW)
          end
          lsof = lsof_runner.call
        else
          lsof = { success: false, stdout: '', stderr: 'lsof ignoré : netstat_runner injecté' }
        end
        if lsof[:success]
          by_port = parse_lsof_listeners(lsof[:stdout])
          return ports.map do |entry|
            owners = Array(by_port[entry[:port]])
            next entry if owners.empty?
            binds = owners.map { |owner| owner[:bind] }
            # Wildcard l'emporte sur loopback ; tous les propriétaires restent visibles.
            bind = binds.include?(:all) ? :all : (binds.uniq.size == 1 ? binds.first : :interface)
            unique_processes = owners.map { |owner| owner[:process] }.uniq
            unique_pids = owners.map { |owner| owner[:pid] }.uniq
            entry.merge(
              bind: bind,
              owners: owners,
              process: unique_processes.size == 1 ? unique_processes.first : nil,
              pid: unique_pids.size == 1 ? unique_pids.first : nil,
              attribution: unique_processes.size > 1 ? :multiple_owners : :single_owner
            )
          end
        end

        # Repli netstat si lsof indisponible : un propriétaire par port, comme avant.
        netstat_runner ||= lambda do
          CommandExecutor.run('/usr/sbin/netstat', '-anv', '-p', 'tcp', timeout: Config::TIMEOUT_SLOW)
        end
        ps_runner ||= lambda do |pids|
          CommandExecutor.run('/bin/ps', '-p', pids.join(','), '-o', 'pid=,comm=', timeout: Config::TIMEOUT_FAST)
        end
        netstat = netstat_runner.call
        return ports unless netstat[:success]
        listeners = parse_listeners(netstat[:stdout])
        pids = ports.map { |entry| listeners.dig(entry[:port], :pid) }.compact.uniq
        names = {}
        unless pids.empty?
          ps = ps_runner.call(pids)
          names = parse_ps(ps[:stdout]) if ps[:success]
        end
        ports.map do |entry|
          info = listeners[entry[:port]]
          next entry unless info
          name = info[:name] || names[info[:pid]]
          name ? entry.merge(process: name, pid: info[:pid], attribution: :legacy_single_owner) : entry
        end
      rescue StandardError => e
        Logger.warn("PortProcessResolver: #{e.class}")
        ports
      end
    end

    # Adresses routées hors tunnel, déclarées par vpnb status. Route hôte
    # correspondante = exception intentionnelle (indiscernable d'une fuite sans
    # cette source). Échec CLI -> ensemble vide, verdict inchangé (UNKNOWN).
    class VPNBypassSource
      CLI_CANDIDATES = [
        '/usr/local/bin/vpnb',
        '/Applications/VPN Bypass.app/Contents/MacOS/vpnb',
        File.expand_path('~/Applications/VPN Bypass.app/Contents/MacOS/vpnb'),
        '/Applications/Utilities/ Applications X/Réseaux:Sécurité/VPN Bypass.app/Contents/MacOS/vpnb'
      ].freeze
      CACHE_TTL = 30

      class << self
        def cache
          @cache ||= AdaptiveLRUCache.new
        end

        def declared_addresses(runner: nil)
          cache.fetch('vpnb_declared', ttl: CACHE_TTL) do
            runner ||= lambda do
              cli = resolve_cli
              Logger.debug("VPNBypassSource: CLI #{cli ? cli.join(' ') : 'introuvable'}")
              cli ? CommandExecutor.safe_run(*cli, 'routes.active', timeout: Config::TIMEOUT_FAST) : { stdout: '', success: false }
            end
            result = runner.call
            addresses = result[:success] ? extract_active_route_addresses(force_utf8(result[:stdout])) : [].freeze
            Logger.debug("VPNBypassSource: #{result[:success] ? addresses.size : 'échec'} adresse(s) de routes actives")
            addresses
          end
        end

        # CLI présente + exceptions annoncées ≠ routage réel prouvé.
        def status(runner: nil)
          cache.fetch('vpnb_status', ttl: CACHE_TTL) do
            cli = resolve_cli
            unless cli
              next({ state: :not_detected, count: 0, addresses: [].freeze }.freeze)
            end

            # 1,5 s (TIMEOUT_SLOW) au lieu de 1,0 s + UNE relance avant UNKNOWN ;
            # raison conservée dans :status_error (nuance textuelle, pas emoji).
            runner ||= lambda do
              result = CommandExecutor.safe_run(*cli, 'status', '--json', timeout: Config::TIMEOUT_SLOW)
              if result[:success]
                result
              else
                Logger.warn("VPNBypassSource: 'status --json' sans réponse (#{result[:stderr].to_s.split("\n").first}) — une relance.")
                CommandExecutor.safe_run(*cli, 'status', '--json', timeout: Config::TIMEOUT_SLOW)
              end
            end
            result = runner.call
            unless result[:success]
              Logger.warn("VPNBypassSource: échec de la commande 'status --json' de la CLI (#{result[:stderr].to_s.split("\n").first}).")
              next({ state: :unknown, status_error: :command_failed,
                     count: 0, addresses: [].freeze }.freeze)
            end

            # v5.9.2 : sous xbar (sans LANG/LC_ALL => US-ASCII), la sortie
            # `status --json` (UTF-8) levait ArgumentError au match?.
            # Normalisation UTF-8 (scrub) AVANT tout parse/match/interpolation.
            output = force_utf8(result[:stdout])
            parsed_status = parse_status(output)
            if parsed_status[:state] == :unknown
              # Décision k : JSON invalide ou ok:false -> UNKNOWN + alerte,
              # aucun repli sur le format texte 5.5.2.
              Logger.warn("VPNBypassSource: sortie 'status --json' illisible (#{parsed_status[:parse_error]}) — état non vérifiable, pas de repli sur l'ancien format texte.")
            end

            # Lignes error/alert/warning de la CLI tracées via Logger, verdict inchangé.
            output.each_line do |line|
              Logger.warn("VPNBypassSource CLI Notice: #{line.strip}") if line.match?(/\b(error|alert|warning)\b/i)
            end

            active_result = CommandExecutor.safe_run(*cli, 'routes.active', timeout: Config::TIMEOUT_FAST)
            active_output = force_utf8(active_result[:stdout])
            active_addresses = active_result[:success] ? extract_active_route_addresses(active_output) : [].freeze
            parsed_status.merge(active_route_count: active_addresses.size).freeze
          rescue StandardError => e
            # ArgumentError sous xbar observé (log 19:07:36) : message + pile
            # tracés. Verdict inchangé : UNKNOWN.
            Logger.warn("VPNBypassSource status: #{e.class}: #{e.message} — #{e.backtrace.to_a.first}")
            { state: :unknown, status_error: :internal_error,
              error_class: e.class.name,
              count: 0, addresses: [].freeze }.freeze
          end
        end

        # Normalisation UTF-8 (retag + scrub des octets invalides). Sous xbar sans
        # LANG, Ruby étiquette en US-ASCII et match?/parse lève ArgumentError.
        # Méthode pure : l'encodage seul est corrigé, jamais le contenu.
        def force_utf8(text)
          str = text.to_s.dup
          str = str.force_encoding(Encoding::UTF_8) unless str.encoding == Encoding::UTF_8
          str.scrub.freeze
        end

        # Analyse pure de `vpnb status --json` (app 6.0.5, schemaVersion 2).
        # JSON invalide / ok:false / result absent -> :unknown, aucun repli
        # 5.5.2 (décision k). Clé `firewall:` lue si exposée ; absente en
        # 6.0.5 -> nil. schemaVersion > KNOWN_STATUS_SCHEMA -> format_unverified,
        # libellé 🟡 « format non vérifié ».
        KNOWN_STATUS_SCHEMA = 2

        def parse_status(output)
          parsed = begin
            JSON.parse(output.to_s)
          rescue JSON::ParserError, StandardError
            return { state: :unknown, parse_error: :invalid_json,
                     count: 0, addresses: [].freeze }.freeze
          end
          unless parsed.is_a?(Hash) && parsed['ok'] == true
            return { state: :unknown, parse_error: :envelope_not_ok,
                     count: 0, addresses: [].freeze }.freeze
          end
          result = parsed['result']
          unless result.is_a?(Hash)
            return { state: :unknown, parse_error: :missing_result,
                     count: 0, addresses: [].freeze }.freeze
          end

          schema_version = result['schemaVersion']
          unless schema_version.is_a?(Integer) && schema_version == KNOWN_STATUS_SCHEMA
            return { state: :unknown, parse_error: :unsupported_schema,
                     schema_version: schema_version,
                     format_unverified: true,
                     count: 0, addresses: [].freeze }.freeze
          end

          runtime = result['runtime']
          routes = result['routes']
          unless runtime.is_a?(Hash) && routes.is_a?(Array) &&
                 routes.all? { |route| route.is_a?(Hash) }
            return { state: :unknown, parse_error: :invalid_structure,
                     count: 0, addresses: [].freeze }.freeze
          end

          route_count = runtime['enforcedRouteCount']
          unless route_count.is_a?(Integer) && route_count >= 0
            return { state: :unknown, parse_error: :invalid_route_count,
                     count: 0, addresses: [].freeze }.freeze
          end

          default_id = result['defaultRouteId']
          active_route = routes.find { |route| route['id'].is_a?(String) && route['id'] == default_id }
          active_profile = active_route && active_route['name'].is_a?(String) ? active_route['name'] : nil
          tri = lambda do |key|
            value = runtime[key]
            value == true ? 'true' : (value == false ? 'false' : nil)
          end

          {
            state: :detected,
            count: route_count,
            addresses: [].freeze,
            mode: result['mode'].is_a?(String) ? result['mode'] : nil,
            enforcing: tri.call('enforcing'),
            route_count: route_count,
            engine_state: nil,
            active_profile: active_profile,
            firewall_state: runtime['firewall']&.to_s,
            vpn_interface: runtime['vpnInterface'].is_a?(String) ? runtime['vpnInterface'] : nil,
            vpn_type: runtime['vpnType'].is_a?(String) ? runtime['vpnType'] : nil,
            vpn_connected: tri.call('vpnConnected'),
            helper_ready: tri.call('helperReady'),
            helper_state: runtime['helperState'].is_a?(String) ? runtime['helperState'] : nil,
            app_version: runtime['appVersion'].is_a?(String) ? runtime['appVersion'] : nil,
            # Kill-switch détecté par l'app (includeAllNetworks/enforceRoutes) :
            # routes sans effet, enforcing=false forcé. Pause : routage suspendu.
            kill_switch: runtime['killSwitch'].is_a?(Array) && !runtime['killSwitch'].empty? ? runtime['killSwitch'].map(&:to_s).freeze : nil,
            paused: tri.call('paused'),
            schema_version: schema_version,
            format_unverified: false
          }.freeze
        end

        # Résolution CLI : chemins du bundle, puis symlink Homebrew dans le PATH.
        def resolve_cli
          candidates = CLI_CANDIDATES.dup
          ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
            candidates << File.join(dir, 'vpnb')
          end
          candidates.each do |path|
            next unless path.include?(File::SEPARATOR)
            return [path] if File.executable?(path)
          end
          nil
        end

        # Extraction agnostique : seules les adresses (IP ou CIDR) du texte.
        def extract_addresses(text)
          tokens = []
          text.to_s.scan(/(?:#{Config::IPV4_PATTERN}|#{Config::IPV6_PATTERN})(?:\/\d{1,3})?/) do
            tokens << Regexp.last_match(0)
          end
          tokens.uniq.map do |token|
            begin
              IPAddr.new(token)
            rescue IPAddr::InvalidAddressError, ArgumentError
              nil
            end
          end.compact.uniq(&:to_string).freeze
        end

        # `routes.active` : « destination -> gateway (source) » ; seule la
        # première adresse est la destination, la passerelle ne compte pas.
        def extract_active_route_addresses(text)
          text.to_s.each_line.each_with_object([]) do |line, addresses|
            destination = line.strip[/\A(?:#{Config::IPV4_PATTERN}|#{Config::IPV6_PATTERN})(?:\/\d{1,3})?/]
            begin
              addresses << IPAddr.new(destination) if destination
            rescue IPAddr::InvalidAddressError, ArgumentError
              next
            end
          end.uniq(&:to_string).freeze
        end

        def declared?(addresses, destination)
          return false if addresses.nil? || addresses.empty?
          begin
            addr = IPAddr.new(destination.to_s)
          rescue IPAddr::InvalidAddressError, ArgumentError
            return false
          end
          addresses.any? { |declared| declared.include?(addr) }
        end

        # État PF local : :enabled, :disabled ou nil. « Statut différent de
        # Enabled » = seul témoignage non ambigu de PF désactivé ; les autres
        # états sont postérieurs à ce contrôle (PF actif, blocage incertain).
        def pf_local_state(pf_result)
          return nil unless pf_result.is_a?(Hash) && !pf_result.empty?
          return nil if %i[unknown error].include?(pf_result[:state])

          evidence = Array(pf_result[:evidence]).map(&:to_s)
          return :disabled if evidence.any? { |item| item.include?('pf: statut différent de Enabled') }
          return :enabled if %i[ok not_applicable warning].include?(pf_result[:state])
          nil
        end

        # Recoupement pare-feu (v5.8.5) : vpnb (firewall:) vs PF local ; chaîne
        # d'affichage ou nil. AFFICHAGE SEUL, verdict/score inchangés (décision g).
        def pf_cross_check(vpnb_status, pf_result)
          announced = vpnb_status.to_h[:firewall_state].to_s.downcase.strip
          return nil if announced.empty?
          announced_on  = announced.match?(/\A(?:on|enabled|active|true|yes|1)\z/)
          announced_off = announced.match?(/\A(?:off|disabled|inactive|false|no|0)\z/)
          return nil unless announced_on || announced_off

          local = pf_local_state(pf_result)
          return nil if local.nil?

          if (announced_on && local == :enabled) || (announced_off && local == :disabled)
            announced_on ? 'ℹ️ Pare-feu : VPN Bypass et PF local annoncent tous deux un pare-feu actif (cohérent, verdict et score inchangés)'
                          : 'ℹ️ Pare-feu : VPN Bypass et PF local annoncent tous deux un pare-feu inactif (cohérent, verdict et score inchangés)'
          else
            "⚠️ Divergence pare-feu : VPN Bypass annonce #{announced_on ? 'actif' : 'inactif'}, PF local paraît #{local == :enabled ? 'actif' : 'inactif'} (à vérifier ; verdict et score inchangés)"
          end
        end
      end
    end

    class RouteSnapshot
      attr_reader :direct_host_routes

      def initialize(raw_output)
        @raw_output = raw_output.to_s
    
        @vpn_route_override = @raw_output.lines.any? do |line|
          route = line.to_s.strip
          next false if route.empty? || route.include?('fe80::')
          route.match?(/^(?:0\/1|128\/1|default)\s+/) && route.match?(/\b(?:utun|tun|ppp|wg|tap)\d*\b/i)
        end

        @unprotected_default_route = @raw_output.lines.any? do |line|
          route = line.to_s.strip
          route.start_with?('default ') && route.match?(/\ben\d+\b/) && !route.match?(/\b(?:blackhole|reject)\b/i)
        end

        all_host_routes = @raw_output.lines.each_with_object([]) do |line, routes|
          route = line.to_s.strip
          next unless route.match?(/\bUGHS\d*\b/)
          next if route.match?(/\b(?:utun|tun|tap|ppp|wg|lo0)\d*\b/i)
          destination = route.split.first
          next if destination.nil? || destination == 'default'
          routes << destination
        end.uniq

        # Tolérance de 1 route hôte (ex: passerelle VPN directe)
        @direct_host_routes = (all_host_routes.size <= 1) ? [] : all_host_routes.freeze
      end

      # RouteSnapshot = source unique des infos de routage de SystemSnapshot.
      def vpn_route_override?; @vpn_route_override; end
      def unprotected_default_route?; @unprotected_default_route; end

      def routes
        @raw_output.lines.map(&:strip).reject(&:empty?)
      end

      def relevant_entries
        routes.select do |line|
          line.match?(/\b(?:default|0\/1|128\/1)\b/i) ||
            line.match?(/\b(?:utun|tun|tap|ppp|wg)\d*\b/i) ||
            line.match?(/\bUGHS\d*\b/i) ||
            line.match?(/\b(?:blackhole|reject)\b/i)
        end
      end

      def vpn_tunnel_active?
        vpn_route_override? || routes.any? { |line| line.match?(/\b(?:utun|tun|tap|ppp|wg)\d*\b/i) }
      end

      def find_physical_default_gateway
        line = routes.find do |entry|
          entry.match?(/^default\s+/i) &&
            entry.match?(/\ben\d+\b/i) &&
            !entry.match?(/\b(?:blackhole|reject)\b/i)
        end
        line && line.split[1]
      end

      # Blackhole quelconque ≠ route par défaut bloquée ; exiger un préfixe par
      # défaut + blackhole/reject. Signal de configuration, pas un test de fuite.
      def has_default_block_route?
        routes.any? do |line|
          default_destination = line.match?(/(?:^|\s)(?:default|0\.0\.0\.0\/0|\:\:\/0)(?:\s|$)/i)
          blocking_route = line.match?(/\b(?:blackhole|reject)\b/i)
          default_destination && blocking_route
        end
      end

      # Compatibilité : sémantique stricte, routes bloquantes couvrant défaut.
      def has_blackhole_route?
        has_default_block_route?
      end
    end

    class SystemSnapshot
      CACHE_TTL = 5
      PROCESS_CACHE_TTL = 10

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
        # `scutil --dns` relu à chaque exécution : un cache (180 s) ne voyait
        # pas un changement de configuration DNS.
        scutil_dns = CommandExecutor.run('scutil', '--dns')[:stdout].to_s

        all_interfaces = ifconfig
          .to_s
          .scan(/^([a-zA-Z0-9\-]+):/i)
          .flatten
          .uniq

        vpn_interfaces = detect_vpn_interfaces_from(all_interfaces, route_snap)
        netstat_an     = CommandExecutor.safe_run('netstat', '-anp', 'tcp', timeout: 0.5)[:stdout]
        processes      = parse_processes

        {
          ifconfig: ifconfig,
          scutil_dns: scutil_dns,
          netstat_rn: netstat,
          route_default: route,
          route_snap: route_snap,
          ps_procs: processes,
          ps_available: !processes.empty?,
          default_interface: parse_default_interface(route),
          default_gateway: parse_default_gateway(route),
          vpn_interfaces: vpn_interfaces,
          all_interfaces: all_interfaces,
          netstat_output: netstat_an,
          netstat_snap: NetstatSnapshot.new(netstat_an)
        }
      end

      def detect_vpn_interfaces_from(interfaces, route_snap)
        vpn_prefixes = Config::VPN_INTERFACE_PREFIXES

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
        @snapshot_data[:ifconfig].to_s.scan(/inet6\s+([0-9a-f:]+)/i).flatten.any? do |ip|
          begin
            addr = IPAddr.new(ip)
            next false unless addr.ipv6?
            next false if addr.loopback? || addr.link_local? || addr.private?
            (addr.to_i & 0xfe00_0000_0000_0000_0000_0000_0000_0000) !=
              0xfc00_0000_0000_0000_0000_0000_0000_0000
          rescue IPAddr::InvalidAddressError, ArgumentError
            false
          end
        end
      end

      def vpn_ipv6_interface?
        refresh!
        data = @snapshot_data
        data[:vpn_interfaces].any? { |iface| interface_has_global_ipv6?(data[:ifconfig], iface) }
      end

      def interface_has_global_ipv6?(ifconfig_output, interface)
        block = ifconfig_output.to_s.split(/^(?=[a-zA-Z0-9._-]+:)/).find { |chunk| chunk.start_with?("#{interface}:") }
        return false unless block
        block.scan(/inet6\s+([0-9a-fA-F:]+)/i).flatten.any? do |ip|
          addr = IPAddr.new(ip)
          # Exclure link-local, loopback, et ULA (fc00::/7)
          is_ula = (addr.to_i & 0xfe00_0000_0000_0000_0000_0000_0000_0000 == 0xfc00_0000_0000_0000_0000_0000_0000_0000)
          addr.ipv6? && !addr.link_local? && !addr.loopback? && !addr.private? && !is_ula
        rescue IPAddr::InvalidAddressError, ArgumentError
          false
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

      # method_missing conservé pour compat ; nouveaux détecteurs : API explicite.
      def routing_table
        refresh!
        @snapshot_data[:route_snap]
      end

      def routes
        refresh!
        @snapshot_data[:route_snap].routes
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

      # Deux essais : un échec isolé de `ps` ≠ « aucun processus ».
      def parse_processes
        2.times do
          res = CommandExecutor.safe_run('ps', '-A', '-o', 'comm=')[:stdout].to_s
          names = res.lines.map do |l|
            clean = l.strip
            !clean.empty? ? File.basename(clean).downcase : nil
          end.compact
          return names unless names.empty?
        end
        Logger.warn('ps -A : liste des processus indisponible après 2 essais')
        []
      end
    end
    
    # v6.1.9 : parsing hôte/port et garde loopback pour les sondes DNS.
    module NetEndpoint
      DIG_TAIL = ['+time=2', '+tries=1', '+noall', '+comments', '+answer', '+stats'].freeze

      module_function

      def valid_port?(value)
        value.to_s.match?(/\A\d{1,5}\z/) && value.to_i.between?(1, 65_535)
      end

      # => [hôte, port] ; hôte sans crochets ni zone (%en0) ; port Integer ou nil.
      # [nil, nil] si l'entrée est illisible. Un IPv6 nu (plusieurs « : »)
      # n'a jamais de port implicite.
      def split_host_port(value)
        text = value.to_s.strip
        return [nil, nil] if text.empty?

        if text.start_with?('[')
          match = text.match(/\A\[([^\]\s]+)\](?::(\d+))?\z/)
          return [nil, nil] unless match
          return [nil, nil] if match[2] && !valid_port?(match[2])

          return [match[1].split('%').first, match[2] && match[2].to_i]
        end

        case text.count(':')
        when 0
          [text, nil]
        when 1
          host, port = text.split(':', 2)
          return [nil, nil] if host.to_s.empty? || !valid_port?(port)

          [host, port.to_i]
        else
          [text.split('%').first, nil]
        end
      end

      def loopback_host?(host)
        text = host.to_s.strip.downcase
        return true if text == 'localhost'

        IPAddr.new(text).loopback?
      rescue StandardError
        false
      end

      def same_family?(first, second)
        IPAddr.new(first.to_s).ipv4? == IPAddr.new(second.to_s).ipv4?
      rescue StandardError
        false
      end

      # -b (adresse source) : jamais vers une cible loopback, adresse valide,
      # même famille que la cible.
      def bind_allowed?(target_host, bind_ip)
        bind = bind_ip.to_s.strip
        return false if bind.empty? || loopback_host?(target_host)

        IPAddr.new(bind)
        same_family?(target_host, bind)
      rescue StandardError
        false
      end

      def dig_command(host, port, name, bind_ip: nil)
        command = ['dig', "@#{host}", '-p', port.to_s]
        command += ['-b', bind_ip.to_s.strip] if bind_allowed?(host, bind_ip)
        command + [name, 'A'] + DIG_TAIL
      end
    end

    # v6.1.9 : secours if_index -> nom d'interface via `ifconfig -v`.
    module InterfaceIndex
      module_function

      # { 6 => 'en1', 16 => 'utun10' } : « en1: flags=… » + « index 6 » sur
      # la même ligne ou une suivante du bloc.
      def parse(text)
        map = {}
        current = nil
        text.to_s.each_line do |line|
          header = line.match(/\A([A-Za-z][A-Za-z0-9._-]*):\s+flags=/)
          current = header[1] if header
          next unless current

          match = line.match(/\bindex:?\s+(\d+)\b/)
          next unless match

          map[match[1].to_i] ||= current
          current = nil
        end
        map
      rescue StandardError
        {}
      end
    end

    # Contexte `scutil --nwi` : strictement indicatif, sans chemin des paquets,
    # ne modifie aucun verdict.
    module NetworkInfo
      module_function

      def parse_nwi(text)
        result = { ipv4: [], ipv6: [], ipv4_none: false, ipv6_none: false,
                   ipv4_reach: nil, ipv6_reach: nil, interfaces: [], recognized: false }
        section = nil
        current = nil
        text.to_s.each_line do |raw|
          stripped = raw.strip
          if stripped.match?(/\AIPv4 network interface information/i)
            section = :ipv4
            current = nil
            result[:recognized] = true
          elsif stripped.match?(/\AIPv6 network interface information/i)
            section = :ipv6
            current = nil
            result[:recognized] = true
          elsif (match = stripped.match(/\ANetwork interfaces:\s*(.*)\z/i))
            result[:interfaces] = match[1].split
            section = nil
            current = nil
          elsif section && stripped.match?(/\ANo IPv[46] states found/i)
            result[section == :ipv4 ? :ipv4_none : :ipv6_none] = true
          elsif section && (match = stripped.match(/\AREACH\s*:\s*flags\s+0x\h+\s*\(([^)]*)\)/))
            result[section == :ipv4 ? :ipv4_reach : :ipv6_reach] = match[1]
          elsif section && (match = stripped.match(/\A(\S+)\s*:\s*flags\s*:\s*0x\h+\s*\(([^)]*)\)/))
            current = { name: match[1], flags: match[2].split(',').map(&:strip), reach: nil }
            result[section] << current
          elsif section && current && (match = stripped.match(/\Areach\s*:\s*0x\h+\s*\(([^)]*)\)/))
            current[:reach] = match[1].split(',').map(&:strip)
          end
        end
        result
      rescue StandardError
        { ipv4: [], ipv6: [], ipv4_none: false, ipv6_none: false, ipv4_reach: nil,
          ipv6_reach: nil, interfaces: [], recognized: false }
      end
    end

    class AdvancedDNSResolver
      # if_index_runner : lambda -> texte `ifconfig -v` (injectable en test ;
      # appelé seulement si scutil ne nomme pas une interface).
      def initialize(snapshot, if_index_runner: nil)
        @snapshot = snapshot
        @if_index_runner = if_index_runner
      end

      # Un résultat par endpoint (rôle) ; processus du port local au mieux
      # (netstat -anv + ps) ; port absent du résultat = aucune affirmation.
      def prove_dns_paths(dns_servers, process_lookup: nil)
        process_lookup ||= lambda do |ports|
          # lsof relie endpoint loopback -> PID et inventorie les sockets
          # distants ; n'attribue pas une transaction DNS particulière.
          lsof = CommandExecutor.run('/usr/sbin/lsof', '-nP', '-i', timeout: Config::TIMEOUT_SLOW)
          if lsof[:success]
            sockets = PortProcessResolver.parse_lsof_network_sockets(lsof[:stdout])
            wanted = Array(ports).map(&:to_i)
            listeners = sockets.select do |socket|
              wanted.include?(socket[:local_port]) &&
                (socket[:local_host].to_s.start_with?('127.') || socket[:local_host] == '::1')
            end
            listeners.group_by { |socket| socket[:local_port] }.transform_values do |owned|
              pids = owned.map { |socket| socket[:pid] }.uniq
              processes = owned.map { |socket| socket[:process] }.uniq
              upstream = sockets.select { |socket| pids.include?(socket[:pid]) && socket[:remote_host] }
              { process: processes.join(', '), pid: pids.join(','),
                socket_status: :observed,
                upstream_sockets: upstream.map { |socket|
                  { protocol: socket[:protocol], family: socket[:family],
                    remote_host: socket[:remote_host], remote_port: socket[:remote_port],
                    local_host: socket[:local_host], local_port: socket[:local_port],
                    dns_class: socket[:dns_class] }
                }.uniq }
            end
          else
            PortProcessResolver.listener_status(
              ports,
              netstat_runner: lambda { CommandExecutor.run('/usr/sbin/netstat', '-anv', '-p', 'tcp', timeout: 0.8) },
              ps_runner: lambda { |pids| CommandExecutor.run('/bin/ps', '-p', pids.join(','), '-o', 'pid=,comm=', timeout: 0.5) }
            )
          end
        end
        expand_with_endpoints(prove_paths_without_origin(dns_servers), resolver_endpoints, process_lookup)
      rescue StandardError => e
        Logger.warn("AdvancedDNSResolver: #{e.class}")
        []
      end

      # Remplace chaque preuve (une par IP) par une preuve par endpoint connu de `scutil --dns`.
      # Les adresses sans endpoint connu sont conservées telles quelles.
      def expand_with_endpoints(base_results, endpoints, process_lookup)
        loopback_ports = endpoints.select { |endpoint| loopback_ip?(endpoint[:ip]) }.map { |endpoint| endpoint[:port] }.uniq
        processes = loopback_ports.empty? ? {} : (process_lookup.call(loopback_ports) || {})

        base_results.flat_map do |result|
          matching = endpoints.select { |endpoint| endpoint[:ip] == result[:ip].to_s }
          next [result] if matching.empty?

          matching.map do |endpoint|
            decorated = result.merge(port: endpoint[:port], origin: endpoint_label(endpoint), default_resolver: endpoint[:default])
            scoped_ifaces = Array(endpoint[:ifaces]).map(&:to_s).reject(&:empty?)
            if !loopback_ip?(endpoint[:ip]) && !endpoint[:default] && Array(endpoint[:domains]).empty? &&
               !scoped_ifaces.empty? && !scoped_ifaces.include?(result[:interface].to_s)
              decorated = decorated.merge(
                status: :unknown,
                proven_secure: false,
                reason: "Résolveur scoped sur #{scoped_ifaces.join(', ')} ; route IP observée via #{result[:interface] || 'interface inconnue'}, chemin DNS effectif non vérifiable"
              )
            end
            descriptor = loopback_ip?(endpoint[:ip]) ? processes[endpoint[:port]] : nil
            case descriptor
            when String then decorated.merge(process: descriptor)
            when Symbol then decorated.merge(listener: descriptor)
            when Hash
              decorated.merge(
                process: descriptor[:process], pid: descriptor[:pid],
                socket_status: descriptor[:socket_status],
                upstream_sockets: descriptor[:upstream_sockets] || []
              )
            else decorated
            end
          end
        end
      rescue StandardError => e
        Logger.warn("AdvancedDNSResolver endpoints: #{e.class}")
        base_results
      end

      # [{ ip:, port:, default:, domains:, ifaces: }] d'après `scutil --dns`.
      def resolver_endpoints
        endpoints = []
        parse_resolver_blocks.each do |block|
          port = block[:port] || 53
          scoped = block[:section] == :scoped || block[:flags].include?('Scoped')
          block[:servers].each do |server|
            endpoint = endpoints.find { |item| item[:ip] == server && item[:port] == port }
            unless endpoint
              endpoint = { ip: server, port: port, default: false, domains: [], ifaces: [] }
              endpoints << endpoint
            end
            if scoped
              iface = block[:iface] || 'interface'
              endpoint[:ifaces] << iface unless endpoint[:ifaces].include?(iface)
              if block[:domain]
                endpoint[:domains] << block[:domain] unless endpoint[:domains].include?(block[:domain])
              end
            elsif block[:domain]
              endpoint[:domains] << block[:domain] unless endpoint[:domains].include?(block[:domain])
            else
              endpoint[:default] = true
            end
            unless scoped
              Array(block[:search_domains]).each do |domain|
                endpoint[:domains] << domain unless endpoint[:domains].include?(domain)
              end
            end
          end
        end
        endpoints
      end

      def endpoint_label(endpoint)
        parts = []
        parts << 'défaut système' if endpoint[:default]
        unless endpoint[:domains].empty?
          noun = endpoint[:domains].size > 1 ? 'domaines' : 'domaine'
          only = !endpoint[:default] && endpoint[:ifaces].empty?
          parts << "#{noun} #{endpoint[:domains].join(', ')}#{only ? ' uniquement' : ''}"
        end
        parts << "limité à #{endpoint[:ifaces].join(', ')}" unless endpoint[:ifaces].empty?
        parts.join(' ; ')
      end

      def parse_resolver_blocks
        blocks = []
        section = :default
        current = nil

        @snapshot.scutil_dns.to_s.each_line do |raw|
          line = raw.strip
          if line.start_with?('DNS configuration (for scoped queries)')
            section = :scoped
            current = nil
          elsif line.start_with?('DNS configuration')
            section = :default
            current = nil
          elsif line.match?(/\Aresolver #\d+/)
            current = { section: section, servers: [], port: nil, iface: nil, if_index: nil, flags: '', domain: nil, search_domains: [] }
            blocks << current
          elsif current
            if (match = line.match(/\Anameserver\[\d+\]\s*:\s*(\S+)/))
              current[:servers] << match[1].split('%').first
            elsif (match = line.match(/\Aport\s*:\s*(\d+)/))
              current[:port] = match[1].to_i
            elsif (match = line.match(/\Aif_index\s*:\s*(\d+)(?:\s*\(([^)]+)\))?/))
              current[:if_index] = match[1].to_i
              current[:iface] = match[2] if match[2]
            elsif (match = line.match(/\Aflags\s*:\s*(.+)\z/))
              current[:flags] = match[1]
            elsif (match = line.match(/\Asearch\s+domain\[\d+\]\s*:\s*(\S+)/))
              current[:search_domains] << match[1] unless current[:search_domains].include?(match[1])
            elsif (match = line.match(/\Adomain\s*:\s*(\S+)/))
              current[:domain] = match[1]
            end
          end
        end
        names = nil
        blocks.each do |block|
          next if block[:iface] || block[:if_index].nil?

          names ||= load_if_index_names
          resolved = names[block[:if_index]]
          block[:iface] = resolved if resolved
        end
        blocks
      end

      # Secours if_index -> nom via `ifconfig -v` si scutil ne nomme pas ; échec = aucun nom.
      def load_if_index_names
        text = if @if_index_runner
                 @if_index_runner.call
               else
                 CommandExecutor.safe_run('ifconfig', '-v', timeout: Config::TIMEOUT_FAST)[:stdout].to_s
               end
        InterfaceIndex.parse(text)
      rescue StandardError
        {}
      end

      # nameserver[0] + port du résolveur par défaut ; affichage uniquement.
      def primary_resolver_endpoint
        block = parse_resolver_blocks.find do |item|
          item[:section] == :default && item[:domain].nil? && !item[:servers].empty? &&
            !item[:flags].to_s.include?('Scoped')
        end
        return nil unless block

        { ip: block[:servers].first, port: block[:port] || 53, iface: block[:iface] }
      rescue StandardError
        nil
      end

      def loopback_ip?(ip)
        IPAddr.new(ip.to_s).loopback?
      rescue StandardError
        false
      end

      def prove_paths_without_origin(dns_servers)
        Array(dns_servers).map do |dns|
          unless VPNChecker.valid_ip?(dns)
            next({
              ip: dns,
              interface: nil,
              proven_secure: false,
              status: :unknown,
              reason: 'Adresse DNS invalide'
            })
          end

          # DNS loopback = relais local, pas une preuve de fuite ; amont non
          # visible via route(8).
          begin
            dns_ip = IPAddr.new(dns)
            if dns_ip.loopback?
              next({
                ip: dns, interface: 'lo0', proven_secure: false,
                status: :local_resolver_observed,
                reason: 'Résolveur DNS local/loopback ; chemin DNS amont non vérifié'
              })
            end
          rescue IPAddr::InvalidAddressError, ArgumentError
            # La validation d'adresse est effectuée plus haut.
          end

          result = CommandExecutor.run(
            '/sbin/route', '-n', 'get', dns,
            timeout: Config::TIMEOUT_FAST
          )

          unless result[:success]
            next({
              ip: dns,
              interface: nil,
              proven_secure: false,
              status: :unknown,
              reason: 'Route DNS non vérifiable'
            })
          end

          iface_match = result[:stdout].to_s.match(
            /interface:\s*([a-zA-Z0-9._-]+)/
          )
          iface = iface_match && iface_match[1]

          if iface.nil? || iface.empty?
            next({
              ip: dns,
              interface: nil,
              proven_secure: false,
              status: :unknown,
              reason: 'Interface de sortie inconnue'
            })
          end

          tunnel = iface.match?(/\A(?:utun|tun|wg|ppp|tap)\d*\z/i)

          {
            ip: dns,
            interface: iface,
            proven_secure: tunnel,
            status: tunnel ? :secure_path_observed : :non_tunnel_path_observed,
            reason: tunnel ? 'Route associée à une interface tunnel' :
                       'Route non associée à une interface tunnel'
          }
        end
      rescue StandardError => e
        Logger.warn("AdvancedDNSResolver: #{e.class} - #{e.message}")
        []
      end


      def detected_tunnel_dns
        tunnel_dns = dns_servers.find do |ip|
          ip_addr = IPAddr.new(ip) rescue nil
          ip_addr && (ip_addr.private? || ip_addr.loopback?)
        end
        return tunnel_dns if tunnel_dns

        default_gw = @snapshot.default_gateway
        gw_addr = IPAddr.new(default_gw.to_s) rescue nil
        return default_gw if gw_addr && gw_addr.private?

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

      def make_request(url_string, timeout: Config::TIMEOUT_FAST, open_timeout: Config::HTTP_OPEN_TIMEOUT, read_timeout: Config::HTTP_READ_TIMEOUT, headers: {})
        uri = URI.parse(url_string) rescue nil
        return nil unless uri && uri.host && uri.scheme == 'https'
        return nil unless uri.userinfo.nil?

        host = uri.host
        unless @circuit_breaker.allow?(host)
          Logger.warn("Circuit Breaker actif : requête ignorée pour #{host}")
          return nil
        end

        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + [timeout.to_f, 0.01].max
        attempts = 0
        max_attempts = Config::MAX_RETRIES

        begin
          attempts += 1
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          raise Timeout::Error, 'deadline HTTP dépassée' if remaining <= 0

          connect_budget = [open_timeout.to_f, remaining].min
          read_budget    = [read_timeout.to_f, remaining].min

          Timeout.timeout(remaining) do
            Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                            open_timeout: connect_budget, read_timeout: read_budget) do |http|
              request = Net::HTTP::Get.new(uri.request_uri)
              request['User-Agent'] = "VPNChecker/#{Config::VERSION}"
              headers.to_h.each do |key, value|
                next if key.to_s.downcase == 'host'
                request[key.to_s] = value.to_s
              end
              response = http.request(request)

              if response.is_a?(Net::HTTPSuccess)
                body = response.body.to_s
                raise 'Réponse HTTP trop volumineuse' if body.bytesize > 1_048_576
                @circuit_breaker.record_success(host)
                return body
              elsif response.is_a?(Net::HTTPClientError) # 4xx
                Logger.warn("Erreur client HTTP #{response.code} pour #{uri.host} (pas de retry)")
                return nil
              else
                raise "HTTP #{response.code}"
              end
            end
          end
        rescue Timeout::Error, Net::OpenTimeout, Net::ReadTimeout, Errno::ETIMEDOUT => e
          Logger.log_timeout("HTTPClient(#{host})", "Tentative #{attempts}/#{max_attempts}: #{e.message}")
          @circuit_breaker.record_failure(host)

          if attempts < max_attempts
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            sleep_time = [Config::RETRY_BACKOFF_STEPS[attempts - 1] || 0.4, [remaining, 0.0].max].min
            sleep(sleep_time) if sleep_time > 0
            retry if Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
          end
          nil
        # Extension de la gestion des erreurs non transitoires (pas de retry immédiat)
        rescue Errno::ENETUNREACH, Errno::EHOSTUNREACH, Errno::EADDRNOTAVAIL, Errno::ECONNREFUSED => e
          Logger.warn("Réseau injoignable ou refusé pour #{host} (#{e.class}) : pas de nouvel essai")
          @circuit_breaker.record_failure(host)
          nil
        rescue StandardError => e
          Logger.warn("Échec requête HTTP (#{url_string}) [Essai #{attempts}/#{max_attempts}]: #{e.message}")
          @circuit_breaker.record_failure(host)

          if attempts < max_attempts
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            sleep_time = [Config::RETRY_BACKOFF_STEPS[attempts - 1] || 0.4, [remaining, 0.0].max].min
            sleep(sleep_time) if sleep_time > 0
            retry if Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
          end
          nil
        end
      end

      def get(url, timeout: Config::TIMEOUT_FAST, headers: {})
        make_request(url, timeout: timeout, headers: headers)
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
      # ----------------------------------------------------------------------
      # CONTRAT COMMUN DES RÉSULTATS (additif)
      # state :ok|:warning|:detected|:unknown|:not_applicable|:error ;
      # confidence 0..100 ; evidence (détail d'origine conservé dans
      # :evidence_detail) ; reason ; detected true|false|nil ; severity.
      #
      # ÉTATS  : :detected (observé), :ok (contrôle fini, non observé ≠ « sécurisé »),
      # :warning (indice, gravité faible), :unknown (preuves insuffisantes/délai),
      # :not_applicable (précondition absente), :error (exception interne).
      # RÈGLES : absence de preuve ≠ « non détecté » ; champs historiques intacts,
      # ajouts seuls ; un constructeur unique pour timeout/erreur/non applicable.
      # ----------------------------------------------------------------------
      STATES        = %i[ok warning detected unknown not_applicable error].freeze
      SEVERITIES    = %i[none low medium high unknown].freeze
      CONTRACT_KEYS = %i[state confidence evidence reason detected severity].freeze

      attr_reader :snapshot, :http_client, :dns_resolver

      def initialize(snapshot: nil, http_client: nil, dns_resolver: nil)
        @snapshot = snapshot
        @http_client = http_client
        @dns_resolver = dns_resolver
      end

      class << self
        # Priorité : valeur historique valide > option explicite > valeur dérivée.
        # opts accepte : :state, :confidence, :evidence, :reason, :detected, :severity.
        def normalize_result(result, opts = {})
          out = result.is_a?(Hash) ? result.dup : {}

          unless out.key?(:detected)
            out[:detected] = opts.key?(:detected) ? opts[:detected] : infer_detected(out)
          end

          sev = coerce_severity(out[:severity])
          if sev.nil?
            out[:raw_severity] = out[:severity] unless out[:severity].nil?
            sev = coerce_severity(opts[:severity])
          end

          unless STATES.include?(out[:state])
            out[:raw_state] = out[:state] unless out[:state].nil?
            out[:state] = STATES.include?(opts[:state]) ? opts[:state] : derive_state(out, sev)
          end
          out[:severity] = sev || derive_severity(out)

          conf = out[:confidence]
          conf = opts[:confidence] unless conf.is_a?(Numeric)
          conf = default_confidence(out[:state]) unless conf.is_a?(Numeric)
          conf = 0 if conf.is_a?(Float) && (conf.nan? || conf.infinite?)
          out[:confidence] = [[conf.to_i, 0].max, 100].min

          out[:reason] = out[:reason].to_s
          if out[:reason].strip.empty?
            fallback = opts[:reason].to_s
            fallback = out[:message].to_s if fallback.strip.empty?
            fallback = "Aucune explication fournie par le détecteur (état : #{out[:state]})." if fallback.strip.empty?
            out[:reason] = fallback
          end

          raw_evidence = out.key?(:evidence) ? out[:evidence] : opts[:evidence]
          unless raw_evidence.nil? || array_of_strings?(raw_evidence)
            out[:evidence_detail] = raw_evidence
          end
          out[:evidence] = evidence_lines(raw_evidence).freeze

          out
        end

        # Délai dépassé : toujours « inconnu », jamais « non détecté ».
        def timeout_result(reason: nil, evidence: nil, **legacy)
          normalize_result(
            legacy.merge(
              state: :unknown, unknown: true, timed_out: true, detected: nil,
              severity: :unknown, confidence: 0,
              evidence: evidence.nil? ? ['timeout'] : evidence,
              reason: reason || 'Délai dépassé : le détecteur n’a pas terminé dans le temps imparti ; aucun résultat exploitable.'
            )
          )
        end

        # Exception interne : classe seule tracée, message non recopié
        # (peut contenir des données externes).
        def error_result(error, reason: nil, evidence: nil, **legacy)
          label = error.is_a?(Exception) ? error.class.name : error.to_s
          normalize_result(
            legacy.merge(
              state: :error, unknown: true, error: label, detected: nil,
              severity: :unknown, confidence: 0,
              evidence: evidence.nil? ? ["error: #{label}"] : evidence,
              reason: reason || "Erreur interne du détecteur (#{label}) : aucun résultat exploitable."
            )
          )
        end

        # Précondition absente (VPN inactif, hors ligne…) : rien n'a été évalué.
        def not_applicable_result(reason: nil, evidence: nil, **legacy)
          normalize_result(
            legacy.merge(
              state: :not_applicable,
              evidence: evidence.nil? ? [] : evidence,
              reason: reason || 'Contrôle non applicable dans le contexte courant.'
            )
          )
        end

        # Problèmes structurels du contrat (liste vide = conforme).
        def contract_problems(result)
          return ['résultat absent ou non-Hash'] unless result.is_a?(Hash)

          problems = []
          problems << 'state invalide' unless STATES.include?(result[:state])
          conf = result[:confidence]
          problems << 'confidence hors 0..100' unless conf.is_a?(Integer) && conf.between?(0, 100)
          evidence = result[:evidence]
          problems << 'evidence doit être un Array de String' unless array_of_strings?(evidence)
          problems << 'reason vide' if result[:reason].to_s.strip.empty?
          problems << 'clé detected absente' unless result.key?(:detected)
          problems << 'detected doit être true, false ou nil' unless [true, false, nil].include?(result[:detected])
          problems << 'severity invalide' unless SEVERITIES.include?(result[:severity])
          problems
        end

        # Incohérences sémantiques (non bloquantes) à traiter séparément.
        def contract_warnings(result)
          return [] unless result.is_a?(Hash)

          warnings = []
          if %i[unknown error].include?(result[:state]) && result[:detected] == false
            warnings << "state=#{result[:state].inspect} avec detected=false : un consommateur qui ne lit que `detected` prendrait ce cas pour une absence prouvée"
          end
          warnings
        end

        private

        def infer_detected(out)
          return nil if out[:unknown] == true || out[:error]
          return nil if %i[unknown error not_applicable].include?(out[:state])
          return out[:leak] if out[:leak] == true || out[:leak] == false

          nil
        end

        def coerce_severity(value)
          sym = value.is_a?(String) ? value.strip.downcase.to_sym : value
          SEVERITIES.include?(sym) ? sym : nil
        end

        def derive_state(out, sev)
          return :error if out[:error]
          return :unknown if out[:unknown] == true || out[:detected].nil?
          return :ok if out[:detected] == false

          sev == :low ? :warning : :detected
        end

        def derive_severity(out)
          case out[:state]
          when :not_applicable then :none
          when :unknown, :error then :unknown
          else
            if out[:detected] == false
              :none
            elsif out[:leak] == true
              :high
            else
              :unknown
            end
          end
        end

        def default_confidence(state)
          case state
          when :unknown, :error then 0
          when :not_applicable then 100
          else 50
          end
        end

        def array_of_strings?(value)
          value.is_a?(Array) && value.all? { |item| item.is_a?(String) }
        end

        def evidence_lines(raw)
          items = case raw
                  when nil then []
                  when Hash then raw.map { |key, value| "#{key}=#{value}" }
                  when Array then raw.flatten
                  else [raw]
                  end
          items.compact.map do |item|
            item.is_a?(Hash) ? item.map { |key, value| "#{key}=#{value}" }.join(' ') : item.to_s
          end
        end
      end

      private

      def build_result(state:, confidence:, evidence: [], reason: "", **legacy)
        self.class.normalize_result(
          legacy.merge(state: state, confidence: confidence, evidence: evidence, reason: reason)
        )
      end

      def unknown_result(reason:, evidence: [], confidence: 0, **legacy)
        build_result(state: :unknown, confidence: confidence, evidence: evidence, reason: reason, **legacy)
      end

      def error_result(error, **opts)
        self.class.error_result(error, **opts)
      end

      def timeout_result(**opts)
        self.class.timeout_result(**opts)
      end
    end

    class OpenPortsDetector < BaseDetector
      # API historique : renvoie un Array (consommé tel quel par le renderer).
      def detect
        @snapshot.netstat_snap.open_ports
      rescue StandardError => e
        Logger.warn("OpenPortsDetector failed: #{e.message}")
        []
      end

      # Meilleur effort : ajoute :process quand il est identifiable (sinon liste inchangée).
      def attribute_processes(ports)
        Infrastructure::PortProcessResolver.enrich(ports)
      end

      # Contrat additif : liste vide ≠ « aucun port » si netstat n'a rien renvoyé.
      def detect_result
        netstat = @snapshot.netstat_snap
        ports = netstat.open_ports

        unless netstat.available?
          return unknown_result(
            confidence: 0, evidence: ['netstat: sortie indisponible'],
            reason: 'Sortie netstat vide ou indisponible : ports non vérifiables. Liste vide ≠ aucun port.',
            ports: []
          )
        end

        ignored = Infrastructure::NetstatSnapshot::IGNORE_PORTS.join(', ')
        if ports.empty?
          build_result(
            state: :ok, confidence: 70, evidence: [],
            reason: "Aucun port TCP en écoute hors ports standard ignorés (#{ignored}).",
            ports: ports, detected: false, severity: :none
          )
        else
          build_result(
            state: :detected, confidence: 70,
            evidence: ports.map { |entry| "tcp/#{entry[:port]} LISTEN" },
            reason: "#{ports.size} port(s) TCP en écoute hors ports standard ignorés (#{ignored}).",
            ports: ports, detected: true
          )
        end
      rescue StandardError => e
        Logger.warn("OpenPortsDetector#detect_result failed: #{e.message}")
        error_result(e, ports: [])
      end
    end

    # socketfilterfw : lecture seule, sans root. Filtrage ENTRANT par app ;
    # distinct de PF, ne dit rien du trafic sortant ni du Kill Switch.
    class AppFirewallDetector < BaseDetector
      BINARY = '/usr/libexec/ApplicationFirewall/socketfilterfw'

      # runner : lambda(flag) -> { success:, stdout:, stderr: } (injectable en test).
      def detect(runner: nil)
        if runner.nil?
          unless File.executable?(BINARY)
            return unknown_result(
              confidence: 0, evidence: ['socketfilterfw: introuvable'],
              reason: 'socketfilterfw introuvable : pare-feu applicatif illisible.',
              enabled: nil, detected: nil, unknown: true, severity: :unknown,
              message: '⚪ Non vérifiable'
            )
          end

          runner = lambda do |flag|
            Infrastructure::CommandExecutor.run(BINARY, flag, timeout: VPNChecker::Config::TIMEOUT_FAST)
          end
        end

        global = runner.call('--getglobalstate')
        unless global[:success]
          return unknown_result(
            confidence: 0, evidence: ['socketfilterfw --getglobalstate: échec'],
            reason: 'Lecture de l’état global impossible : non vérifiable.',
            enabled: nil, detected: nil, unknown: true, severity: :unknown,
            message: '⚪ Non vérifiable'
          )
        end

        text = global[:stdout].to_s
        state_match = text.match(/State\s*=\s*(\d)/)
        enabled = if state_match
                    state_match[1] != '0'
                  elsif text.match?(/\bdisabled\b/i)
                    false
                  elsif text.match?(/\benabled\b/i)
                    true
                  end
        if enabled.nil?
          return unknown_result(
            confidence: 0, evidence: ['socketfilterfw --getglobalstate: sortie non interprétable'],
            reason: 'Sortie du pare-feu applicatif ininterprétable : non vérifiable.',
            enabled: nil, detected: nil, unknown: true, severity: :unknown,
            message: '⚪ Non vérifiable'
          )
        end

        stealth = flag_from(runner.call('--getstealthmode'), /stealth mode is (on|off)/i, 'on')
        block_all = flag_from(runner.call('--getblockall'), /block all state set to (enabled|disabled)/i, 'enabled')

        evidence = [
          "mode furtif : #{describe(stealth, 'activé', 'désactivé')}",
          "blocage de toutes les connexions entrantes : #{describe(block_all, 'activé', 'désactivé')}"
        ]
        details = { enabled: enabled, stealth: stealth, block_all: block_all }

        if enabled
          build_result(
            state: :ok, confidence: 80, evidence: evidence,
            reason: 'Pare-feu applicatif activé : filtre les entrées par application (pas le trafic sortant).',
            detected: true, severity: :none, message: '🟢 Activé', **details
          )
        else
          build_result(
            state: :warning, confidence: 80, evidence: evidence,
            reason: 'Pare-feu applicatif désactivé : aucune application filtrée en entrée.',
            detected: false, severity: :unknown, message: '🔴 Désactivé', **details
          )
        end
      rescue StandardError => e
        Logger.warn("AppFirewallDetector: #{e.class}")
        error_result(e, enabled: nil, message: '⚪ Non vérifiable')
      end

      private

      def flag_from(result, pattern, true_word)
        return nil unless result.is_a?(Hash) && result[:success]

        match = result[:stdout].to_s.match(pattern)
        match ? match[1].downcase == true_word : nil
      end

      def describe(value, on_text, off_text)
        return 'non vérifiable' if value.nil?

        value ? on_text : off_text
      end
    end

    class EncryptedDNSDetector < BaseDetector
      DOQ_PORTS = [784, 853, 8853].freeze
      DOH_PROVIDERS = %w[cloudflared nextdns dnsproxy stubby].freeze

      def detect
        # Port en écoute = capacité, pas preuve d'usage ; seul un processus
        # reconnu reste un indice « présent ». Port seul rapporté à part,
        # sans effet sur état/score/icône.
        proc_methods = [detect_dnscrypt, detect_doh_process].compact
        port_methods = [detect_doh_port, detect_dot, detect_doq].compact.uniq
        methods = proc_methods.empty? ? port_methods : proc_methods

        if proc_methods.empty? && !port_methods.empty?
          return unknown_result(
            confidence: 15,
            evidence: port_methods.map { |name| "port en écoute: #{name} (capacité, pas un usage)" },
            reason: 'Un port DoH/DoT/DoQ en écoute ne prouve pas qu’un DNS chiffré est utilisé : aucun processus de résolveur chiffré reconnu, usage par le système non prouvé.',
            encrypted: nil, unknown: true, methods: methods, detected: nil, severity: :unknown,
            level: :port_only, port_only: true,
            message: "⚪ Port #{port_methods.join('/')} en écoute ; usage DNS chiffré non prouvé"
          )
        end

        if methods.empty?
          ps_available = !@snapshot.respond_to?(:ps_available) || @snapshot.ps_available
          if ps_available
            unknown_result(
              confidence: 0, evidence: [],
              reason: 'Aucun indice de chiffrement DNS ; un DoH/DoT navigateur, profil ou proxy n’est pas visible ici : absence de preuve ≠ absence de chiffrement.',
              encrypted: nil, unknown: true, methods: [], detected: nil, severity: :unknown,
              message: '⚪ Aucun chiffrement DNS détecté (DoH/DoT navigateur ou profil non visibles)'
            )
          else
            unknown_result(
              confidence: 0, evidence: ['ps: liste des processus indisponible'],
              reason: 'ps indisponible : relais DNS chiffré non vérifiable.',
              encrypted: nil, unknown: true, methods: [], detected: nil, severity: :unknown,
              process_list_unavailable: true,
              message: '⚪ Non vérifié (liste des processus indisponible)'
            )
          end
        else
          build_result(
            state: :detected, confidence: 40,
            evidence: methods.map { |method_name| "indice: #{method_name}" } +
                      port_methods.map { |name| "port en écoute: #{name} (capacité, pas un usage)" },
            reason: 'Indice local de chiffrement DNS (processus de résolveur chiffré observé) ; usage réel par le résolveur système non prouvé.',
            encrypted: true, methods: methods, detected: true, severity: :none,
            level: :present,
            message: "⚪ #{methods.join(' + ')} présent ; usage système non prouvé"
          )
        end
      end

      private

      def detect_dnscrypt
        procs = @snapshot.ps_procs || []
        return 'DNSCrypt' if procs.any? { |p| p.include?('dnscrypt-proxy') }
        nil
      end

      # Processus reconnu seulement (indice « présent »).
      def detect_doh_process
        procs = @snapshot.ps_procs || []
        procs.any? { |prov| DOH_PROVIDERS.any? { |p| prov.include?(p) } } ? 'DoH' : nil
      end

      # Port seul (capacité) : jamais un indice d'usage.
      def detect_doh_port
        @snapshot.netstat_snap.doh? ? 'DoH' : nil
      end

      # Conservé pour compatibilité : processus puis port.
      def detect_doh
        detect_doh_process || detect_doh_port
      end

      def detect_dot
        @snapshot.netstat_snap.dot? ? 'DoT' : nil
      end

      def detect_doq
        @snapshot.netstat_snap.doq? ? 'DoQ' : nil
      end
    end

    class VPNDetector < BaseDetector
      KNOWN_VPN_PROCESSES = Config::VPN_PROCESS_KEYWORDS

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

        default_on_tunnel = route_based_vpn
        active_status = default_on_tunnel || active_if
        evidence = { tunnel_interface: active_if, default_route_tunnel: default_on_tunnel, vpn_process: active_pr }

        reason_text = if active_status
                        "VPN observé — route par défaut via tunnel : #{route_based_vpn ? 'oui' : 'non'} ; interface tunnel : #{active_if ? 'oui' : 'non'} ; processus VPN connu : #{active_pr ? 'oui' : 'non'}."
                      else
                        'Aucun tunnel VPN observé (interfaces, routes et processus analysés).'
                      end

        build_result(
          state: active_status ? :detected : :ok,
          confidence: calculate_confidence(active_if, active_pr, route_based_vpn),
          evidence: evidence,
          reason: reason_text,
          detected: active_status ? true : false,
          severity: :none,
          active: active_status,
          interface_based: active_if,
          process_based: active_pr,
          route_based: route_based_vpn,
          tunnel_type: active_status ? detect_tunnel_type(processes) : 'Inconnu',
          interface: interfaces.first,
          interfaces: interfaces
        )
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
      # L'ancien code appelait detect(...), alors que l'implémentation exposait
      # uniquement evaluate. On garde les deux API pour éviter toute régression.
      def detect(vpn_active: nil)
        evaluate(vpn_active: vpn_active)
      rescue StandardError => e
        Logger.warn("KillSwitchDetector failed: #{e.message}")
        error_result(
          e,
          reason: 'Kill Switch non vérifiable : erreur interne du détecteur.',
          status: '⚪ Non vérifiable', broken: false, protection_proven: false
        )
      end

      def evaluate(vpn_active: nil)
        routes = snapshot.routing_table
        tunnel_active = vpn_active.nil? ? routes.vpn_tunnel_active? : !!vpn_active
        physical_gateway = routes.find_physical_default_gateway
        default_block_route = routes.has_default_block_route?

        if !tunnel_active
          build_result(
            state: :not_applicable, confidence: 100, evidence: routes.relevant_entries,
            reason: 'VPN inactif : Kill Switch non validable.',
            status: '⚪ Inactif', broken: false, protection_proven: false, tunnel_active: false
          )
        elsif default_block_route && physical_gateway.nil?
          unknown_result(
            confidence: 75, evidence: routes.relevant_entries,
            reason: 'Route bloquante par défaut présente ; la table seule ne prouve pas le blocage effectif après rupture du VPN.',
            status: '🟡 Configuration détectée, protection non prouvée',
            broken: false, protection_proven: false, tunnel_active: true
          )
        elsif physical_gateway
          unknown_result(
            confidence: 60,
            evidence: ["physical_gateway: #{physical_gateway}", 'vpn_active: true'],
            reason: 'Route du tunnel présente ; comportement après coupure non prouvable (netstat seul).',
            status: '🟡 Non vérifiable', broken: false, protection_proven: false, tunnel_active: true
          )
        else
          unknown_result(
            confidence: 50, evidence: routes.relevant_entries,
            reason: 'Tunnel détecté ; confinement après rupture non prouvé.',
            status: '🟡 Non vérifiable', broken: false, protection_proven: false, tunnel_active: true
          )
        end
      end
    end

    
    class DNSLeakDetector < BaseDetector
      def initialize(snapshot: nil, http_client: nil, dns_resolver: nil)
        @snapshot = snapshot
        @http_client = http_client
        @dns_resolver = dns_resolver
      end

      def detect(vpn_active: false)
        unless vpn_active
          return build_result(
            state: :not_applicable, confidence: 100, evidence: [],
            reason: 'VPN inactif : chemins DNS hors périmètre.',
            leak: false, detected: nil, unknown: false, severity: :none,
            message: '⚪ VPN inactif'
          )
        end

        unless @dns_resolver
          return unknown_result(
            reason: 'Résolveur indisponible : serveurs et chemins DNS inobservables.',
            leak: nil, detected: nil, unknown: true, severity: :unknown,
            message: '⚪ DNS non vérifiables : resolver manquant'
          )
        end

        dns_servers = @dns_resolver.dns_servers

        if dns_servers.empty?
          return unknown_result(
            reason: 'Aucun serveur DNS exploitable dans la configuration système : rien à analyser.',
            leak: nil, detected: nil, unknown: true, severity: :unknown,
            message: '⚪ DNS non vérifiables : aucun serveur DNS exploitable'
          )
        end

        results = @dns_resolver.prove_dns_paths(dns_servers)

        if results.empty?
          return unknown_result(
            reason: 'Aucune preuve de chemin DNS n’a pu être collectée.',
            leak: nil, detected: nil, unknown: true, severity: :unknown,
            message: '⚪ DNS non vérifiables : aucune preuve exploitable'
          )
        end

        unknown_results = results.select { |r| r[:status] == :unknown }
        non_tunnel_results = results.select do |r|
          r[:status] == :non_tunnel_path_observed
        end

      # Les relais locaux (loopback/LAN) : amont non observable (charte, BLOQUÉ).
      # Serveurs distants comptés séparément ; relais conservés en :evidence,
      # état :unknown (preuve insuffisante).
        local_relays = results.select { |r| r[:status] == :local_resolver_observed }
        remote_results = results.reject { |r| r[:status] == :local_resolver_observed }
        remote_total = remote_results.size
        remote_secure = remote_results.count { |r| r[:status] == :secure_path_observed }
        remote_note = if remote_total.zero?
                        'aucun serveur distant observé'
                      else
                        "#{remote_secure}/#{remote_total} serveur(s) distant(s) via le tunnel"
                      end

        if non_tunnel_results.any?
          incomplete = !unknown_results.empty?
          reason_text = 'Au moins un serveur DNS est joint par une interface hors tunnel (preuve par la table de routage).'
          reason_text += ' Certains autres serveurs restent non vérifiables.' if incomplete
          build_result(
            state: :detected, confidence: 85, evidence: results,
            reason: reason_text,
            leak: true, detected: true, unknown: incomplete, incomplete: incomplete, severity: :high,
            message: "🔴 Chemin DNS hors tunnel observé : " \
                     "#{non_tunnel_results.map { |r| "#{r[:ip]} via #{r[:interface]}" }.join(', ')}"
          )
        elsif local_relays.any?
          unknown_result(
            confidence: 30,
            evidence: results,
            reason: "#{remote_note} ; #{local_relays.size} relais local(aux) (loopback/LAN) configuré(s) : le résolveur amont n’est pas observé, donc le chemin réel de ses requêtes n’est pas prouvé.",
            leak: nil, detected: nil, unknown: true, severity: :unknown,
            message: "🟡 Relais DNS local actif ; #{remote_note}, amont non vérifié"
          )
        elsif unknown_results.any?
          unknown_result(
            confidence: 0, evidence: results,
            reason: "Le chemin d’au moins un serveur DNS n’a pas pu être observé : preuves insuffisantes (#{remote_note}).",
            leak: nil, detected: nil, unknown: true, severity: :unknown,
            message: "🟡 Chemin DNS non vérifiable : #{remote_note}"
          )
        else
          build_result(
            state: :ok, confidence: 85, evidence: results,
            reason: 'Tous les serveurs DNS observés sont joints par une interface tunnel.',
            leak: false, detected: false, unknown: false, severity: :none,
            message: '🟢 Tous les chemins DNS observés utilisent une interface tunnel'
          )
        end
      rescue StandardError => e
        Logger.warn("DNSLeakDetector: #{e.class} - #{e.message}")

        error_result(
          e,
          reason: 'Analyse DNS interrompue : résultat non vérifiable.',
          leak: nil,
          message: '⚪ Analyse DNS interrompue : résultat non vérifiable'
        )
      end
    end


    class LeakDetector < BaseDetector
      def stun_service_detected?
        @snapshot.netstat_snap.stun_service_detected?
      end

      def detect_ipv6_leak(snapshot_param = nil, public_ipv6 = nil)
        curr_snapshot = snapshot_param || @snapshot
        ipv6_interface_active = curr_snapshot.ipv6_interface_active?
        vpn_route_active      = curr_snapshot.vpn_route_override?

        if ipv6_interface_active && public_ipv6 && vpn_route_active
          tunnel_ipv6 = curr_snapshot.vpn_ipv6_interface?
          unknown_result(
            confidence: tunnel_ipv6 ? 40 : 30,
            evidence: [
              'ipv6_interface_active',
              'public_ipv6: présente',
              'vpn_route_override: présent',
              "vpn_ipv6_interface: #{tunnel_ipv6 ? 'présente' : 'absente'}",
              'effective_ipv6_path: non mesuré'
            ],
            reason: 'IPv6 publique observée ; interface et route ne prouvent pas le chemin effectif.',
            leak: nil, detected: nil, unknown: true, severity: :unknown,
            message: tunnel_ipv6 ? '⚪ IPv6 via VPN possible, chemin non vérifié' : '🟡 Risque IPv6 à vérifier',
            active: true
          )
        elsif ipv6_interface_active && public_ipv6.nil?
          Logger.warn("IPv6 global actif mais adresse IPv6 publique non vérifiable")
          unknown_result(
            confidence: 20,
            evidence: ['ipv6_interface_active', 'public_ipv6: non obtenue'],
            reason: 'IPv6 globale active, IP publique indéterminée : exposition non vérifiable.',
            leak: nil, detected: nil, unknown: true, severity: :unknown,
            message: '🟡 IPv6 actif mais non vérifiable', active: true
          )
        elsif ipv6_interface_active
          Logger.warn("IPv6 actif sans route VPN observée : chemin effectif non confirmé")
          unknown_result(
            confidence: 30,
            evidence: ['ipv6_interface_active', 'public_ipv6: présente', 'vpn_route_override: absent'],
            reason: 'IPv6 globale active sans route VPN : sortie hors tunnel possible, chemin non confirmé.',
            leak: nil, detected: nil, unknown: true, severity: :unknown,
            message: '🟡 Risque de fuite IPv6 à vérifier', active: true
          )
        else
          # Décision j : vert = fait local observable de l'instantané, ne prouve
          # rien après reconnexion ; réserve conservée.
          build_result(
            state: :ok, confidence: 70,
            evidence: ['ipv6_interface_active: false'],
            reason: 'Aucune interface IPv6 globale active observée.',
            leak: false, detected: false, severity: :none,
            message: '🟢 Aucune', active: false
          )
        end
      end
    end

    class WebRTCLeakDetector < BaseDetector
      # Ce script ne peut pas observer les candidats ICE/WebRTC du navigateur.
      def detect(vpn_ip: nil)
        unknown_result(
          confidence: 0, evidence: [],
          reason: 'Le script Ruby ne mesure pas les adresses ICE/WebRTC du navigateur.',
          leak: nil, detected: nil, unknown: true, severity: :unknown,
          message: '⚪ Non testé (test navigateur requis)'
        )
      end
    end

    class TorDetector < BaseDetector
      def detect(ip: nil)
        if ip.nil? || %w[Non\ détectée Inconnu].include?(ip)
          return unknown_result(
            confidence: 0, evidence: ['ip_publique: indisponible'],
            reason: 'IP publique indisponible : comparaison avec la liste Tor impossible.',
            active: false, detected: nil, unknown: true, severity: :unknown,
            message: '🟡 Inactif'
          )
        end

        socks_open = test_socks_proxy
        tor_process = tor_process_running?
        exit_nodes = exit_node_list
        exit_node = exit_nodes.include?(ip)
        exit_list_available = !exit_nodes.empty?
        active = socks_open || tor_process || exit_node
        message = active ? '🟣 Actif' : '⚪ Inactif'

        if active
          evidence = []
          evidence << 'socks5: 127.0.0.1:9050' if socks_open
          evidence << 'processus: tor/obfs4proxy' if tor_process
          evidence << 'ip_publique: nœud de sortie Tor connu' if exit_node
          build_result(
            state: :detected, confidence: exit_node ? 90 : 60, evidence: evidence,
            reason: exit_node ? 'L’IP publique figure dans la liste des nœuds de sortie Tor.' : 'Indice local de Tor (proxy SOCKS ou processus) ; il ne prouve pas que le trafic sortant passe par Tor.',
            active: true, detected: true, severity: :none, message: message
          )
        elsif exit_list_available
          build_result(
            state: :ok, confidence: 70,
            evidence: ['liste_noeuds_sortie: disponible', 'socks5: fermé', 'processus: absent'],
            reason: 'Ni proxy SOCKS local, ni processus Tor, ni IP de sortie Tor connue (liste potentiellement ancienne).',
            active: false, detected: false, severity: :none, message: message
          )
        else
          unknown_result(
            confidence: 20,
            evidence: ['liste_noeuds_sortie: indisponible', 'socks5: fermé', 'processus: absent'],
            reason: 'Aucun indice Tor local ; liste des nœuds de sortie indisponible : non vérifiable.',
            active: false, detected: nil, unknown: true, severity: :unknown, message: message
          )
        end
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
    
    class ProviderDetector < BaseDetector
      def detect(geo_info: {}, ip: nil)
        if ip.nil? || %w[Non\ détectée Inconnu].include?(ip)
          return unknown_result(
            confidence: 0, evidence: ['ip_publique: indisponible'],
            reason: 'IP publique indisponible : classification du fournisseur impossible.',
            provider: 'Inconnu', type: Enums::InfrastructureType[:UNKNOWN],
            unknown: true, detected: nil, severity: :unknown
          )
        end

        info = geo_info || {}
        org = info['org'] || info[:org] || ''
        asn_raw = info['asn'] || info[:asn] || ''
        asn_num = asn_raw.to_s.gsub(/\D/, '').to_i
        raw_type = info['type'] || info[:type]
        rdns = info[:reverse_dns].to_s.downcase
        org_down = org.to_s.downcase

        provider = detect_provider_from_mappings(org_down) || detect_provider_from_asn(asn_raw.to_s)

        infra_types = Enums::InfrastructureType
        declared_type = raw_type.to_s.strip.downcase.to_sym
        type = if RESIDENTIAL_ASNS.key?(asn_num)
                 infra_types[:RESIDENTIAL]
               elsif infra_types.value?(declared_type) && declared_type != :unknown
                 declared_type
               elsif !provider.nil? || rdns.include?('hosted') || rdns.include?('vpn') || org_down.include?('worldstream') || org_down.include?('datacenter')
                 infra_types[:HOSTING]
               else
                 infra_types[:UNKNOWN]
               end

        provider_name = provider || (RESIDENTIAL_ASNS[asn_num] if RESIDENTIAL_ASNS.key?(asn_num)) || (org.empty? ? 'INCONNU' : org.sub(/^AS\d+\s*/, ''))
        confidence = calculate_confidence(org_down, asn_raw.to_s, provider)

        matched = !provider.nil?
        build_result(
          state: matched ? :detected : :ok,
          confidence: confidence,
          evidence: [matched ? "motif fournisseur: #{provider}" : 'motif fournisseur: aucun', "type: #{type}"],
          reason: matched ? 'Fournisseur reconnu par motif sur l’organisation ou l’ASN (heuristique).' : 'Aucun fournisseur VPN/hébergeur connu reconnu (liste heuristique non exhaustive).',
          detected: matched, severity: :none,
          provider: provider_name, type: type
        )
      end

      private

      def detect_provider_from_mappings(org_down)
        return nil if org_down.empty?
        VPNChecker::Helpers.detect_vpn_provider(org_down)
      end

      def detect_provider_from_asn(asn)
        return nil if asn.empty?
        asn_upper = asn.upcase
        VPNChecker::Helpers.detect_vpn_provider(asn_upper)
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
      def initialize(snapshot: nil, http_client: nil, dns_resolver: nil, reverse_dns: nil, bypass_source: nil)
        super(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver)
        @reverse_dns = reverse_dns
        @bypass_source = bypass_source
      end

      def detect(vpn_active: false, target_domain: nil)
        unless vpn_active
          return build_result(
            state: :not_applicable, confidence: 100,
            evidence: [], reason: 'VPN inactif : Split Tunnel non évaluable.',
            leak: false, detected: false, severity: :none, message: '⚪ VPN Inactif'
          )
        end

        # target_domain seul ≠ route autorisée : décision sur IP déclarée
        # (VPN Bypass) ou IP statique de confiance, jamais sur le nom.

        unless @snapshot.respond_to?(:routes)
          return build_result(
            state: :unknown, confidence: 0, evidence: [],
            reason: 'Table de routage indisponible : aucune conclusion possible.',
            leak: nil, detected: nil, unknown: true, severity: :unknown,
            message: '🟡 Split Tunnel non vérifiable (table de routage indisponible)'
          )
        end

        routes = Array(@snapshot.routes).map { |line| line.to_s.strip }.reject(&:empty?)
        if routes.empty?
          return build_result(
            state: :unknown, confidence: 0, evidence: [],
            reason: 'Table vide ou collecte échouée : absence de preuve ≠ absence de fuite.',
            leak: nil, detected: nil, unknown: true, severity: :unknown,
            message: '🟡 Split Tunnel non vérifiable (aucune route exploitable)'
          )
        end

        classified = routes.map { |route_line| [route_line, classify_route(route_line)] }
        leaks = classified.select { |_, kind| kind == :internet_host_route_via_physical }

        if leaks.any?
          # Exceptions : IP statiques fiables et routes VPN Bypass déclarées ;
          # un PTR sur domaine connu ne suffit pas.
          trusted, declared, unverified = partition_trusted(leaks)

          if unverified.empty?
            parts = []
            parts << "#{trusted.size} destination(s) de confiance (liste blanche)" if trusted.any?
            parts << "#{declared.size} route(s) hôte publique(s) corrélée(s) à VPN Bypass" if declared.any?
            # v5.9.8 : décompte par destination UNIQUE ; routes annoncées sans
            # route hôte corrélée nommées.
            declared_unique = declared.map { |line| line.to_s.split.first.to_s }.uniq.size
            missing_announced = announced_unmatched(declared, routes)
            # RFC1918 annoncée + route hôte via interface physique : classée
            # :lan_private (hors décompte public) mais corrélée.
            lan_covered = missing_announced.select { |item| item[:where] == :private_lan }
            missing_announced -= lan_covered
            declared_unique += lan_covered.size
            parts << "#{lan_covered.size} route(s) LAN privée(s) annoncée(s) et présente(s)" if lan_covered.any?
            return build_result(
              state: :ok, confidence: declared.empty? ? 90 : 80,
              evidence: trusted.map { |line, label| "#{line}  # confiance: #{label}" } +
                        declared.map { |line| "#{line}  # déclaré: VPN Bypass" } +
                        lan_covered.map { |item| "#{item[:line]}  # déclaré: VPN Bypass (LAN privée)" },
              reason: "#{parts.join(' • ')} : exceptions intentionnelles du tunnel, pas des fuites.",
              leak: false, detected: false, severity: :none,
              trusted_count: trusted.size, declared_count: declared.size,
              declared_unique_count: declared_unique, missing_announced: missing_announced,
              lan_covered_count: lan_covered.size,
              message: "🟢 #{parts.join(' • ')}"
            )
          end

          leaks = unverified.map { |line| [line, :internet_host_route_via_physical] }
          notes = []
          notes << "#{trusted.size} route(s) rattachée(s) à la liste blanche" unless trusted.empty?
          notes << "#{declared.size} route(s) déclarée(s) par VPN Bypass" unless declared.empty?
          trusted_note = notes.empty? ? '' : " ; #{notes.join(' • ')}"
          # Route hôte publique sur interface physique : peut être une route de
          # service (VPN, DNS…) ; la table seule ne prouve pas une fuite.
          # Drapeau PROTO1 : indice de créateur commun, pas une preuve d'origine.
          proto1_count = leaks.count { |line, _| line.split[2].to_s.include?('1') }
          scope_label = if proto1_count == leaks.size
                          "#{leaks.size} route(s) hôte marquée(s) PROTO1 via interface physique"
                        elsif proto1_count.positive?
                          "#{leaks.size} route(s) hôte via interface physique, dont #{proto1_count} marquée(s) PROTO1"
                        else
                          "#{leaks.size} route(s) hôte via interface physique"
                        end
          build_result(
            state: :unknown, confidence: 45,
            evidence: leaks.map(&:first),
            reason: 'Des routes hôte publiques via interface physique : exceptions VPN possibles. Fuite à confirmer par corrélation avec les endpoints du tunnel et les routes effectives.' + trusted_note,
            leak: nil, detected: true, severity: :medium,
            proto1_count: proto1_count,
            message: "🟡 Split Tunnel à vérifier (#{scope_label} ; fuite non confirmée#{trusted_note})"
          )
        else
          usable = classified.select { |_, kind| kind != :unknown }
          if usable.empty?
            build_result(
              state: :unknown, confidence: 0, evidence: routes,
              reason: 'Lignes non interprétables : routage non évaluable.',
              leak: nil, detected: nil, unknown: true, severity: :unknown,
              message: '🟡 Split Tunnel non vérifiable (routes non interprétables)'
            )
          else
            build_result(
              state: :unknown, confidence: 55,
              evidence: usable.map(&:first),
              reason: 'Aucune route hôte explicite via interface physique ; ne prouve pas que tout le trafic Internet passe par le VPN.',
              # detected: nil : état inconnu, pas une absence prouvée.
              leak: nil, detected: nil, unknown: true, severity: :low,
              message: '🟡 Aucun indice explicite détecté ; routage complet non prouvé'
            )
          end
        end
      end

      private

      # Sépare les routes hôte « leak » : IP fiables, exceptions VPN Bypass,
      # destinations non vérifiées. Un PTR n'est jamais une preuve.
      def partition_trusted(leaks)
        trusted = []
        declared = []
        unverified = []
        addresses = bypass_source.declared_addresses
        leaks.each do |line, _kind|
          destination = line.to_s.split.first.to_s
          if VPNChecker.whitelisted_ip?(destination)
            trusted << [line, "IP #{destination}"]
            next
          end
          if bypass_source.declared?(addresses, destination)
            declared << line
            next
          end
          # PTR non fiable (nom arbitraire possible) : renseignement seul,
          # jamais une exception « sûre ».
          unverified << line
        end
        [trusted, declared, unverified]
      end

      # v5.9.8 : routes VPN Bypass sans route hôte corrélée ; :absent,
      # :other_route ou :ipv6. Meilleur effort, sans effet sur le verdict.
      def announced_unmatched(declared_lines, all_routes)
        announced = Array(bypass_source.declared_addresses)
        matched = declared_lines.map { |line| parse_route_destination(line) }.compact
        announced.each_with_object([]) do |addr, missing|
          next unless addr.respond_to?(:include?)
          next if matched.any? { |dest| addr.include?(dest) }

          label = format_announced(addr)
          if addr.respond_to?(:ipv6?) && addr.ipv6?
            missing << { address: label, where: :ipv6 }
            next
          end
          other = all_routes.find do |line|
            dest = parse_route_destination(line)
            dest && addr.include?(dest)
          end
          if other
            parts = other.to_s.split
            dest = parse_route_destination(other)
            lan_host_physical = dest && private_or_local_destination?(dest.to_s) &&
                                parts[3].to_s.match?(/\Aen\d+\z/i) && parts[2].to_s.include?('H')
            missing << { address: label, where: (lan_host_physical ? :private_lan : :other_route),
                         flags: parts[2].to_s, via: parts[3].to_s, line: other.to_s }
          else
            missing << { address: label, where: :absent }
          end
        end
      rescue StandardError => e
        Logger.warn("SplitTunnelDetector announced_unmatched: #{e.class}: #{e.message}")
        []
      end

      def parse_route_destination(line)
        text = line.to_s.split.first.to_s.split('/').first.to_s
        return nil if text.empty?
        IPAddr.new(text)
      rescue IPAddr::InvalidAddressError, ArgumentError
        nil
      end

      def format_announced(addr)
        full = addr.ipv6? ? 128 : 32
        prefix = addr.respond_to?(:prefix) ? addr.prefix : full
        prefix == full ? addr.to_s : "#{addr}/#{prefix}"
      end

      def reverse_dns
        @reverse_dns ||= Intelligence::ReverseDNS.new
      end

      def bypass_source
        @bypass_source || Infrastructure::VPNBypassSource
      end

      def classify_route(route_line)
        parts = route_line.to_s.strip.split
        return :unknown if parts.empty?

        destination = parts[0].to_s
        flags       = parts[2].to_s
        netif       = parts[3].to_s

        # Interface loopback
        return :lan_private if netif.match?(/\Alo\d*\z/i)

        # Classification des destinations IP
        begin
          address_text = destination.split('/').first
          # Retrait du scope d'interface (fe80::1%en1) avant classement
          # (IPAddr Ruby 2.6 n'interprète pas %en1).
          address_text = address_text.split('%', 2).first
          address = IPAddr.new(address_text)

          # Multicast IPv4 : 224.0.0.0/4
          if address.ipv4?
            multicast = IPAddr.new('224.0.0.0/4')
            return :multicast_link_local if multicast.include?(address)
          else
            # Multicast IPv6 : ff00::/8
            multicast = IPAddr.new('ff00::/8')
            return :multicast_link_local if multicast.include?(address)
          end

          # Link-local, loopback et plages privées
          return :multicast_link_local if address.link_local?
          return :lan_private if address.loopback? || address.private?
        rescue IPAddr::InvalidAddressError, ArgumentError
          # "default" et certaines destinations système ne sont pas des IP.
        end

        # Interfaces VPN
        if netif.match?(/\A(?:utun|tun|wg|ppp|tap)\d*\z/i)
          return :vpn_infrastructure
        end

        # Route système Apple spécifique
        return :apple_system if destination.start_with?('17.')

        # Route hôte via interface physique : à examiner, pas une preuve de fuite.
        physical_interface = netif.match?(/\Aen\d+\z/i)
        host_route = flags.include?('H') || flags.include?('UGHS')

        if physical_interface && host_route
          return :internet_host_route_via_physical
        end

        :unknown
      end

      def private_or_local_destination?(destination)
        ip = IPAddr.new(destination.sub(%r{/\d+\z}, '')) rescue nil
        return false unless ip
        ip.loopback? || ip.link_local? || ip.private? ||
          (ip.ipv4? && destination.start_with?('169.254.'))
      end
    end
  end

  module Intelligence
    class IPLookupService
      def initialize(http_client: nil)
        @http_client = http_client || Network::HTTPClient.new
      end

      # ipv6_lookup: false : pas d'interrogation externe pour une IPv6 publique
      # sans interface IPv6 globale active.
      def fetch_public_ips(ipv6_lookup: true)
        ipv4, ipv6 = nil, nil
        threads = []

        threads << Thread.new { ipv4 = fetch_fastest(VPNChecker::Config::PUBLIC_IP_APIS, :v4) }
        if ipv6_lookup
          threads << Thread.new { ipv6 = fetch_fastest(VPNChecker::Config::PUBLIC_IPV6_APIS, :v6) }
        end

        threads.each { |t| t.join(VPNChecker::Config::TIMEOUT_FAST) }
        ipv6 = nil if ipv6 == ipv4

        {
          # Jamais de repli sur l'IP mémorisée : une valeur périmée serait présentée comme actuelle.
          v4: VPNChecker::Helpers.clean_str(ipv4, nil),
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

        fallback_geo
      end

      def fallback_geo
        {
          country: nil, country_code: nil, region: nil, city: nil,
          latitude: nil, longitude: nil, timezone: nil,
          asn: nil, org: nil, type: Enums::InfrastructureType[:UNKNOWN]
        }
      end

      private

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
          type: VPNChecker::Helpers.clean_str(json.dig('connection', 'type'), Enums::InfrastructureType[:UNKNOWN])
        }
      rescue StandardError
        {}
      end

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
          type: Enums::InfrastructureType[:UNKNOWN]
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
      # v5.9.8 : plafond d'affichage (calcul inchangé) ; score affiché plafonné
      # à CONFIDENCE_CAP si moins de la moitié des contrôles vérifiés.
      CONFIDENCE_CAP = 70

      def self.confidence_capped?(coverage)
        coverage.is_a?(Array) && coverage.size == 2 &&
          coverage[0].is_a?(Integer) && coverage[1].is_a?(Integer) &&
          coverage[1].positive? && coverage[0] * 2 < coverage[1]
      end

      def self.display_score(score, coverage)
        return score unless score.is_a?(Numeric)
        confidence_capped?(coverage) ? [score, CONFIDENCE_CAP].min : score
      end

      # Noms des contrôles sans preuve (statut nil) ; nil si non applicable.
      def self.unverified_check_names(ctx_struct)
        return nil unless ctx_struct[:ip_ok]
        vpn = ctx_struct[:vpn] || {}
        return nil unless vpn[:active]

        build_checks(ctx_struct).select { |check| check[:status].nil? }.map { |check| check[:name] }
      end

      def self.calculate(ctx_struct)
        return nil unless ctx_struct[:ip_ok]
        vpn = ctx_struct[:vpn] || {}
        return 25 unless vpn[:active]

        checks = build_checks(ctx_struct)

        applicable = checks.reject { |check| check[:status].nil? }
        return 50 if applicable.empty?

        total = applicable.sum { |check| check[:weight] }
        passed = applicable.sum { |check| check[:status] ? check[:weight] : 0 }
        # Le score ne doit pas transformer un état inconnu en échec certain.
        ((passed.to_f / total) * 90).round.clamp(0, 90)
      end

      # [vérifiés, total] ; nil si non applicable. Contrôle inconnu : ni réussi ni échoué.
      def self.coverage(ctx_struct)
        return nil unless ctx_struct[:ip_ok]
        vpn = ctx_struct[:vpn] || {}
        return nil unless vpn[:active]

        checks = build_checks(ctx_struct)
        [checks.count { |check| !check[:status].nil? }, checks.size]
      end

      def self.build_checks(ctx_struct)
        vpn = ctx_struct[:vpn] || {}
        [
          # Route-based (default route via tunnel) : indicateur fort (poids 25)
          { name: 'Route VPN', status: vpn[:route_based], weight: 25 },

          # DNS Leak : aucune requête DNS hors tunnel (poids 20)
          { name: 'Fuite DNS', status: tri_state(ctx_struct.dig(:dns_leak, :leak), false), weight: 20 },

          # IPv6 Leak : trafic IPv6 hors tunnel (poids 15)
          { name: 'Fuite IPv6', status: tri_state(ctx_struct.dig(:ipv6, :leak), false), weight: 15 },

          # Kill Switch : protection après chute du tunnel (poids 15)
          { name: 'Kill Switch', status: ks_ok?(ctx_struct[:ks]), weight: 15 },

          # Split Tunnel : routes non autorisées hors tunnel (poids 15)
          { name: 'Split Tunnel', status: split_ok?(ctx_struct[:split_tunnel]), weight: 15 },

          # Encrypted DNS : processus/port = indice ; seul le contrôle validé compte.
          { name: 'DNS chiffré', status: tri_state(ctx_struct.dig(:dns_encrypted, :verified), true), weight: 10 }
        ]
      end
      private_class_method :build_checks

      def self.tri_state(value, safe_value)
        return nil if value.nil?
        value == safe_value
      end
      private_class_method :tri_state

      def self.ks_ok?(ks)
        return nil unless ks.is_a?(Hash) && !ks.empty?

        # Les états non applicables/inconnus ne prouvent ni protection ni échec.
        return nil if %i[unknown error not_applicable].include?(ks[:state])
        return true if ks[:state] == :protected
        return false if ks[:state] == :exposed || ks[:broken] == true

        # Compatibilité stricte avec les anciens résultats structurés.
        return true if ks[:protection_proven] == true
        nil
      end
      private_class_method :ks_ok?

      def self.split_ok?(split)
        return nil if split.nil? || split.empty?
        # Un état inconnu, en erreur ou non applicable n'est ni une réussite ni un échec.
        return nil if %i[unknown error not_applicable].include?(split[:state])
        detected = split.key?(:detected) ? split[:detected] : split[:leak]
        return nil if detected.nil?
        !detected
      end
      private_class_method :split_ok?
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
        # Chaque hôte est sondé ; le premier répondant fournit la mesure.
        VPNChecker::Config::PING_HOSTS.each do |target_host|
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
          break unless latencies.empty?
        end
        latencies.compact
      end
    end
  end

  module Renderers
    module EmojiHelper
      module_function

      def country_code_to_emoji(code)
        return '🏳️' unless code.is_a?(String) && code.match?(/\A[A-Za-z]{2}\z/) && code.upcase != 'XX'

        code.upcase.codepoints.map { |c| (127397 + c).chr('UTF-8') }.join
      rescue StandardError
        '🏳️'
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

    # MiniToml (v6.1.1) : sous-ensemble strict de TOML ; tout non compris ->
    # ParseError, aucune valeur devinée. Non supporté volontairement :
    # multilignes, dates, hex/octal, inf/nan.
    module MiniToml
      class ParseError < StandardError
        attr_reader :line

        def initialize(message, line)
          super("#{message} (ligne #{line})")
          @line = line
        end
      end

      class Parser
        BARE_KEY = /[A-Za-z0-9_-]+/.freeze
        NUMBER = /[+-]?\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?(?![\w:.-])/.freeze

        def initialize(text)
          source = text.to_s.dup.force_encoding(Encoding::UTF_8).scrub('')
          @source = source.sub(/\A\uFEFF/, '').gsub("\r\n", "\n")
          @s = StringScanner.new(@source)
          @defined_tables = Set.new
        end

        def parse
          root = {}
          current = root
          loop do
            skip_blank
            break if @s.eos?

            if @s.scan(/\[\[/)
              path = parse_key_path
              expect(']]')
              current = open_array_table(root, path)
            elsif @s.scan(/\[/)
              path = parse_key_path
              expect(']')
              current = open_table(root, path)
            else
              path = parse_key_path
              expect('=')
              skip_inline_space
              assign(current, path, parse_value)
            end
            end_of_line
          end
          root
        end

        private

        def bail!(message)
          consumed = @source.byteslice(0, @s.pos).to_s
          raise ParseError.new(message, consumed.count("\n") + 1)
        end

        def skip_blank
          @s.skip(/(?:[ \t\n]+|#[^\n]*)+/)
        end

        def skip_inline_space
          @s.skip(/[ \t]+/)
        end

        def expect(token)
          skip_inline_space
          bail!("'#{token}' attendu") unless @s.scan(/#{Regexp.escape(token)}/)
        end

        def end_of_line
          skip_inline_space
          @s.skip(/#[^\n]*/)
          return if @s.eos? || @s.scan(/\n/)

          bail!('fin de ligne attendue')
        end

        def parse_key_path
          parts = []
          loop do
            skip_inline_space
            parts << parse_key_part
            skip_inline_space
            break unless @s.scan(/\./)
          end
          parts
        end

        def parse_key_part
          if @s.check(/"/)
            parse_basic_string
          elsif @s.check(/'/)
            parse_literal_string
          else
            key = @s.scan(BARE_KEY)
            bail!('clé attendue') unless key
            key
          end
        end

        def parse_value
          case @s.peek(1)
          when '"' then parse_basic_string
          when "'" then parse_literal_string
          when '[' then parse_array
          when '{' then parse_inline_table
          else parse_scalar
          end
        end

        def parse_basic_string
          bail!('chaîne multiligne non supportée') if @s.check(/"""/)
          @s.getch
          out = +''
          loop do
            char = @s.getch
            bail!('chaîne non fermée') if char.nil? || char == "\n"
            return out if char == '"'

            if char == '\\'
              out << parse_escape
            else
              out << char
            end
          end
        end

        def parse_escape
          code = @s.getch
          case code
          when 'n' then "\n"
          when 't' then "\t"
          when 'r' then "\r"
          when 'b' then "\b"
          when 'f' then "\f"
          when '"' then '"'
          when '\\' then '\\'
          when 'u'
            hex = @s.scan(/[0-9a-fA-F]{4}/)
            bail!('séquence \\u invalide') unless hex
            [hex.hex].pack('U')
          when 'U'
            hex = @s.scan(/[0-9a-fA-F]{8}/)
            bail!('séquence \\U invalide') unless hex
            [hex.hex].pack('U')
          else
            bail!("séquence d'échappement invalide")
          end
        end

        def parse_literal_string
          bail!('chaîne multiligne non supportée') if @s.check(/'''/)
          literal = @s.scan(/'[^'\n]*'/)
          bail!('chaîne littérale non fermée') unless literal
          literal[1..-2]
        end

        def parse_scalar
          return true if @s.scan(/true(?![\w-])/)
          return false if @s.scan(/false(?![\w-])/)

          number = @s.scan(NUMBER)
          bail!('valeur non supportée') unless number
          clean = number.delete('_')
          clean.match?(/[.eE]/) ? clean.to_f : clean.to_i
        end

        def parse_array
          @s.getch
          items = []
          loop do
            skip_blank
            bail!('tableau non fermé') if @s.eos?
            return items if @s.scan(/\]/)

            items << parse_value
            skip_blank
            next if @s.scan(/,/)
            return items if @s.scan(/\]/)

            bail!("',' ou ']' attendu dans le tableau")
          end
        end

        def parse_inline_table
          @s.getch
          table = {}
          loop do
            skip_blank
            bail!('table inline non fermée') if @s.eos?
            return table if @s.scan(/\}/)

            path = parse_key_path
            expect('=')
            skip_blank
            assign(table, path, parse_value)
            skip_blank
            next if @s.scan(/,/)
            return table if @s.scan(/\}/)

            bail!("',' ou '}' attendu dans la table inline")
          end
        end

        def assign(table, path, value)
          node = table
          path[0...-1].each do |part|
            node[part] = {} unless node.key?(part)
            bail!("'#{part}' n'est pas une table") unless node[part].is_a?(Hash)
            node = node[part]
          end
          key = path.last
          bail!("clé dupliquée : #{path.join('.')}") if node.key?(key)
          node[key] = value
        end

        def walk(root, path)
          node = root
          path.each do |part|
            child = node[part]
            if child.nil?
              child = {}
              node[part] = child
            elsif child.is_a?(Array)
              child = child.last
              bail!("'#{part}' n'est pas une table") unless child.is_a?(Hash)
            elsif !child.is_a?(Hash)
              bail!("'#{part}' n'est pas une table")
            end
            node = child
          end
          node
        end

        def open_table(root, path)
          bail!("table dupliquée : [#{path.join('.')}]") if @defined_tables.include?(path)
          @defined_tables << path
          walk(root, path)
        end

        def open_array_table(root, path)
          parent = walk(root, path[0...-1])
          key = path.last
          list = parent[key]
          if list.nil?
            list = []
            parent[key] = list
          end
          bail!("'#{key}' n'est pas un tableau de tables") unless list.is_a?(Array)
          @defined_tables.delete_if { |known| known.length > path.length && known[0, path.length] == path }
          table = {}
          list << table
          table
        end
      end

      def self.parse(text)
        Parser.new(text).parse
      end
    end

    # Audit du fichier de blocage (v6.1.1) : en flux, sans stocker ni afficher
    # les entrées (numéros de ligne et raisons seuls). Grammaire APPROCHÉE :
    # ne prouve pas que dnscrypt-proxy charge chaque règle.
    module DNSCryptBlocklist
      MAX_BYTES = 64 * 1024 * 1024
      MAX_LINES = 2_000_000
      MAX_INVALID_SAMPLES = 5
      LABEL = /\A[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\z/i.freeze
      PATTERN_CHARS = /\A[a-z0-9_.\-*?\[\]^!]+\z/i.freeze
      HOSTS_LINE = /\A\d{1,3}(?:\.\d{1,3}){3}\s+\S/.freeze
      SOURCE_MARKER = /\A\s*#+\s*Blocklist from\s+(.+?)\s*#+\s*\z/i.freeze

      module_function

      # Marqueurs de provenance déclarée, pas de fraîcheur ni de téléchargement prouvé.
      def source_marker(raw)
        match = raw.to_s.chomp.match(SOURCE_MARKER)
        match && match[1].to_s.strip
      end

      def source_age_days(mtime, now = Time.now)
        modified = mtime.is_a?(Time) ? mtime : Time.parse(mtime.to_s)
        delta = now - modified
        delta.negative? ? nil : (delta / 86_400).floor
      rescue StandardError
        nil
      end


      # Retourne [statut, détail, clé] :
      #   [:blank, nil, nil] | [:comment, nil, nil]
      #   [:valid, :domain|:exact|:pattern, clé_normalisée]
      #   [:invalid, raison, nil]
      def classify(raw)
        line = raw.strip
        return [:blank, nil, nil] if line.empty?
        return [:comment, nil, nil] if line.start_with?('#')
        return [:invalid, :hosts_format, nil] if line.match?(HOSTS_LINE)

        line = line.sub(/\s+#.*\z/, '')
        parts = line.split('@', -1)
        return [:invalid, :syntax, nil] if parts.length > 2

        name = parts[0].to_s.strip
        schedule = parts[1] && parts[1].strip
        return [:invalid, :syntax, nil] if name.empty? || (schedule && schedule.empty?)

        exact = name.start_with?('=')
        body = exact ? name[1..-1].to_s : name
        return [:invalid, :bad_label, nil] if body.empty? || body.length > 253

        if exact || !body.match?(/[*?\[]/)
          body.chomp('.').split('.', -1).each do |label|
            return [:invalid, :bad_label, nil] unless label.length <= 63 && label.match?(LABEL)
          end
          genre = exact ? :exact : :domain
        else
          return [:invalid, :bad_charset, nil] unless body.match?(PATTERN_CHARS)

          genre = :pattern
        end

        key = "#{exact ? '=' : ''}#{body.downcase}"
        key = "#{key}@#{schedule.downcase}" if schedule
        [:valid, genre, key]
      end

      def audit(path, max_bytes: MAX_BYTES)
        return { status: :not_configured } if path.nil? || path.to_s.empty?
        return { status: :not_found, path: path } unless File.file?(path)
        return { status: :not_readable, path: path } unless File.readable?(path)

        stat = File.stat(path)
        base = { path: path, bytes: stat.size, mtime: stat.mtime.iso8601 }
        return base.merge(status: :too_large) if stat.size > max_bytes

        total = blank = comments = valid = invalid = duplicates = 0
        truncated = false
        kinds = Hash.new(0)
        reasons = Hash.new(0)
        samples = []
        hidden = Hash.new(0)
        source_sections = []
        source_redundancy = Hash.new(0)
        seen = Set.new

        note_invalid = lambda do |line_no, reason|
          invalid += 1
          reasons[reason] += 1
          samples << [line_no, reason] if samples.length < MAX_INVALID_SAMPLES
        end

        File.open(path, 'r:UTF-8') do |file|
          file.each_line do |raw|
            if total >= MAX_LINES
              truncated = true
              break
            end
            total += 1

            unless raw.valid_encoding?
              note_invalid.call(total, :encoding)
              next
            end
            if total == 1 && raw.start_with?("\uFEFF")
              hidden[:bom] += 1
              raw = raw.sub(/\A\uFEFF/, '')
            end
            hidden[:crlf] += 1 if raw.include?("\r")
            hidden[:nbsp] += 1 if raw.match?(/[\u00A0\u200B-\u200D\u2060\uFEFF]/)
            hidden[:control] += 1 if raw.match?(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/)
            hidden[:trailing_space] += 1 if raw.chomp.match?(/[ \t]+\z/)

            marker = source_marker(raw)
            source_sections << marker if marker && !marker.empty?
            if (match = raw.match(/^\s*#\s*Ignored duplicates:\s*(\d+)/i))
              source_redundancy[:ignored_duplicates] += match[1].to_i
            elsif (match = raw.match(/^\s*#\s*Ignored due to overlapping local patterns:\s*(\d+)/i))
              source_redundancy[:overlapping_patterns] += match[1].to_i
            elsif (match = raw.match(/^\s*#\s*Ignored entries due to the allowlist:\s*(\d+)/i))
              source_redundancy[:allowlist_excluded] += match[1].to_i
            end

            status, detail, key = classify(raw)
            case status
            when :blank then blank += 1
            when :comment then comments += 1
            when :invalid then note_invalid.call(total, detail)
            else
              valid += 1
              kinds[detail] += 1
              duplicates += 1 unless seen.add?(key)
            end
          end
        end

        base.merge(
          status: :ok,
          truncated: truncated,
          total_lines: total,
          blank: blank,
          comments: comments,
          candidates: valid + invalid,
          valid: valid,
          unique_valid: seen.size,
          duplicates: duplicates,
          invalid: invalid,
          invalid_by_reason: reasons,
          invalid_samples: samples,
          hidden_chars: hidden,
          kinds: kinds,
          provenance: {
            source_sections: source_sections.length,
            sources: source_sections.uniq,
            age_days: source_age_days(stat.mtime),
            source_redundancy: source_redundancy
          }
        )
      rescue Errno::EACCES
        { status: :not_readable, path: path }
      rescue StandardError => e
        Logger.warn("Audit du fichier de blocage : #{e.class}")
        { status: :error, path: path }
      end
    end

    module DNSCryptConfigAudit
      CACHE_FILE = File.join(Config::CACHE_DIR, 'dnscrypt_config_audit.json').freeze
      CONFIG_PATHS = [
        '/usr/local/etc/dnscrypt-proxy.toml',
        '/opt/homebrew/etc/dnscrypt-proxy.toml'
      ].freeze
      MAX_CONFIG_BYTES = 1_048_576
      BLOCKLIST_STATUS_LABELS = {
        'not_found' => 'introuvable',
        'not_readable' => 'illisible sans privilège',
        'too_large' => 'trop volumineux ; audit ignoré',
        'error' => 'erreur de lecture',
        'not_configured' => 'non configuré',
        'skipped' => 'non analysé'
      }.freeze
      HIDDEN_LABELS = {
        bom: 'BOM UTF-8',
        crlf: 'fins de ligne CR/CRLF',
        nbsp: 'espaces insécables / largeur nulle',
        control: 'caractères de contrôle',
        trailing_space: 'espaces en fin de ligne'
      }.freeze
      REASON_LABELS = {
        hosts_format: 'format hosts',
        bad_label: 'nom invalide',
        bad_charset: 'caractères invalides',
        syntax: 'syntaxe',
        encoding: 'encodage'
      }.freeze

      module_function

      def section(node, *keys)
        keys.each do |key|
          return nil unless node.is_a?(Hash)

          node = node[key]
        end
        node.is_a?(Hash) ? node : nil
      end

      def string_list(value)
        return nil unless value.is_a?(Array) && value.all? { |item| item.is_a?(String) }

        value
      end

      def parse_routes(value, issues)
        return [] if value.nil?

        unless value.is_a?(Array)
          issues << 'routes : tableau attendu'
          return []
        end

        routes = []
        value.each_with_index do |entry, index|
          name = entry.is_a?(Hash) ? entry['server_name'] : nil
          via = entry.is_a?(Hash) ? string_list(entry['via']) : nil
          if name.is_a?(String) && via
            routes << { server_name: name, via: via }
          else
            issues << "route n°#{index + 1} : server_name/via invalides"
          end
        end
        routes
      end

      def dnscry_source_active?(doc)
        sources = section(doc, 'sources')
        return false unless sources

        sources.any? do |name, conf|
          next false unless conf.is_a?(Hash)

          urls = conf['urls'].is_a?(Array) ? conf['urls'] : []
          name.to_s.match?(/dnscry/i) || urls.any? { |url| url.to_s.match?(/dnscry\.pt/i) }
        end
      end

      def parse_config(text, config_path = nil, audit_blocklist: true)
        begin
          doc = MiniToml.parse(text)
        rescue MiniToml::ParseError => e
          return { status: :parse_error, config_path: config_path, parse_error: e.message }
        end

        issues = []

        raw_servers = doc['server_names']
        servers = string_list(raw_servers)
        issues << 'server_names : tableau de chaînes attendu' if raw_servers && servers.nil?
        servers ||= []

        raw_strategy = doc['lb_strategy']
        strategy = raw_strategy.is_a?(String) ? raw_strategy : nil
        issues << 'lb_strategy : chaîne attendue' if raw_strategy && strategy.nil?

        anonymized = section(doc, 'anonymized_dns')
        routes = parse_routes(anonymized && anonymized['routes'], issues)

        listen = string_list(doc['listen_addresses'])
        blocked = section(doc, 'blocked_names')
        log_raw = blocked && blocked['log_file']
        log_raw = nil unless log_raw.is_a?(String) && !log_raw.empty?
        log_file = log_raw && config_path ? File.expand_path(log_raw, File.dirname(config_path)) : log_raw
        file_raw = blocked && blocked['blocked_names_file']
        file_raw = nil unless file_raw.is_a?(String) && !file_raw.empty?
        blocked_file = if file_raw && config_path
                         File.expand_path(file_raw, File.dirname(config_path))
                       else
                         file_raw
                       end
        blocklist = if blocked_file.nil?
                      { status: :not_configured }
                    elsif audit_blocklist
                      DNSCryptBlocklist.audit(blocked_file)
                    else
                      { status: :skipped, path: blocked_file }
                    end

        {
          status: :ok,
          config_path: config_path,
          server_names: servers,
          lb_strategy: strategy,
          anonymized_routes: routes,
          dnscry_pt_source_active: dnscry_source_active?(doc),
          blocked_names_section_active: !blocked.nil?,
          blocked_names_file: blocked_file,
          blocked_log_file: log_file,
          listen_addresses: listen || [],
          blocklist: blocklist,
          issues: issues
        }
      end

      def locate_config
        CONFIG_PATHS.find { |path| File.file?(path) }
      end

      # Indices de lancement via ps ; absence d'argument -config ≠ fichier par
      # défaut prouvé (wrapper possible).
      def runtime_process_evidence(command_output = nil)
        output = command_output
        if output.nil?
          result = Infrastructure::CommandExecutor.safe_run('ps', '-axo', 'pid=,command=', timeout: Config::TIMEOUT_FAST)
          output = result[:stdout].to_s
        end
        processes = output.to_s.lines.each_with_object([]) do |line, found|
          match = line.strip.match(/\A(\d+)\s+(.+)\z/)
          next unless match
          command = match[2]
          next unless File.basename(command.split(/\s+/, 2).first.to_s).match?(/\Adnscrypt-proxy\z/i)

          args = begin
            Shellwords.split(command)
          rescue ArgumentError
            []
          end
          config = nil
          args.each_with_index do |arg, index|
            if %w[-config --config].include?(arg)
              config = args[index + 1] if args[index + 1] && !args[index + 1].start_with?('-')
              break
            elsif arg.start_with?('-config=', '--config=')
              config = arg.split('=', 2)[1]
              break
            end
          end
          found << { pid: match[1].to_i, config_path: config }
        end
        explicit = processes.map { |item| item[:config_path] }.compact.uniq
        { status: :ok, process_count: processes.length,
          pids: processes.map { |item| item[:pid] }, explicit_config_paths: explicit,
          config_argument_visible: !explicit.empty? }
      rescue StandardError => e
        Logger.warn("Détection runtime DNSCrypt : #{e.class}")
        { status: :unavailable, process_count: nil, pids: [], explicit_config_paths: [], config_argument_visible: false }
      end

      def run!
        path = locate_config
        return { status: :not_found, checked_at: Time.now.iso8601 } unless path

        stat = File.stat(path)
        return { status: :too_large, config_path: path, checked_at: Time.now.iso8601 } if stat.size > MAX_CONFIG_BYTES
        return { status: :not_readable, config_path: path, checked_at: Time.now.iso8601 } unless File.readable?(path)

        parsed = parse_config(File.read(path), path)
        parsed.merge(checked_at: Time.now.iso8601,
                     runtime_process: runtime_process_evidence)
      rescue Errno::EACCES
        { status: :not_readable, config_path: path, checked_at: Time.now.iso8601 }
      rescue StandardError => e
        Logger.warn("Audit DNSCrypt en lecture seule : #{e.class}")
        { status: :error, config_path: path, checked_at: Time.now.iso8601 }
      end

      def fmt_int(value)
        value.to_i.to_s.reverse.scan(/\d{1,3}/).join(' ').reverse
      end

      def fmt_size(bytes)
        megabytes = bytes.to_f / 1_048_576
        megabytes >= 0.1 ? format('%.1f Mo', megabytes).tr('.', ',') : format('%d o', bytes.to_i)
      end

      def blocklist_lines(blocklist)
        return ['-- Blocage local : section active • fichier non analysé'] unless blocklist.is_a?(Hash)

        get = ->(key) { blocklist.key?(key) ? blocklist[key] : blocklist[key.to_s] }
        status = get.call(:status).to_s
        lines = []

        unless status == 'ok'
          lines << "-- Blocage local : section active • fichier #{BLOCKLIST_STATUS_LABELS.fetch(status, status)}"
          lines << "-- Fichier de blocage : #{get.call(:path)}" if get.call(:path)
          return lines
        end

        lines << '-- Blocage local : section active • fichier lisible'
        lines << "-- Fichier : #{get.call(:path)} • #{fmt_size(get.call(:bytes))} • modifié #{get.call(:mtime)}"
        lines << "-- Lignes : #{fmt_int(get.call(:total_lines))} au total • #{fmt_int(get.call(:candidates))} entrées" \
                 " • #{fmt_int(get.call(:comments))} commentaires • #{fmt_int(get.call(:blank))} vides"
        lines << "-- Entrées valides : #{fmt_int(get.call(:unique_valid))} uniques • " \
                 "#{fmt_int(get.call(:duplicates))} doublon(s) (#{fmt_int(get.call(:valid))} au total)"

        provenance = get.call(:provenance)
        if provenance.is_a?(Hash)
          source_count = (provenance[:source_sections] || provenance['source_sections']).to_i
          age_days = provenance[:age_days] || provenance['age_days']
          age_label = age_days.nil? ? 'âge indisponible' : "âge du fichier : #{fmt_int(age_days)} j"
          lines << "-- Provenance : #{source_count} section(s) source • #{age_label}"
          redundancy = provenance[:source_redundancy] || provenance['source_redundancy'] || {}
          dupes = redundancy[:ignored_duplicates] || redundancy['ignored_duplicates'] || 0
          overlaps = redundancy[:overlapping_patterns] || redundancy['overlapping_patterns'] || 0
          allowlisted = redundancy[:allowlist_excluded] || redundancy['allowlist_excluded'] || 0
          lines << "-- Redondance déclarée : #{fmt_int(dupes)} doublon(s) ignoré(s) • #{fmt_int(overlaps)} chevauchement(s) • #{fmt_int(allowlisted)} entrée(s) allowlist écartée(s)"
          sources = Array(provenance[:sources] || provenance['sources'])
          if sources.empty?
            lines << '-- Sources : aucun marqueur « Blocklist from … » détecté'
          else
            sources.first(5).each do |source|
              safe_source = source.to_s.gsub(/[\r\n\t]/, ' ')[0, 100]
              lines << "-- Source : #{safe_source}"
            end
            lines << "-- … et #{fmt_int(sources.length - 5)} autre(s)" if sources.length > 5
          end
        else
          lines << '-- Provenance : marqueurs de source non analysés'
        end

        invalid = get.call(:invalid).to_i
        if invalid.zero?
          lines << '-- Entrées invalides : 0'
        else
          reasons = get.call(:invalid_by_reason) || {}
          detail = reasons.map { |reason, count| "#{REASON_LABELS.fetch(reason.to_sym, reason)} ×#{count}" }.join(', ')
          lines << "-- Entrées invalides : #{fmt_int(invalid)} (#{detail})"
          samples = Array(get.call(:invalid_samples)).map do |line_no, reason|
            "l.#{line_no} (#{REASON_LABELS.fetch(reason.to_sym, reason)})"
          end
          lines << "-- Lignes à vérifier : #{samples.join(', ')}" unless samples.empty?
        end

        hidden = (get.call(:hidden_chars) || {}).map { |kind, count| [kind.to_sym, count.to_i] }.select { |_, count| count.positive? }
        unless hidden.empty?
          detail = hidden.map { |kind, count| "#{HIDDEN_LABELS.fetch(kind, kind)} ×#{fmt_int(count)}" }.join(', ')
          lines << "-- Caractères cachés (informatif) : #{detail}"
        end

        lines << "-- Analyse tronquée à #{fmt_int(DNSCryptBlocklist::MAX_LINES)} lignes" if get.call(:truncated)
        lines << '-- Validité selon une grammaire approchée ; chargement réel par dnscrypt-proxy non prouvé'
        lines
      end

      def menu_lines(data)
        return ['-- DNSCrypt : audit non effectué (action manuelle)'] unless data.is_a?(Hash)

        case data[:status] || data['status']
        when :not_found, 'not_found'
          return ['-- DNSCrypt : configuration Homebrew introuvable']
        when :not_readable, 'not_readable'
          return ['-- DNSCrypt : configuration présente mais illisible sans privilège']
        when :too_large, 'too_large'
          return ['-- DNSCrypt : fichier trop volumineux ; audit ignoré']
        when :error, 'error'
          return ['-- DNSCrypt : audit en erreur ; aucune conclusion']
        when :parse_error, 'parse_error'
          return [
            '-- DNSCrypt : configuration non analysable ; aucune conclusion',
            "-- Détail TOML : #{data[:parse_error] || data['parse_error']}",
            '-- Audit manuel • aucun changement • aucun effet sur le score'
          ]
        end

        get = ->(key) { data.key?(key) ? data[key] : data[key.to_s] }
        lines = ["-- DNSCrypt — audit en lecture seule • #{get.call(:checked_at) || 'date inconnue'}"]
        config_path = get.call(:config_path)
        lines << "-- Configuration déclarée : #{config_path || 'chemin inconnu'}"

        runtime = get.call(:runtime_process) || {}
        runtime_get = ->(key) { runtime.key?(key) ? runtime[key] : runtime[key.to_s] }
        case runtime_get.call(:status).to_s
        when 'ok'
          count = runtime_get.call(:process_count).to_i
          pids = Array(runtime_get.call(:pids))
          lines << "-- Processus dnscrypt-proxy : #{count.positive? ? "détecté • PID #{pids.join(', ')}" : 'non détecté par ps'}"
          explicit = Array(runtime_get.call(:explicit_config_paths))
          if explicit.empty?
            lines << '-- Configuration runtime : argument -config non visible ; fichier effectivement chargé indéterminé'
          else
            explicit.each do |runtime_path|
              relation = config_path && File.expand_path(runtime_path) == File.expand_path(config_path) ? 'identique au fichier audité' : 'DIFFÉRENT du fichier audité'
              lines << "-- Configuration runtime (argument du processus) : #{runtime_path} • #{relation}"
            end
          end
        else
          lines << '-- Processus dnscrypt-proxy : information runtime indisponible'
        end

        servers = Array(get.call(:server_names))
        lines << "-- Serveurs déclarés : #{servers.empty? ? 'non lus / absents' : servers.join(', ')}"
        strategy = get.call(:lb_strategy)
        lines << "-- Load balancing : #{strategy || 'non configuré / non lu'}"

        routes = Array(get.call(:anonymized_routes))
        if routes.empty?
          lines << '-- Routes anonymisées : aucune route active lue'
        else
          routes.each do |route|
            name = route[:server_name] || route['server_name'] || 'serveur inconnu'
            via = Array(route[:via] || route['via'])
            lines << "-- Route #{name} via : #{via.empty? ? 'aucun relais lu' : via.join(', ')}"
          end
        end

        lines << "-- DNSCry.pt : source #{get.call(:dnscry_pt_source_active) ? 'active' : 'désactivée / absente'}"
        if get.call(:blocked_names_section_active)
          lines.concat(blocklist_lines(get.call(:blocklist)))
        else
          lines << '-- Blocage local : section [blocked_names] non détectée'
        end

        Array(get.call(:issues)).first(5).each do |issue|
          lines << "-- ⚠️ Point d'attention : #{issue}"
        end

        lines << '-- Limite : configuration déclarée seulement ; usage macOS, chaînage et chiffrement amont non prouvés'
        lines << '-- Audit manuel • aucun changement • aucun effet sur le score'
        lines
      end
    end

    # Sonde manuelle du blocage DNSCrypt (v6.1.2) : lecture seule, aucun nom
    # de domaine affiché/écrit ; seuls les numéros de ligne sont conservés.
    module DNSCryptBlockProbe
      CACHE_FILE = File.join(Config::CACHE_DIR, 'dnscrypt_block_probe.json').freeze
      SAMPLE_SIZE = 8
      CONTROL_DOMAIN = 'example.com'
      DEFAULT_HOST = '127.0.0.1'
      DEFAULT_PORT = 53
      BLOCKED = %i[blocked_hinfo blocked_null_ip].freeze
      OUTCOME_LABELS = {
        blocked_hinfo: 'bloquée (réponse HINFO locale)',
        blocked_null_ip: 'bloquée (adresse nulle)',
        refused: 'REFUSED (compatible avec un blocage, non prouvé)',
        resolved: 'résolue (adresse réelle)',
        nxdomain: 'NXDOMAIN (non concluant)',
        empty: 'NOERROR sans adresse (non concluant)',
        servfail: 'SERVFAIL (non concluant)',
        dns_error: 'erreur DNS (non concluante)',
        timeout: 'délai dépassé',
        no_answer: 'aucune réponse'
      }.freeze
      VERDICT_LINES = {
        blocking_observed: 'Blocage observé : toutes les entrées échantillonnées sont bloquées ou refusées',
        blocking_not_observed: 'Blocage NON observé : aucune entrée échantillonnée n\'est bloquée et au moins une se résout normalement',
        partial: 'Résultat partiel : seules certaines entrées échantillonnées sont bloquées',
        inconclusive: 'Résultat non concluant : réponses ni bloquées ni clairement résolues',
        control_failed: 'Témoin neutre sans adresse : résolveur injoignable ou muet, aucune conclusion',
        no_sample: 'Aucune entrée « domaine » simple exploitable dans le fichier : aucune conclusion'
      }.freeze

      module_function

      def null_address?(value)
        value.to_s == '0.0.0.0' || value.to_s.match?(/\A[0:]+\z/)
      end

      # Classe une réponse dig (+noall +comments +answer). Le motif est stable,
      # sans jamais conserver le nom interrogé.
      def classify_response(text)
        source = text.to_s
        parsed = Infrastructure::PortProcessResolver.parse_dig_result(source)
        answer_lines = source.each_line.select { |line| line.match?(/\sIN\s+(?:A|AAAA|HINFO)\s/) }
        hinfo = answer_lines.any? { |line| line.match?(/\sIN\s+HINFO\s/) }
        addresses = answer_lines.map do |line|
          fields = line.split
          fields[-1] if fields.length >= 5 && %w[A AAAA].include?(fields[-2])
        end.compact

        outcome = case parsed[:outcome]
                  when :timeout then :timeout
                  when :no_response then :no_answer
                  when :refused then :refused
                  when :servfail then :servfail
                  when :dns_error then parsed[:status] == 'NXDOMAIN' ? :nxdomain : :dns_error
                  when :noerror
                    if hinfo then :blocked_hinfo
                    elsif addresses.empty? then :empty
                    elsif addresses.all? { |address| null_address?(address) } then :blocked_null_ip
                    else :resolved
                    end
                  else :no_answer
                  end
        { outcome: outcome, query_time_ms: parsed[:query_time_ms] }
      rescue StandardError
        { outcome: :no_answer, query_time_ms: nil }
      end

      # Échantillon déterministe (réservoir à graine fixe) d'entrées « domaine »
      # simples ; retourne [numéro_de_ligne, nom], noms en mémoire.
      def sample_entries(path, size: SAMPLE_SIZE)
        stat = File.stat(path)
        rng = Random.new(stat.size ^ stat.mtime.to_i)
        reservoir = []
        seen = Set.new
        eligible = 0
        line_no = 0
        File.open(path, 'r:UTF-8') do |file|
          file.each_line do |raw|
            break if line_no >= DNSCryptBlocklist::MAX_LINES

            line_no += 1
            next unless raw.valid_encoding?

            raw = raw.sub(/\A\uFEFF/, '') if line_no == 1
            status, genre, key = DNSCryptBlocklist.classify(raw)
            next unless status == :valid && genre == :domain && !key.include?('@')

            name = key.chomp('.')
            next unless name.include?('.') && seen.add?(name)

            eligible += 1
            if reservoir.length < size
              reservoir << [line_no, name]
            else
              slot = rng.rand(eligible)
              reservoir[slot] = [line_no, name] if slot < size
            end
          end
        end
        { entries: reservoir.sort_by(&:first), eligible: eligible }
      end

      def default_runner
        lambda do |host, port, name|
          Infrastructure::CommandExecutor.run(*Infrastructure::NetEndpoint.dig_command(host, port, name),
                                              timeout: 2.8)
        end
      end

      def verdict(results, control)
        return :control_failed unless control && control[:outcome] == :resolved
        return :no_sample if results.empty?

        blocked = results.count { |item| BLOCKED.include?(item[:outcome]) || item[:outcome] == :refused }
        resolved = results.count { |item| item[:outcome] == :resolved }
        return :blocking_observed if blocked == results.length
        return :blocking_not_observed if blocked.zero? && resolved.positive?
        return :partial if blocked.positive?

        :inconclusive
      end

      def file_facts(path)
        return nil unless path.is_a?(String) && File.file?(path)

        stat = File.stat(path)
        { bytes: stat.size, mtime: stat.mtime.iso8601 }
      rescue StandardError
        nil
      end

      # host/port : endpoint DNSCrypt ; runner : injectable pour les tests.
      def evaluate(blocklist_path, host: DEFAULT_HOST, port: DEFAULT_PORT, runner: nil, log_path: nil)
        runner ||= default_runner
        base = { tested_at: Time.now.iso8601, host: host, port: port, score_impact: 0,
                 blocklist_path: blocklist_path, blocklist_facts: file_facts(blocklist_path) }
        unless blocklist_path.is_a?(String) && File.file?(blocklist_path) && File.readable?(blocklist_path)
          return base.merge(status: :no_blocklist, verdict: :no_sample, results: [], eligible: 0)
        end

        sampled = sample_entries(blocklist_path)
        probe = lambda do |name|
          response = runner.call(host, port, name)
          classify_response(response[:stdout].to_s + "\n" + response[:stderr].to_s)
        end
        control = probe.call(CONTROL_DOMAIN)
        results = sampled[:entries].map do |line_no, name|
          probe.call(name).merge(line: line_no)
        end
        base.merge(
          status: :ok, control: control, results: results, eligible: sampled[:eligible],
          verdict: verdict(results, control), block_log: file_facts(log_path)
        )
      rescue StandardError => e
        Logger.warn("Sonde de blocage DNSCrypt : #{e.class}")
        base.merge(status: :error, verdict: :inconclusive, results: [], eligible: 0)
      end

      def run!
        path = DNSCryptConfigAudit.locate_config
        return { status: :no_config, tested_at: Time.now.iso8601, results: [] } unless path

        parsed = DNSCryptConfigAudit.parse_config(File.read(path), path, audit_blocklist: false)
        return { status: :parse_error, tested_at: Time.now.iso8601, results: [] } unless parsed[:status] == :ok

        # split_host_port gère IPv4, [ipv6]:port et IPv6 nu ; écoute explicite
        # 127.0.0.1:<port> seule retenue.
        endpoint = Array(parsed[:listen_addresses])
                   .map { |item| Infrastructure::NetEndpoint.split_host_port(item) }
                   .find { |host, port| host == '127.0.0.1' && port }
        endpoint = endpoint && endpoint.last
        data = evaluate(parsed[:blocked_names_file], port: (endpoint || DEFAULT_PORT).to_i,
                                                     log_path: parsed[:blocked_log_file])
        data[:config_path] = path
        Infrastructure::SecureDiskCache.write_json(CACHE_FILE, data)
        JSON.parse(JSON.generate(data))
      rescue StandardError => e
        Logger.warn("Sonde de blocage DNSCrypt (config) : #{e.class}")
        { status: :error, tested_at: Time.now.iso8601, results: [] }
      end

      def latest
        Infrastructure::SecureDiskCache.read_json(CACHE_FILE, ttl: 10 * 365 * 24 * 60 * 60)
      rescue StandardError
        nil
      end

      def menu_lines(data)
        return ['-- Blocage DNSCrypt : JAMAIS TESTÉ (action manuelle)'] unless data.is_a?(Hash)

        get = ->(key) { data.key?(key) ? data[key] : data[key.to_s] }
        case get.call(:status).to_s
        when 'no_config' then return ['-- Blocage DNSCrypt : configuration Homebrew introuvable']
        when 'parse_error' then return ['-- Blocage DNSCrypt : configuration non analysable ; aucune conclusion']
        when 'no_blocklist' then return ['-- Blocage DNSCrypt : aucun fichier de blocage lisible ; aucune conclusion']
        when 'error' then return ['-- Blocage DNSCrypt : sonde en erreur ; aucune conclusion']
        end

        lines = ["-- Sonde du blocage DNSCrypt • #{get.call(:tested_at) || 'date inconnue'} • #{get.call(:host)}:#{get.call(:port)}"]
        lines << "-- Configuration lue : #{get.call(:config_path)}" if get.call(:config_path)
        blocklist_path = get.call(:blocklist_path)
        lines << "-- Fichier effectivement sondé : #{blocklist_path || 'non déterminé'}"
        facts = get.call(:blocklist_facts)
        if facts.is_a?(Hash)
          bytes = facts[:bytes] || facts['bytes']
          mtime = facts[:mtime] || facts['mtime']
          lines << "-- Fichier sondé : #{DNSCryptConfigAudit.fmt_size(bytes)} • modifié #{mtime}"
        end
        control = get.call(:control) || {}
        control_outcome = (control[:outcome] || control['outcome']).to_s
        lines << "-- Témoin neutre : #{OUTCOME_LABELS.fetch(control_outcome.to_sym, control_outcome)}" unless control_outcome.empty?

        results = Array(get.call(:results))
        lines << "-- Échantillon : #{results.length} entrée(s) sur #{DNSCryptConfigAudit.fmt_int(get.call(:eligible))} éligibles (noms non affichés)"
        results.each do |item|
          outcome = (item[:outcome] || item['outcome']).to_s
          line_no = item[:line] || item['line']
          lines << "---- l.#{line_no} : #{OUTCOME_LABELS.fetch(outcome.to_sym, outcome)}"
        end

        unclear = results.count { |item| %w[nxdomain empty servfail dns_error timeout no_answer].include?((item[:outcome] || item['outcome']).to_s) }
        verdict_key = get.call(:verdict).to_s.to_sym
        lines << "-- #{get.call(:verdict).to_s.empty? ? 'Verdict absent' : VERDICT_LINES.fetch(verdict_key, verdict_key.to_s)}"

        facts = get.call(:block_log)
        if facts.is_a?(Hash)
          bytes = (facts[:bytes] || facts['bytes']).to_i
          mtime = facts[:mtime] || facts['mtime']
          lines << "-- Journal de blocage : #{DNSCryptConfigAudit.fmt_size(bytes)} • modifié #{mtime} (taille seulement, contenu non lu)"
        end

        if verdict_key == :blocking_not_observed
          lines << "-- #{unclear} entrée(s) non concluante(s) (NXDOMAIN, vide, délai) : probablement mortes ou filtrées en amont" if unclear.positive?
          lines << '-- À vérifier (causes non établies) : le PID qui écoute sur ce port est-il celui qui a chargé la liste (lsof) ?'
          lines << '-- À vérifier : redémarrage après modification, clé blocked_names_file de la bonne section, journal dnscrypt-proxy'
        end
        lines << '-- Limite : un blocage par IP personnalisée (blocked_query_response) n\'est pas distinguable d\'une résolution'
        lines << '-- Les requêtes d\'une entrée non bloquée partent vers le résolveur amont'
        lines << '-- Sonde manuelle • lecture seule • aucun effet sur le score'
        lines
      end
    end

    module ManualDNSProbe
      CACHE_FILE = File.join(Config::CACHE_DIR, 'dns_manual_probe.json').freeze
      RELAYS = [
        { name: 'DNSCrypt', host: '127.0.0.1', port: 53, process: /dnscrypt-proxy/i },
        { name: 'VPN Bypass', host: '127.0.0.1', port: 53530, process: /vpnbypass|com\.geiserx\.vpnbypass/i, optional: true, split: true }
      ].freeze

      module_function

      def catalina?
        result = Infrastructure::CommandExecutor.run('sw_vers', '-productVersion', timeout: 1.0)
        version = result[:stdout].to_s.strip
        version.start_with?('10.15')
      rescue StandardError
        false
      end

      def process_present?(pattern, ps_text)
        ps_text.to_s.each_line.any? { |line| line.match?(pattern) }
      end

      def listener_state(port, netstat_text)
        lines = netstat_text.to_s.each_line.to_a
        tcp = lines.any? { |line| line.match?(/^tcp\S*\s/) && line.match?(/(?:\.|:)#{Regexp.escape(port.to_s)}\s/) && line.include?('LISTEN') }
        udp = lines.any? { |line| line.match?(/^udp\S*\s/) && line.match?(/(?:\.|:)#{Regexp.escape(port.to_s)}\s/) }
        return :observed if tcp || udp
        :not_observed
      end

      # Ports loopback du résolveur par défaut depuis scutil --dns ; le port
      # détecté ne prouve ni propriétaire ni chaînage.
      def system_resolver_endpoints(scutil_text)
        snapshot = Struct.new(:scutil_dns).new(scutil_text.to_s)
        Infrastructure::AdvancedDNSResolver.new(snapshot).resolver_endpoints.select do |endpoint|
          endpoint[:default] && IPAddr.new(endpoint[:ip].to_s).loopback?
        rescue StandardError
          false
        end.uniq { |endpoint| [endpoint[:ip], endpoint[:port]] }
      rescue StandardError
        []
      end

      # Tous les endpoints annoncés par scutil --dns (défaut, domaines, interfaces).
      def scutil_endpoints(scutil_text)
        snapshot = Struct.new(:scutil_dns).new(scutil_text.to_s)
        Infrastructure::AdvancedDNSResolver.new(snapshot).resolver_endpoints
      rescue StandardError
        []
      end

      # nameserver[0] + port du résolveur par défaut (v6.1.9), détectés dynamiquement.
      def primary_system_endpoint(scutil_text)
        snapshot = Struct.new(:scutil_dns).new(scutil_text.to_s)
        Infrastructure::AdvancedDNSResolver.new(snapshot).primary_resolver_endpoint
      rescue StandardError
        nil
      end

      def domain_in_scope?(name, domains)
        host = name.to_s.downcase.chomp('.')
        Array(domains).any? do |domain|
          suffix = domain.to_s.downcase.chomp('.')
          !suffix.empty? && (host == suffix || host.end_with?(".#{suffix}"))
        end
      end

      # REFUSED d'un relais scoped/split pour un nom hors de ses domaines : c'est le
      # comportement attendu, pas une erreur bloquante. REFUSED dans un domaine
      # ciblé, ou sur un résolveur par défaut, reste une anomalie à expliquer.
      def refused_expected?(outcome, relay, endpoints, queried_name)
        return false unless outcome == :refused

        endpoint = Array(endpoints).find { |item| item[:ip] == relay[:host] && item[:port] == relay[:port] }
        domains = endpoint ? Array(endpoint[:domains]) : []
        scoped = endpoint ? (!endpoint[:default] && (!domains.empty? || !Array(endpoint[:ifaces]).empty?)) : false
        return false unless scoped || relay[:split] == true

        !domain_in_scope?(queried_name, domains)
      end

      def parse_probe(text)
        parsed = Infrastructure::PortProcessResolver.parse_dig_result(text)
        status = parsed[:status]
        addresses = text.to_s.each_line.map do |line|
          fields = line.split
          next unless fields.length >= 5 && %w[A AAAA].include?(fields[-2])
          value = fields[-1]
          value if value.match?(/\A(?:\d{1,3}\.){3}\d{1,3}\z|\A[0-9a-f:]+\z/i)
        end.compact.uniq
        parsed.merge(addresses: addresses, resolution: addresses.empty? ? :no_address : :address_obtained,
                     status: status || (parsed[:outcome] == :timeout ? 'TIMEOUT' : 'NO_RESPONSE'))
      rescue StandardError
        { status: 'ERROR', outcome: :error, addresses: [], resolution: :not_verified,
          query_time_ms: nil, encrypted_upstream: nil }
      end

      def run!
        ps = Infrastructure::CommandExecutor.run('ps', '-axo', 'pid,command', timeout: 1.5)[:stdout].to_s
        tcp = Infrastructure::CommandExecutor.run('netstat', '-anv', '-p', 'tcp', timeout: 1.5)[:stdout].to_s
        udp = Infrastructure::CommandExecutor.run('netstat', '-anv', '-p', 'udp', timeout: 1.5)[:stdout].to_s
        combined_netstat = tcp + "\n" + udp
        scutil = Infrastructure::CommandExecutor.run('scutil', '--dns', timeout: 1.5)[:stdout].to_s
        system_endpoints = system_resolver_endpoints(scutil)
        all_endpoints = scutil_endpoints(scutil)
        primary = primary_system_endpoint(scutil)
        results = []
        RELAYS.each do |relay|
          if relay[:optional] && catalina?
            results << { name: relay[:name], host: relay[:host], port: relay[:port], applicable: false,
                         process: :not_required, listener: :not_required, status: 'NON APPLICABLE (CATALINA)',
                         resolution: :not_required, addresses: [], chain: :not_demonstrated,
                         encrypted_upstream: :not_demonstrated }
            next
          end
          present = process_present?(relay[:process], ps)
          listener = listener_state(relay[:port], combined_netstat)
          command = Infrastructure::NetEndpoint.dig_command(relay[:host], relay[:port], 'www.iana.org')
          response = Infrastructure::CommandExecutor.run(*command, timeout: 2.8)
          parsed = parse_probe(response[:stdout].to_s + "\n" + response[:stderr].to_s)
          parsed[:status] = 'ERROR' if !response[:success] && parsed[:status] == 'NO_RESPONSE' && !response[:stderr].to_s.match?(/timeout/i)
          results << {
            name: relay[:name], host: relay[:host], port: relay[:port], applicable: true,
            process: present ? :detected : :absent,
            listener: listener, status: parsed[:status], outcome: parsed[:outcome],
            refused_expected: refused_expected?(parsed[:outcome], relay, all_endpoints, 'www.iana.org'),
            resolution: parsed[:resolution], addresses: parsed[:addresses],
            query_time_ms: parsed[:query_time_ms], chain: :not_demonstrated,
            encrypted_upstream: :not_demonstrated
          }
        end
        # Sonde en plus du port Viscosity configuré : celui réellement annoncé
        # comme résolveur loopback par défaut par macOS (scutil --dns).
        system_endpoints.each do |endpoint|
          next if RELAYS.any? { |relay| relay[:host] == endpoint[:ip] && relay[:port] == endpoint[:port] }
          port = endpoint[:port].to_i
          listener = listener_state(port, combined_netstat)
          command = Infrastructure::NetEndpoint.dig_command(endpoint[:ip], port, 'www.iana.org')
          response = Infrastructure::CommandExecutor.run(*command, timeout: 2.8)
          parsed = parse_probe(response[:stdout].to_s + "\n" + response[:stderr].to_s)
          parsed[:status] = 'ERROR' if !response[:success] && parsed[:status] == 'NO_RESPONSE' && !response[:stderr].to_s.match?(/timeout/i)
          results << {
            name: 'Résolveur système (défaut)', host: endpoint[:ip], port: port,
            applicable: true, role: :system_default, process: :not_attributed,
            primary: !primary.nil? && primary[:ip] == endpoint[:ip] && primary[:port] == port,
            listener: listener, status: parsed[:status], outcome: parsed[:outcome],
            resolution: parsed[:resolution], addresses: parsed[:addresses],
            query_time_ms: parsed[:query_time_ms], chain: :not_demonstrated,
            encrypted_upstream: :not_demonstrated
          }
        end
        data = { tested_at: Time.now.iso8601, domain: 'www.iana.org', relays: results,
                 system_resolvers: system_endpoints, primary_resolver: primary, viscosity_configured_port: nil,
                 score_impact: 0, chain_proof: false, encrypted_upstream_proof: false }
        Infrastructure::SecureDiskCache.write_json(CACHE_FILE, data)
        JSON.parse(JSON.generate(data))
      end

      def latest
        Infrastructure::SecureDiskCache.read_json(CACHE_FILE, ttl: 10 * 365 * 24 * 60 * 60)
      rescue StandardError
        nil
      end

      def menu_lines(data)
        return ['-- Relais DNS : JAMAIS TESTÉS'] unless data.is_a?(Hash) && data['relays'].is_a?(Array)
        lines = ["-- Dernier test : #{data['tested_at']} • www.iana.org"]
        endpoints = Array(data['system_resolvers'])
        if endpoints.empty?
          lines << "-- Résolveur système par défaut : port loopback non identifié (scutil --dns indisponible ou sans endpoint loopback)"
        else
          primary = data['primary_resolver'].is_a?(Hash) ? data['primary_resolver'] : {}
          endpoints.each do |endpoint|
            ip = endpoint['ip'] || endpoint[:ip]
            port = endpoint['port'] || endpoint[:port]
            main = !primary.empty? && primary['ip'] == ip && primary['port'].to_i == port.to_i
            lines << "-- Résolveur système par défaut : #{ip}:#{port} (scutil --dns#{main ? ', nameserver[0]' : ''})"
          end
        end
        lines << '-- Viscosity : aucun port DNS fixe supposé ; consulter les endpoints macOS ci-dessus'
        data['relays'].each do |relay|
          if relay['applicable'] == false
            lines << "-- #{relay['name']} : non applicable sur Catalina"
            next
          end
          proc_label = case relay['process'].to_s
                       when 'detected' then 'processus détecté'
                       when 'absent' then 'processus absent'
                       when 'not_attributed' then 'propriétaire non attribué'
                       else 'processus non déterminé'
                       end
          listen_label = relay['listener'].to_s == 'observed' ? 'écoute constatée' : 'écoute non constatée'
          addresses = Array(relay['addresses']).join(', ')
          resolution = relay['resolution'].to_s == 'address_obtained' ? "IP : #{addresses}" : 'aucune adresse obtenue'
          status_label = relay['refused_expected'] ? 'REFUSED attendu (relais scoped/split, domaine hors périmètre)' : relay['status']
          lines << "-- #{relay['name']} #{relay['host']}:#{relay['port']} : #{status_label} • #{relay['query_time_ms'] || '?'} ms"
          lines << "---- #{proc_label} • #{listen_label} • #{resolution}"
          lines << "---- Chaînage : non démontré • DNS chiffré amont : non démontré"
        end
        lines << '-- Sonde manuelle uniquement • aucun effet sur le score'
        lines
      end
    end

    # Audit DNS multicouche (v6.1.6), opt-in : observations indépendantes
    # (processus, extension, résolveurs) ; aucune ne prouve le chemin d'une requête.
    module DNSStackAudit
      LOCAL_SERVICES = %w[dnscrypt-proxy tor torsocks cloudflared spoofdpi].freeze

      module_function

      def process_observations(ps_text)
        text = ps_text.to_s
        {
          adguard: text.each_line.any? { |line| line.match?(/AdGuard/i) },
          viscosity: text.each_line.any? { |line| line.match?(/Viscosity/i) },
          dnscrypt: text.each_line.any? { |line| line.match?(/dnscrypt-proxy/i) }
        }
      rescue StandardError
        { adguard: nil, viscosity: nil, dnscrypt: nil }
      end

      # Services locaux (ps, nom d'exécutable) ; présence ≠ service utilisé.
      def local_service_observations(ps_text)
        names = ps_text.to_s.each_line.map do |line|
          match = line.match(/\A\s*\d+\s+(\S+)/)
          match && File.basename(match[1])
        end.compact
        LOCAL_SERVICES.each_with_object({}) { |service, memo| memo[service] = names.include?(service) }
      rescue StandardError
        {}
      end

      # Environnement d'exécution (Ruby système ou Homebrew) : information seule.
      def runtime_environment(ruby_path: RbConfig.ruby, path: ENV['PATH'])
        kind = if ruby_path.to_s.start_with?('/usr/bin/')
                 :system
               elsif ruby_path.to_s.match?(%r{\A/(?:opt/homebrew|usr/local)/})
                 :homebrew
               else
                 :other
               end
        { ruby_path: ruby_path.to_s, ruby_version: RUBY_VERSION, ruby_kind: kind,
          path_head: path.to_s.split(File::PATH_SEPARATOR).first(3) }
      rescue StandardError
        { ruby_path: nil, ruby_version: RUBY_VERSION, ruby_kind: :other, path_head: [] }
      end

      def same_ip?(first, second)
        IPAddr.new(first.to_s) == IPAddr.new(second.to_s)
      rescue StandardError
        first.to_s == second.to_s
      end

      # listen_addresses de dnscrypt-proxy (config lue en lecture seule, sans sudo).
      def dnscrypt_listen_config
        path = DNSCryptConfigAudit.locate_config
        return { status: :no_config, addresses: [] } unless path
        return { status: :too_large, addresses: [] } if File.size(path) > DNSCryptConfigAudit::MAX_CONFIG_BYTES
        return { status: :not_readable, addresses: [] } unless File.readable?(path)

        parsed = DNSCryptConfigAudit.parse_config(File.read(path), path, audit_blocklist: false)
        return { status: :parse_error, addresses: [] } unless parsed[:status] == :ok

        { status: :ok, config_path: path, addresses: Array(parsed[:listen_addresses]) }
      rescue StandardError
        { status: :error, addresses: [] }
      end

      # (hôte, port) dans les listen_addresses ? `localhost` = 127.0.0.1 ; port absent = 53.
      def config_listen_match?(endpoint, listen_addresses)
        Array(listen_addresses).any? do |entry|
          host, port = Infrastructure::NetEndpoint.split_host_port(entry)
          next false if host.nil?

          host = '127.0.0.1' if host.casecmp('localhost').zero?
          (port || 53) == endpoint[:port].to_i && same_ip?(host, endpoint[:ip])
        end
      end

      # Déduction (jamais une preuve) si lsof non-root n'attribue pas :
      # permission_limited / not_attributed / unavailable.
      def owner_deduction(endpoint, ownership, listen_addresses, dnscrypt_observed)
        return nil if ownership[:status] == :observed
        return nil unless Infrastructure::NetEndpoint.loopback_host?(endpoint[:ip])
        return nil unless config_listen_match?(endpoint, listen_addresses)

        { config_match: true, inferred_owner: (dnscrypt_observed == true ? 'dnscrypt-proxy' : nil) }
      end

      def primary_resolver(scutil_text)
        snapshot = Struct.new(:scutil_dns).new(scutil_text.to_s)
        Infrastructure::AdvancedDNSResolver.new(snapshot).primary_resolver_endpoint
      rescue StandardError
        nil
      end

      def extension_observation(extension_text)
        text = extension_text.to_s
        matching = text.each_line.select { |line| line.match?(/AdGuard/i) }
        return :not_listed if matching.empty?
        return :activated_enabled if matching.any? { |line| line.match?(/activated/i) && line.match?(/enabled/i) }
        return :listed_state_unknown if matching.any?
        :not_listed
      rescue StandardError
        :unknown
      end

      # Attribution opportuniste loopback via lsof, sans élévation ; sortie
      # vide/partielle ≠ absence de processus.
      def resolver_ownership(endpoints, lsof_result)
        sockets = if lsof_result.is_a?(Hash) && lsof_result[:success]
                    Infrastructure::PortProcessResolver.parse_lsof_network_sockets(lsof_result[:stdout])
                  else
                    []
                  end
        collection = Infrastructure::PortProcessResolver.lsof_collection_status(
          lsof_result, parsed_count: sockets.length
        )
        Array(endpoints).each_with_object({}) do |endpoint, memo|
          ip = endpoint[:ip].to_s
          next unless ip.start_with?('127.') || ip == '::1'
          port = endpoint[:port].to_i
          matches = sockets.select do |socket|
            socket[:local_port] == port &&
              (socket[:local_host].to_s.start_with?('127.') || socket[:local_host] == '::1')
          end
          memo[[ip, port]] = if !matches.empty?
            { status: :observed, owners: matches.map { |socket| { process: socket[:process], pid: socket[:pid], protocol: socket[:protocol] } }.uniq }
          elsif collection == :permission_limited
            { status: :permission_limited, owners: [] }
          elsif collection == :unavailable
            { status: :unavailable, owners: [] }
          else
            { status: :not_attributed, owners: [] }
          end
        end
      rescue StandardError
        {}
      end

      def resolver_observations(scutil_text, lsof_result: nil, listen_addresses: [], dnscrypt_observed: nil,
                                if_index_runner: nil)
        snapshot = Struct.new(:scutil_dns).new(scutil_text.to_s)
        endpoints = Infrastructure::AdvancedDNSResolver.new(snapshot, if_index_runner: if_index_runner).resolver_endpoints
        owners = resolver_ownership(endpoints, lsof_result)
        endpoints.map do |endpoint|
          ownership = owners[[endpoint[:ip], endpoint[:port]]] || { status: :unavailable, owners: [] }
          observation = {
            ip: endpoint[:ip], port: endpoint[:port], default: endpoint[:default],
            domains: Array(endpoint[:domains]), interfaces: Array(endpoint[:ifaces]),
            owner_status: ownership[:status], owners: ownership[:owners]
          }
          deduction = owner_deduction(endpoint, ownership, listen_addresses, dnscrypt_observed)
          deduction ? observation.merge(deduction) : observation
        end
      rescue StandardError
        []
      end

      def run!
        ps_result = Infrastructure::CommandExecutor.run('ps', '-axo', 'pid,command', timeout: 1.5)
        dns_result = Infrastructure::CommandExecutor.run('scutil', '--dns', timeout: 1.5)
        # systemextensionsctl peut être absent ou ne pas exposer AdGuard : échec = inconnu.
        ext_result = Infrastructure::CommandExecutor.run('systemextensionsctl', 'list', timeout: 2.0)
        # lsof non-root : attribution opportuniste uniquement, jamais de sudo.
        lsof_result = Infrastructure::CommandExecutor.run('/usr/sbin/lsof', '-nP', '-i', timeout: 1.5)
        # v6.1.9 : contexte indicatif, collectes bornées et en lecture seule.
        nwi_result = Infrastructure::CommandExecutor.run('scutil', '--nwi', timeout: 1.5)
        process_data = ps_result[:success] ? process_observations(ps_result[:stdout]) :
                       { adguard: nil, viscosity: nil, dnscrypt: nil }
        config = dnscrypt_listen_config
        {
          tested_at: Time.now.iso8601,
          processes: process_data,
          adguard_system_extension: ext_result[:success] ? extension_observation(ext_result[:stdout]) : :unknown,
          extension_command_available: !!ext_result[:success],
          resolvers: resolver_observations(dns_result[:stdout], lsof_result: lsof_result,
                                           listen_addresses: config[:addresses],
                                           dnscrypt_observed: process_data[:dnscrypt]),
          resolver_command_available: !!dns_result[:success],
          primary_resolver: primary_resolver(dns_result[:stdout]),
          dnscrypt_config: { status: config[:status], listen_addresses: config[:addresses] },
          network_context: nwi_result[:success] ? Infrastructure::NetworkInfo.parse_nwi(nwi_result[:stdout]) : nil,
          local_services: ps_result[:success] ? local_service_observations(ps_result[:stdout]) : {},
          runtime_environment: runtime_environment,
          conclusions: {
            dns_chain: :not_demonstrated,
            adguard_filtering_effective: :not_demonstrated,
            dnscrypt_upstream_encryption: :not_demonstrated
          },
          score_impact: 0
        }
      rescue StandardError
        {
          tested_at: Time.now.iso8601,
          processes: { adguard: nil, viscosity: nil, dnscrypt: nil },
          adguard_system_extension: :unknown,
          extension_command_available: false,
          resolvers: [],
          resolver_command_available: false,
          conclusions: { dns_chain: :not_demonstrated,
                         adguard_filtering_effective: :not_demonstrated,
                         dnscrypt_upstream_encryption: :not_demonstrated },
          score_impact: 0
        }
      end

      def network_context_lines(context)
        get = ->(key) { context.key?(key) ? context[key] : context[key.to_s] }
        return ['-- Contexte réseau (scutil --nwi) : indisponible'] unless context.is_a?(Hash) && get.call(:recognized)

        describe = lambda do |items, none, global|
          list = Array(items)
          if list.empty?
            none ? 'aucun état' : 'non reconnu'
          else
            labels = list.map do |item|
              reach = Array(item[:reach] || item['reach']).join(', ').downcase
              "#{item[:name] || item['name']} (#{reach.empty? ? 'reach inconnue' : reach})"
            end
            global ? "#{labels.join(', ')} • global : #{global.to_s.downcase}" : labels.join(', ')
          end
        end
        interfaces = Array(get.call(:interfaces))
        [
          '-- Contexte réseau (scutil --nwi, indicatif)',
          "--   IPv4 : #{describe.call(get.call(:ipv4), get.call(:ipv4_none), get.call(:ipv4_reach))}",
          "--   IPv6 : #{describe.call(get.call(:ipv6), get.call(:ipv6_none), get.call(:ipv6_reach))}",
          "--   Interfaces actives : #{interfaces.empty? ? 'non listées' : interfaces.join(' ')}",
          '--   Ne prouve ni le chemin réel des paquets ni le verdict VPN'
        ]
      end

      def local_service_lines(services)
        observed = services.select { |_name, value| value == true }.keys.map(&:to_s)
        absent = services.select { |_name, value| value == false }.keys.map(&:to_s)
        lines = ["-- Services locaux observés (ps) : #{observed.empty? ? 'aucun' : observed.join(', ')}"]
        lines << "--   non observés : #{absent.join(', ')}" unless absent.empty?
        lines << '--   un processus présent ne prouve pas qu\'il est utilisé par macOS ou par le tunnel'
        lines
      end

      def runtime_lines(env)
        get = ->(key) { env.key?(key) ? env[key] : env[key.to_s] }
        label = case get.call(:ruby_kind).to_s
                when 'system' then 'Ruby système'
                when 'homebrew' then 'Ruby Homebrew'
                else 'Ruby alternatif'
                end
        [
          "-- Environnement : #{label} #{get.call(:ruby_version)} (#{get.call(:ruby_path)})",
          '--   Outils système (scutil, ifconfig, route, dig, netstat, lsof, ps) appelés par chemin absolu ; PATH enfant : répertoires système d\'abord'
        ]
      end

      def context_lines(data)
        fetch = ->(key) { data.key?(key) ? data[key] : data[key.to_s] }
        lines = []
        primary = fetch.call(:primary_resolver)
        if primary.is_a?(Hash)
          iface = primary[:iface] || primary['iface']
          suffix = iface ? " • #{iface}" : ''
          lines << "-- Résolveur système principal (nameserver[0]) : #{primary[:ip] || primary['ip']}:#{primary[:port] || primary['port']}#{suffix}"
        end
        config = fetch.call(:dnscrypt_config)
        if config.is_a?(Hash)
          status = (config[:status] || config['status']).to_s
          addresses = Array(config[:listen_addresses] || config['listen_addresses'])
          lines << (status == 'ok' ? "-- Config dnscrypt-proxy lue : listen_addresses #{addresses.empty? ? 'vide' : addresses.join(', ')}" : "-- Config dnscrypt-proxy : #{status.empty? ? 'non lue' : status} ; aucune déduction d'attribution")
        end
        lines.concat(network_context_lines(fetch.call(:network_context))) if data.key?(:network_context) || data.key?('network_context')
        services = fetch.call(:local_services)
        lines.concat(local_service_lines(services)) if services.is_a?(Hash) && !services.empty?
        env = fetch.call(:runtime_environment)
        lines.concat(runtime_lines(env)) if env.is_a?(Hash)
        lines
      rescue StandardError
        []
      end

      def menu_lines(data)
        return ['-- Audit DNS multicouche : non disponible'] unless data.is_a?(Hash)
        processes = data[:processes] || data['processes'] || {}
        ext = (data[:adguard_system_extension] || data['adguard_system_extension']).to_s
        ext_label = case ext
                    when 'activated_enabled' then 'AdGuard System Extension : activée + enabled (état déclaré)'
                    when 'not_listed' then 'AdGuard System Extension : non listée (état du filtre non concluable)'
                    when 'listed_state_unknown' then 'AdGuard System Extension : listée, état non reconnu'
                    else 'AdGuard System Extension : non vérifiable'
                    end
        lines = ["-- Audit DNS multicouche : #{data[:tested_at] || data['tested_at'] || 'date inconnue'}",
                 "-- AdGuard processus : #{processes[:adguard] == true || processes['adguard'] == true ? 'observé' : (processes[:adguard] == false || processes['adguard'] == false ? 'non observé' : 'inconnu')}",
                 "-- #{ext_label}"]
        %i[viscosity dnscrypt].each do |key|
          value = processes[key] || processes[key.to_s]
          label = value == true ? 'observé' : (value == false ? 'non observé' : 'inconnu')
          lines << "-- Processus #{key == :dnscrypt ? 'dnscrypt-proxy' : 'Viscosity'} : #{label}"
        end
        resolvers = data[:resolvers] || data['resolvers'] || []
        resolver_available = data.key?(:resolver_command_available) ? data[:resolver_command_available] : data['resolver_command_available']
        if resolver_available == false
          lines << '-- Résolveurs macOS (scutil --dns) : collecte indisponible'
        else
          lines << "-- Résolveurs macOS (scutil --dns) : #{resolvers.length} endpoint(s)"
        end
        resolvers.each do |endpoint|
          ip = endpoint[:ip] || endpoint['ip']
          port = endpoint[:port] || endpoint['port']
          default = endpoint[:default] || endpoint['default']
          domains = endpoint[:domains] || endpoint['domains'] || []
          ifaces = endpoint[:interfaces] || endpoint['interfaces'] || []
          suffix = []
          suffix << 'défaut' if default
          suffix << "domaines scoped #{Array(domains).join(',')}" unless Array(domains).empty?
          suffix << "interfaces scoped #{Array(ifaces).join(',')}" unless Array(ifaces).empty?
          lines << "--   #{ip}:#{port}#{suffix.empty? ? '' : " • #{suffix.join(' • ')}"}"
          owner_status = (endpoint[:owner_status] || endpoint['owner_status']).to_s
          owners = endpoint[:owners] || endpoint['owners'] || []
          if owner_status == 'observed' && !owners.empty?
            owner_labels = owners.map { |owner| "#{owner[:process] || owner['process']} (PID #{owner[:pid] || owner['pid']})" }.uniq
            lines << "--     propriétaire observé : #{owner_labels.join(', ')}"
          elsif owner_status == 'permission_limited'
            lines << '--     propriétaire non attribué : lsof limité par les permissions (sans root)'
          elsif owner_status == 'unavailable'
            lines << '--     propriétaire non vérifiable : lsof indisponible'
          else
            lines << '--     propriétaire non attribué par lsof (absence de résultat ≠ absence de processus)'
          end
          if endpoint[:config_match] || endpoint['config_match']
            inferred = endpoint[:inferred_owner] || endpoint['inferred_owner']
            if inferred
              lines << "--     attribution déduite (listen_addresses de la config + processus #{inferred} observé) : #{inferred} — déduction, socket non prouvé sans privilèges"
            else
              lines << '--     écoute présente dans la config dnscrypt-proxy (listen_addresses) ; processus non observé : aucune attribution'
            end
          end
        end
        lines.concat(context_lines(data))
        lines << '-- Chaînage DNS : non démontré'
        lines << '-- Filtrage AdGuard effectif : non démontré par cet audit'
        lines << '-- DNSCrypt amont chiffré : non démontré par cet audit'
        lines << '-- Lecture seule • sonde à la demande • impact score : 0'
        lines
      end
    end

    # Diagnostic externe opt-in (v6.1.9) : bash.ws + log dnscrypt-proxy ; jamais
    # au rafraîchissement xbar ; lecture seule, sans effet verdict/score.
    module DNSDiag
      BASH_WS_HOST = 'bash.ws'.freeze
      PROBE_COUNT = 6
      MAX_HTTP_BYTES = 65_536
      MAX_LOG_BYTES = 32_768
      LOG_TAIL_LINES = 12

      module_function

      def clean(value, limit = 80)
        value.to_s.gsub(/[^[:print:]]/, '')[0, limit]
      end

      def parse_bash_ws_results(json_text)
        entries = JSON.parse(json_text.to_s)
        return { status: :unreadable, dns_servers: [], conclusion: nil } unless entries.is_a?(Array)

        servers = entries.select { |entry| entry.is_a?(Hash) && entry['type'].to_s == 'dns' }.map do |entry|
          { ip: clean(entry['ip']), country: clean(entry['country_name']), asn: clean(entry['asn']) }
        end
        conclusion = entries.find { |entry| entry.is_a?(Hash) && entry['type'].to_s == 'conclusion' }
        { status: :ok, dns_servers: servers, conclusion: conclusion ? clean(conclusion['ip'], 120) : nil }
      rescue StandardError
        { status: :unreadable, dns_servers: [], conclusion: nil }
      end

      def fetch_https(url, open_timeout: 1.5, read_timeout: 2.5)
        uri = URI.parse(url)
        return nil unless uri.scheme == 'https' && uri.host == BASH_WS_HOST

        Timeout.timeout(open_timeout + read_timeout + 1.0) do
          Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: open_timeout,
                                              read_timeout: read_timeout) do |http|
            response = http.request(Net::HTTP::Get.new(uri.request_uri))
            body = response.is_a?(Net::HTTPSuccess) ? response.body.to_s : nil
            body && body.bytesize <= MAX_HTTP_BYTES ? body : nil
          end
        end
      rescue StandardError
        nil
      end

      # Résolutions par le résolveur du système (getaddrinfo, comme les applications),
      # puis lecture du résultat côté bash.ws. Échec = « non vérifié », jamais « sûr ».
      def run_bash_ws
        id = fetch_https("https://#{BASH_WS_HOST}/id").to_s.strip
        return { status: :unavailable, reason: 'identifiant bash.ws non obtenu', dns_servers: [] } unless id.match?(/\A[0-9A-Za-z]{1,64}\z/)

        threads = (1..PROBE_COUNT).map do |index|
          Thread.new do
            begin
              Addrinfo.getaddrinfo("#{index}.#{id}.#{BASH_WS_HOST}", nil, nil, :STREAM)
              true
            rescue StandardError
              false
            end
          end
        end
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 4.0
        threads.each do |thread|
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          thread.join([remaining, 0.05].max)
        end
        threads.each { |thread| thread.kill if thread.alive? }

        body = fetch_https("https://#{BASH_WS_HOST}/dnsleak/test/#{id}?json")
        return { status: :unavailable, reason: 'résultat bash.ws non obtenu', dns_servers: [] } unless body

        parse_bash_ws_results(body)
      rescue StandardError
        { status: :unavailable, reason: 'erreur pendant le test bash.ws', dns_servers: [] }
      end

      def configured_log_file
        path = DNSCryptConfigAudit.locate_config
        return nil unless path && File.readable?(path) && File.size(path) <= DNSCryptConfigAudit::MAX_CONFIG_BYTES

        value = MiniToml.parse(File.read(path))['log_file']
        value.is_a?(String) && !value.empty? ? File.expand_path(value, File.dirname(path)) : nil
      rescue StandardError
        nil
      end

      def tail_log(path, max_bytes: MAX_LOG_BYTES, lines: LOG_TAIL_LINES)
        return { status: :not_configured } if path.to_s.empty?
        return { status: :not_found, path: path } unless File.file?(path)
        return { status: :not_readable, path: path } unless File.readable?(path)

        size = File.size(path)
        raw = File.open(path, 'rb') do |file|
          file.seek([size - max_bytes, 0].max)
          file.read(max_bytes).to_s
        end
        decoded = raw.force_encoding(Encoding::UTF_8).scrub('?')
        tail = decoded.lines.last(lines).map { |line| line.rstrip.gsub(/[[:cntrl:]]/, '')[0, 200] }
        { status: :ok, path: path, size: size, lines: tail }
      rescue StandardError
        { status: :error, path: path }
      end

      def run!
        {
          tested_at: Time.now.iso8601,
          bash_ws: run_bash_ws,
          dnscrypt_log: tail_log(configured_log_file),
          score_impact: 0
        }
      end

      def menu_lines(data)
        return ['-- Diagnostic DNS externe : non disponible'] unless data.is_a?(Hash)

        lines = ["-- Diagnostic DNS externe (opt-in) : #{data[:tested_at] || 'date inconnue'}"]
        ws = data[:bash_ws] || {}
        if ws[:status] == :ok
          servers = Array(ws[:dns_servers])
          lines << "-- bash.ws : #{servers.length} résolveur(s) DNS vu(s) par bash.ws"
          servers.each { |server| lines << "--   #{server[:ip]} • #{server[:country]} • #{server[:asn]}" }
          lines << "-- bash.ws conclusion : #{ws[:conclusion] || 'non fournie'} (donnée externe, non vérifiée localement)"
        else
          lines << "-- bash.ws : non vérifié (#{ws[:reason] || 'résultat illisible'}) ; aucune conclusion"
        end
        log = data[:dnscrypt_log] || {}
        case log[:status]
        when :ok
          lines << "-- Log dnscrypt-proxy (#{log[:path]}) : #{Array(log[:lines]).length} dernière(s) ligne(s)"
          Array(log[:lines]).each { |line| lines << "--   #{line}" }
        when :not_configured
          lines << '-- Log dnscrypt-proxy : log_file non configuré (aucune lecture)'
        when :not_found then lines << "-- Log dnscrypt-proxy : fichier introuvable (#{log[:path]})"
        when :not_readable then lines << "-- Log dnscrypt-proxy : illisible sans privilège (#{log[:path]})"
        else lines << '-- Log dnscrypt-proxy : non lu'
        end
        lines << '-- Lecture seule • opt-in hors rafraîchissement • aucun effet sur le verdict ni le score'
        lines
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
        leak_status = {} unless leak_status.is_a?(Hash)
        leak = leak_status[:leak]

        if network_state == Enums::ProtectionState[:PROTECTED] && leak == false
          puts "🔒 VPN | color=green"
        elsif leak == true || network_state == Enums::ProtectionState[:EXPOSED]
          puts "🚨 ALERTE | color=red"
        else
          puts "⚪ VPN — protection non vérifiée | color=gray"
        end

        puts "---"
        puts "État Réseau : #{network_state.to_s.upcase}"
        puts "Empreinte   : #{context[:fingerprint]}"
        puts "Pare-feu PF : #{firewall_label(firewall_status)}"

        if leak == true
          puts "---"
          puts "⚠️ Fuites Détectées | color=orange"
          puts "Détails: #{leak_status[:message]}"
        elsif leak.nil?
          puts "---"
          puts "⚪ État des fuites : non vérifiable"
          puts "Détails: #{leak_status[:message]}" if leak_status[:message]
        end

        puts "---"
        puts "IP Publique : #{geo[:ip] || 'N/A'}"
        puts "Pays        : #{geo[:country] || 'Inconnu'}"
      end

      # Libellé xbar VPN Bypass (décisions h/i/k) : 🟢 seulement si routes
      # actives + enforcing confirmé + helper prêt + format vérifié, sinon 🟡.
      # Méthode pure, tout vient de vpnb_status.
      def self.vpnb_bypass_label(vpnb_status)

        case vpnb_status[:state]
        when :detected
          # Libellé court : infos utiles au coup d'œil ; le reste en sous-menu.
          # Chaînes imposées par les tests conservées (« (OpenVPN) », « helper
          # non prêt », note vpn-only). Mode « bypass » masqué, autres affichés.
          details = []
          details << 'format non vérifié (schemaVersion inconnu)' if vpnb_status[:format_unverified]
          # v5.9.8 : « bypass » (mode par défaut) n'apporte rien au coup d'œil ;
          # tout autre mode (ex. vpn-only) reste affiché.
          details << vpnb_status[:mode] if vpnb_status[:mode] && vpnb_status[:mode] != 'bypass'
          # vpn-only : sémantique inversée, sites listés bloqués hors tunnel.
          # Note d'affichage seule, sans impact verdict/score.
          details << 'vpn-only : sites listés bloqués hors tunnel (annoncé)' if vpnb_status[:mode] == 'vpn-only'
          details << vpnb_status[:active_profile] if vpnb_status[:active_profile]
          if vpnb_status[:vpn_interface] && vpnb_status[:vpn_type]
            details << "#{vpnb_status[:vpn_interface]} (#{vpnb_status[:vpn_type]})"
          elsif vpnb_status[:vpn_interface]
            details << vpnb_status[:vpn_interface]
          end
          details << (vpnb_status[:vpn_connected] == 'true' ? 'connecté' : 'non connecté') if vpnb_status[:vpn_connected]
          routes = vpnb_status[:active_route_count] || vpnb_status[:route_count]
          details << "#{routes} route#{routes.to_i > 1 ? 's' : ''}" if routes
          details << (vpnb_status[:enforcing] == 'true' ? 'enforcement actif' : 'enforcement non confirmé')
          details << 'helper non prêt' if vpnb_status[:helper_ready] == 'false'
          details << "⚠️ kill-switch VPN (#{vpnb_status[:kill_switch].join(', ')}) : routes sans effet (annoncé)" if vpnb_status[:kill_switch]
          details << 'routing en pause (annoncé)' if vpnb_status[:paused] == 'true'
          active = vpnb_status[:active_route_count]
          # runtime.killSwitch / paused (PR #189/#203) : absentes du JSON 6.0.12
          # (8 clés vérifiées). Silence tant qu'elles sont absentes, aucune clé
          # inventée, codé-silencieux comme firewall: ; items 15/16 [À SUIVRE].
          confirmed = active.is_a?(Integer) && active.positive? &&
                      vpnb_status[:enforcing] == 'true' &&
                      vpnb_status[:helper_ready] != 'false' &&
                      !vpnb_status[:format_unverified] &&
                      !vpnb_status[:kill_switch] &&
                      vpnb_status[:paused] != 'true'
          # v5.9.8 : le préfixe « VPN Bypass » est déjà porté par la ligne « VPN Bypass.app: ».
          "#{confirmed ? '🟢' : '🟡'} #{details.join(' • ')}"


        when :no_exceptions
          '🟡 CLI détectée • aucune exception confirmée via vpnb status'
        when :not_detected
          '⚪ non détecté (CLI absente)'
        else
          # Libellé précis sur l'échec (décision i) ; couleur 🟡 dans tous les cas.
          if vpnb_status[:status_error] == :command_failed
            '🟡 status vpnb sans réponse'
          elsif vpnb_status[:parse_error]
            '🟡 status vpnb illisible / format inconnu'
          else
            '🟡 status vpnb indisponible'
          end
        end
      end

      # Recoupement affiché : vpnConnected (vpnb) vs détection locale.
      # Divergence = information, jamais une fuite ni un verdict (g/i). Méthode pure.
      def self.vpn_announced_divergence(vpnb_status, vpn_local_active)
        return nil unless vpnb_status.is_a?(Hash) && vpnb_status[:state] == :detected
        announced = vpnb_status[:vpn_connected]
        return nil if announced.nil?
        announced_active = announced == 'true'
        local_active = vpn_local_active == true
        return nil if announced_active == local_active
        "⚠️ Divergence VPN : vpnb annonce #{announced_active ? 'VPN connecté' : 'VPN non connecté'}, détection locale #{local_active ? 'active' : 'inactive'} (à vérifier ; verdict et score inchangés)"
      end

      # Comparaison pure : divergence informative, jamais une fuite.
      def self.vpn_interface_divergence(vpnb_status, local_tunnel_type)
        return nil unless vpnb_status.is_a?(Hash) && vpnb_status[:state] == :detected
        local_iface = local_tunnel_type.to_s[/\b(?:utun|tun|tap|wg|ppp)\d+\b/i]
        announced_iface = vpnb_status[:vpn_interface].to_s
        return nil if local_iface.to_s.empty? || announced_iface.empty? || local_iface == announced_iface
        "Interfaces divergentes : local #{local_iface} / VPN Bypass #{announced_iface} ; à vérifier"
      end

      # v5.9.8 : divergence d'interface par RÔLE — interface annoncée présente
      # parmi les VPN locales = deux tunnels (note ℹ️) ; sinon ⚠️ « à vérifier ».
      # Retour : nil | [:info, texte] | [:warn, texte]. Sans incidence verdict/score.
      def self.vpn_interface_note(vpnb_status, vpn)
        vpn = {} unless vpn.is_a?(Hash)
        base = vpn_interface_divergence(vpnb_status, vpn[:tunnel_type])
        return nil unless base

        announced = vpnb_status[:vpn_interface].to_s
        local = Array(vpn[:interfaces]).map(&:to_s)
        if !announced.empty? && local.include?(announced)
          local_iface = vpn[:tunnel_type].to_s[/\b(?:utun|tun|tap|wg|ppp)\d+\b/i]
          [:info, "Deux tunnels distincts : local #{local_iface} / VPN Bypass #{announced} (tous deux observés)"]
        else
          [:warn, base]
        end
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
        vpn_active  = vpn[:active] == true

        # Le bandeau n'est vert/sécurisé que si le VPN est actif ET le pays autorisé
        is_secure_vpn = vpn_active && is_allowed

        # IP et pays doivent avoir été mesurés à cet instant ; sinon ni vert, ni drapeau.
        ip_known = VPNChecker.valid_ip?(ips[:v4]) && country_code != 'XX'
        flag_emoji, header_color = header_style(
          is_denied: is_denied, is_allowed: is_allowed, vpn_active: vpn_active,
          country_code: country_code, ip_known: ip_known
        )

        country_status_label = if is_denied
                                 '🚨 [DANGER / DENY]'
                               elsif !ip_known
                                 '⚪ [NON VÉRIFIÉ]'
                               elsif is_allowed
                                 '✅ [SÉCURISÉ / ALLOWED]'
                               else
                                 '⚠️ [HORS LISTE AUTORISÉE]'
                               end

        # Aucun état n'est écrit sans mesure valide (sinon fausses alertes et perte du dernier état connu).
        VPNChecker::FlagTracer.trace_and_log(flag_emoji, header_color, ip_v4, country_name, org) if ip_known

        puts "#{flag_emoji} | color=#{header_color} dropdown=true"
        puts "---"
        puts "VPN Checker v#{APP_VERSION} • contrôle #{Time.now.strftime('%H:%M:%S')} | font=Menlo"
        puts "---"
        puts '-- ℹ️ Connectivité externe non vérifiée ; contrôles distants différés, observations locales conservées' if context[:connectivity_unverified]

        puts "🌐 IDENTITÉ RÉSEAU (#{ip_v4})"
        puts "-- ⚠️ IP publique non vérifiée à cet instant ; aucune valeur mémorisée n'est affichée" unless ip_known
        rdns_info = VPNChecker::Helpers.reverse_dns_status(context[:ptr], org, ip_v4, vpn_active: vpn[:active])

        if rdns_info[:alert] && context[:ptr]
          puts "PTR Alerte: (#{sanitize_xbar(context[:ptr])}) (#{sanitize_xbar(org)}) 🚨[PTR Incohérent]"
        end

        puts "Infrastructure: ☁️ #{infrastructure_label(provider[:type])} (#{sanitize_xbar(geo[:asn])})"
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
        score_display = score_display_label(context[:sec_score], context[:score_coverage])
        puts "🔒 SÉCURITÉ RÉSEAU • Score: #{score_display}"
        # v5.9.8 : ce qui manque pour une couverture complète, en sous-menu.
        note = coverage_note_line(context[:score_coverage], Intelligence::SecurityScore.unverified_check_names(context))
        puts note if note
        puts "VPN: #{vpn[:active] ? "🟢 Actif (#{vpn[:tunnel_type]})" : '🔴 Inactif'}"
        puts "Kill Switch: #{ks_title(ks, firewall_status)}"
        ks_menu_lines(ks, firewall_status, context[:firewall], DEBUG_MODE).each { |line| puts line }
        app_firewall = context[:app_firewall]
        if app_firewall.is_a?(Hash)
          puts "Pare-feu applicatif: #{summary_clip(sanitize_xbar(app_firewall[:message]))}"
          detail_menu_lines(app_firewall).each { |line| puts line }
        end
        puts "Split Tunnel: #{summary_clip(sanitize_xbar(split_tunnel[:message]))}"
        split_menu_lines(split_tunnel, 120, true).each { |line| puts line }
        # État VPN Bypass séparé : jamais le verdict Split Tunnel (routes observées).
        vpnb_status = context[:vpnb_status].is_a?(Hash) ? context[:vpnb_status] : Infrastructure::VPNBypassSource.status
        vpnb_message = vpnb_bypass_label(vpnb_status)
        puts "VPN Bypass.app: #{vpnb_message}"
        # Sous-menu (v5.9.6) : diagnostic détaillé si état exploitable ; sinon 🟡 suffit.
        if vpnb_status[:state] == :detected
          sub = []
          sub << "app #{vpnb_status[:app_version]}" if vpnb_status[:app_version]
          sub << "helper : #{vpnb_status[:helper_state]}" if vpnb_status[:helper_state]
          if vpnb_status[:route_count] || vpnb_status[:active_route_count]
            sub << "#{vpnb_status[:route_count] || '?'}/#{vpnb_status[:active_route_count] || '?'} annoncées/actives"
          end
          puts "-- #{sub.join(' • ')}" unless sub.empty?
          puts "-- moteur: #{vpnb_status[:engine_state]}" if vpnb_status[:engine_state]
          puts "-- pare-feu: #{vpnb_status[:firewall_state]}" if vpnb_status[:firewall_state]
        end

        # Recoupement VPN annoncé/local : divergence information, jamais un verdict.
        vpn_div = vpn_announced_divergence(vpnb_status, vpn[:active] == true)
        puts "-- ⚠️ #{sanitize_xbar(vpn_div.sub('⚠️ ', ''))}" if vpn_div
        iface_note = vpn_interface_note(vpnb_status, vpn)
        if iface_note
          puts "-- #{iface_note[0] == :info ? 'ℹ️' : '⚠️'} #{sanitize_xbar(iface_note[1])}"
        end

        # Écarts (v5.8.1) : trois sources comparées (annoncées, actives, observées).
        # Un écart appelle une vérification, jamais une conclusion de fuite.
        vpnb_active = vpnb_status[:active_route_count]
        if vpnb_active.is_a?(Integer) && vpnb_status[:route_count].is_a?(Integer) && vpnb_status[:route_count] != vpnb_active
          puts "-- ⚠️ Écart CLI : #{vpnb_status[:route_count]} route(s) annoncée(s) / #{vpnb_active} active(s)"
        end
        # v5.9.8 : l'écart routes annoncées / corrélées n'est plus répété ici ;
        # il est exposé une seule fois, dans le bloc Split Tunnel (titre + détail).

        # Recoupement pare-feu (v5.8.5, décision g) : affichage seul, sans verdict ni score.
        pf_cross = Infrastructure::VPNBypassSource.pf_cross_check(vpnb_status, context[:firewall])
        puts "-- #{sanitize_xbar(pf_cross)}" if pf_cross

        # Enforcement annoncé (décision g) : visible, n'ajuste jamais le score.
        if vpnb_status[:state] == :detected && vpnb_status[:enforcing] == 'true'
          puts "-- ℹ️ enforcement : information contextuelle, sans effet sur le score"
        end

        # Actions xbar via CLI, sans élévation ; jamais de verdict modifié.
        vpnb_cli = Infrastructure::VPNBypassSource.resolve_cli&.first
        if vpnb_cli
          puts "-- 🚀 Activer VPN Bypass | bash=\"#{vpnb_cli}\" param1=\"on\" refresh=true terminal=false"
          puts "-- ⏹️ Désactiver VPN Bypass | bash=\"#{vpnb_cli}\" param1=\"off\" refresh=true terminal=false"
          puts "-- ⏸️ Mettre VPN Bypass en pause | bash=\"#{vpnb_cli}\" param1=\"pause\" refresh=true terminal=false"
          puts "-- 🔄 Recharger les routes VPN Bypass | bash=\"#{vpnb_cli}\" param1=\"reload\" refresh=true terminal=false"
          # `vpnb why` à la demande (décision m) : un domaine à la fois, terminal
          # ouvert ; jamais au rafraîchissement automatique.
          if vpnb_status[:state] == :detected
            puts "-- 🔍 Vérifier un site de confiance (vpnb why)"
            VPNChecker::TRUSTED_WHITELIST.each do |domain|
              puts "---- vpnb why #{domain} | bash=\"#{vpnb_cli}\" param1=\"why\" param2=\"#{domain}\" refresh=true terminal=true"
            end
          end
        end

        puts "Tor: #{sanitize_xbar(tor[:message])}" if tor[:active]
        puts "DNS: #{summary_clip(sanitize_xbar(dns_leak[:message]), 110)}"
        Renderers::ManualDNSProbe.menu_lines(Renderers::ManualDNSProbe.latest).each { |line| puts line }
        
        # Chemin sans espace (alias ~/.xbar-plugins) : un paramètre xbar avec
        # espace casse terminal=true.
        script_path = VPNChecker.action_script_path

        puts "-- 🧪 Tester les relais DNS | bash=\"/usr/bin/ruby\" param1=#{script_path.dump} param2=\"dns-probe\" refresh=true terminal=false"
        puts "-- 🔎 Auditer DNSCrypt (lecture seule) | bash=\"/usr/bin/ruby\" param1=#{script_path.dump} param2=\"dnscrypt-audit\" refresh=true terminal=true"
        puts "-- 🚧 Tester le blocage DNSCrypt (lecture seule) | bash=\"/usr/bin/ruby\" param1=#{script_path.dump} param2=\"dnscrypt-block-probe\" refresh=true terminal=true"
        puts "-- 🧭 Auditer les couches DNS (lecture seule) | bash=\"/usr/bin/ruby\" param1=#{script_path.dump} param2=\"dns-stack-audit\" refresh=true terminal=true"
        puts "-- 🌐 Diagnostic DNS externe bash.ws + log (opt-in) | bash=\"/usr/bin/ruby\" param1=#{script_path.dump} param2=\"dns-diag\" refresh=false terminal=true"
        Renderers::DNSCryptBlockProbe.menu_lines(Renderers::DNSCryptBlockProbe.latest).each { |line| puts line }
        dns_menu_lines(dns_leak, context[:dns_servers]).each { |line| puts line }
        puts "Fuite IPv6: #{sanitize_xbar(ipv6[:message])}"
        puts "Fuite WebRTC: #{sanitize_xbar(webrtc_leak[:message])} | href=https://browserleaks.com/webrtc"
        puts "DNS Chiffré: #{dns_encrypted_label(context[:dns_encrypted], dns_leak)}"
        dns_encrypted_menu_lines(context[:dns_encrypted], dns_leak).each { |line| puts line }
        puts "---"
        puts "⚡ PERFORMANCES"
        latency = perf[:latency] ? sanitize_xbar(perf[:latency]) : 'N/D'
        jitter = perf[:jitter] ? sanitize_xbar(perf[:jitter]) : 'N/D'
        puts "Latence: #{latency} • Jitter: #{jitter}"
        puts "---"

        puts "🚪 PORTS TCP ÉCOUTÉS (SÉCURITÉ)"
        app_firewall_line = app_firewall_ports_line(context[:app_firewall])
        puts app_firewall_line if app_firewall_line
        open_ports = context[:open_ports].to_a
        ports_status = context[:open_ports_status]
        if open_ports.empty? && ports_status.is_a?(Hash) && %i[unknown error].include?(ports_status[:state])
          puts "-- ⚪ Non vérifiable : la collecte des ports n'a pas abouti (liste vide ≠ aucun port)"
        elsif open_ports.empty?
          puts "-- Aucun port TCP non standard détecté"
        else
          port_menu_lines(open_ports).each { |line| puts line }
        end
        puts "---"

        script_path = File.expand_path(__FILE__)
        puts "⚡ ACTIONS RAPIDES"
        puts "-- 🔄 Rafraîchir les contrôles | refresh=true"
        # Utilisation de parametres séparés pour xbar (param1, param2) au lieu d'une ligne bash interpolée risquée
        puts "-- 🧹 Purger le cache local | bash=\"/usr/bin/ruby\" param1=#{script_path.dump} param2=\"purge\" refresh=true terminal=false"
        puts "-- 🛡️ Activer le Firewall PF | bash=\"/usr/bin/osascript\" param1=\"-e\" param2='do shell script \"pfctl -e\" with administrator privileges' refresh=true terminal=false"

        if SHOW_FINGERPRINT
          fingerprint = context[:fingerprint].to_s
          short_fp = fingerprint[0, 6]
          puts "---"
          puts "Empreinte: #{short_fp}… | color=#888888"
        end
      end


      # Trois états : un type inconnu n'est jamais présenté comme « Résidentiel ».
      def self.infrastructure_label(type)
        case type
        when Enums::InfrastructureType[:HOSTING], Enums::InfrastructureType[:DATACENTER], Enums::InfrastructureType[:VPN_NODE]
          'Cloud / VPN'
        when Enums::InfrastructureType[:RESIDENTIAL]
          'Résidentiel'
        else
          'Indéterminé'
        end
      end

      # v5.9.9 : services macOS courants à l'écoute sur toutes les interfaces.
      # Heuristique par NOM de processus : un signal, jamais un verdict.
      SYSTEM_LISTENERS = %w[rapportd kdc launchd sharingd controlcenter].freeze
      EXPECTED_APP_LISTENERS = [].freeze
      PORT_HINTS = { 88 => 'Kerberos', 445 => 'SMB' }.freeze

      # Qualification opérationnelle, jamais un verdict d'accessibilité réseau.
      # :expected = service système courant ou application explicitement reconnue ;
      # :inspect = wildcard détenu par une application/autre processus ;
      # :unknown = propriétaire/portée insuffisamment attribués.
      def self.port_operational_classification(entry)
        return :unknown unless entry.is_a?(Hash)
        return :expected if %i[loopback interface].include?(entry[:bind])
        return :unknown unless entry[:bind] == :all

        owners = Array(entry[:owners])
        names = owners.map { |owner| owner[:process].to_s.downcase.gsub(/[^a-z0-9]/, '') }.reject(&:empty?)
        names = [entry[:process].to_s.downcase.gsub(/[^a-z0-9]/, '')] if names.empty? && entry[:process]
        return :unknown if names.empty? || names.any? { |name| name.empty? || name == 'unidentified' }
        return :expected if names.all? { |name| SYSTEM_LISTENERS.map { |item| item.gsub(/[^a-z0-9]/, '') }.include?(name) || EXPECTED_APP_LISTENERS.map { |item| item.gsub(/[^a-z0-9]/, '') }.include?(name) }
        :inspect
      end

      # Compatibilité des appels/tests historiques.
      def self.port_exposure_class(entry)
        return :loopback if entry.is_a?(Hash) && entry[:bind] == :loopback
        return :interface if entry.is_a?(Hash) && entry[:bind] == :interface
        case port_operational_classification(entry)
        when :expected then :system
        when :inspect then :app
        else :unknown
        end
      end

      # Lignes du sous-menu des ports : exposés d'abord (ordre stable sinon),
      # synthèse ⚠️ si au moins un port applicatif est exposé.
      def self.port_menu_lines(open_ports)
        entries = open_ports.to_a.select { |entry| entry.is_a?(Hash) }
        ordered = entries.each_with_index.sort_by { |entry, index| [entry[:bind] == :all ? 0 : 1, index] }.map(&:first)
        lines = []
        exposed_apps = ordered.count { |entry| port_operational_classification(entry) == :inspect }
        lines << "-- ⚠️ #{exposed_apps} port(s) applicatif(s) écoute(s) wildcard à examiner (joignabilité non testée)" if exposed_apps.positive?
        ordered.each do |entry|
          details = []
          scope = port_scope_label(entry[:bind])
          details << scope unless scope.empty?
          owners = Array(entry[:owners])
          if owners.size > 1
            labels = owners.map do |owner|
              process = owner[:process].to_s.strip
              process = 'propriétaire non identifié' if process.empty? || process == 'unidentified'
              scope_detail = case owner[:bind_detail]
                             when :wildcard_ipv4 then 'wildcard IPv4'
                             when :wildcard_ipv6 then 'wildcard IPv6'
                             when :loopback_ipv4 then 'loopback IPv4'
                             when :loopback_ipv6 then 'loopback IPv6'
                             else 'interface précise'
                             end
              "#{process}(pid #{owner[:pid]}, #{owner[:family]}, #{scope_detail}, #{owner[:address]})"
            end.uniq
            details << "propriétaires multiples : #{sanitize_xbar(labels.join(' / '))}"
          elsif owners.size == 1
            owner = owners.first
            process = owner[:process].to_s.strip
            if process.empty? || process == 'unidentified'
              pid = owner[:pid] ? " (pid #{owner[:pid]})" : ''
              details << "propriétaire non identifié#{pid}"
            else
              details << sanitize_xbar(process)
            end
            family_scope = case owner[:bind_detail]
                           when :wildcard_ipv4 then 'IPv4 wildcard'
                           when :wildcard_ipv6 then 'IPv6 wildcard'
                           when :loopback_ipv4 then 'IPv4 loopback'
                           when :loopback_ipv6 then 'IPv6 loopback'
                           when :interface then 'interface précise'
                           end
            details << family_scope if family_scope
          elsif entry[:process] && !entry[:process].to_s.strip.empty? && entry[:process].to_s != 'unidentified'
            details << sanitize_xbar(entry[:process])
          elsif entry[:bind] == :all
            details << 'propriétaire non identifié'
          end
          hint = PORT_HINTS[entry[:port]]
          details << hint if hint
          classification = port_operational_classification(entry)
          marker = { inspect: '⚠️ ', expected: 'ℹ️ ', unknown: '⚪ ' }.fetch(classification, '⚪ ')
          details << { inspect: 'à examiner', expected: 'service attendu / portée observée', unknown: 'qualification inconnue' }.fetch(classification)
          suffix = details.empty? ? '' : " • #{details.join(' • ')}"
          lines << "-- #{marker}Port #{entry[:port]}#{suffix} (#{sanitize_xbar(entry[:command])})"
        end
        lines
      end

      def self.port_scope_label(bind)
        case bind
        when :all then '🌐 toutes interfaces'
        when :loopback then '🔒 local uniquement'
        when :interface then '📡 interface précise'
        else ''
        end
      end

      DNS_STATUS_LABELS = {
        secure_path_observed: 'via le tunnel',
        non_tunnel_path_observed: 'HORS TUNNEL',
        local_resolver_observed: 'relais local (amont non vérifié)',
        unknown: 'non vérifiable'
      }.freeze

      # Coupe proprement : une phrase tronquée se termine toujours par « … ».
      def self.clip(text, max)
        value = text.to_s
        value.length > max ? "#{value[0, max - 1].rstrip}…" : value
      end

      # Résumé d'une ligne principale : conserve le début ET la fin du statut pour
      # éviter de masquer une qualification importante (ex. « non vérifiable »).
      # Les détails complets restent dans les sous-menus existants.
      def self.summary_clip(text, max = 68)
        value = text.to_s
        return value if value.length <= max

        head_size = max - 28
        tail_size = 27
        "#{value[0, head_size].rstrip}…#{value[-tail_size, tail_size].to_s.lstrip}"
      end

      # Retire les pictogrammes de tête (ex. « 🔐 ») : ils laissent croire à une preuve.
      def self.strip_leading_symbols(text)
        text.to_s.sub(/\A[^\p{Alnum}]+/, '')
      end

      # Retour au mot pour les phrases longues : macOS tronque visuellement les
      # items de menu trop longs ; plusieurs lignes complètes restent lisibles.
      # La première ligne reçoit le préfixe « ℹ️ » chez l'appelant.
      def self.wrap_reason_lines(reason, max = 90)
        words = sanitize_xbar(reason.to_s).split(/\s+/).reject(&:empty?)
        return [] if words.empty?
        lines = [words.shift]
        words.each do |word|
          if (lines.last.length + 1 + word.length) <= max
            lines.last << ' ' << word
          else
            lines << word.dup
          end
        end
        lines
      end
      
      def self.dns_server_label(ip, port = nil, process = nil, listener = nil)
        host = port && port != 53 ? "#{ip}:#{port}" : ip.to_s
        name = if process
                 "processus #{process}"
               elsif listener == :no_listener
                 'aucune écoute TCP : proxy système possible'
               elsif listener == :unidentified
                 'écoute TCP, processus non identifié'
               elsif port.nil? || port == 53
                 table_name = DNS_PROVIDERS[ip.to_s]
                 table_name = DNS_PROVIDERS[ip.to_s]
                 if table_name
                   strip_leading_symbols(table_name)
                 else
                   private_fallback_dns_name(ip)
                 end
               end
        name ? "#{host} (#{name})" : host
      end

      # Filet de sécurité (v5.8.8) : RFC1918 absente de DNS_PROVIDERS -> étiquette
      # sans deviner le propriétaire (Proton 10.2.0.1/10.96.0.1/10.124.0.1,
      # liste NON exhaustive, ou box locale) ; IP publique inconnue -> libellé
      # nu. Le verdict des détecteurs ne dépend jamais du nom.
      def self.private_fallback_dns_name(ip)
        addr = begin
          IPAddr.new(ip.to_s)
        rescue IPAddr::InvalidAddressError, ArgumentError
          nil
        end
        return nil unless addr && (addr.private? || addr.link_local?) && !addr.loopback?
        'relais DNS interne (réseau privé)'
      end

      def self.public_dns_ip?(ip)
        address = IPAddr.new(ip.to_s)
        !(address.loopback? || address.private? || address.link_local?)
      rescue StandardError
        false
      end

      def self.loopback_dns_ip?(ip)
        IPAddr.new(ip.to_s).loopback?
      rescue StandardError
        false
      end

      # Lignes de sous-menu xbar assainies ; opts : :reason et :evidence (défaut true).
      def self.detail_menu_lines(result, limit = 12, opts = {})
        return [] unless result.is_a?(Hash)

        lines = []
        reason = result[:reason].to_s.strip
                if opts.fetch(:reason, true) && !reason.empty?
          wrap_reason_lines(reason).each_with_index do |part, index|
            lines << (index.zero? ? "-- ℹ️ #{part}" : "-- #{part}")
          end
        end
        return lines unless opts.fetch(:evidence, true)
        return lines if result[:timed_out]

        detail = result[:evidence_detail]
        dns_style = detail.is_a?(Array) && !detail.empty? &&
                    detail.all? { |item| item.is_a?(Hash) && item.key?(:ip) && item.key?(:status) }
        evidence = if dns_style
                     detail.map do |item|
                       origin = item[:origin].to_s.empty? ? '' : " • #{item[:origin]}"
                       "#{dns_server_label(item[:ip], item[:port], item[:process], item[:listener])} via #{item[:interface] || '?'} : #{DNS_STATUS_LABELS.fetch(item[:status], item[:status].to_s)}#{origin}"
                     end
                   else
                     Array(result[:evidence]).map(&:to_s)
                   end
        evidence = evidence.map(&:strip).reject(&:empty?)

        evidence.first(limit).each { |item| lines << "-- #{sanitize_xbar(clip(item, 200))}" }
        lines << "-- … +#{evidence.size - limit} autre(s)" if evidence.size > limit
        lines
      end

      # Sous-menu « Fuite DNS » : une ligne par endpoint si preuves ; sinon
      # liste des serveurs configurés, jamais perdue. Alerte « mixte » :
      # résolveurs par défaut seulement.
      def self.dns_menu_lines(dns_leak, fallback_servers = [])
        detail = dns_leak.is_a?(Hash) ? dns_leak[:evidence_detail] : nil
        dns_style = detail.is_a?(Array) && !detail.empty? &&
                    detail.all? { |item| item.is_a?(Hash) && item.key?(:ip) && item.key?(:status) }
        general_public = []
        has_general_local = false

        if dns_style
          lines = detail_menu_lines(dns_leak, 12, reason: false)
          general = detail.select { |item| item.fetch(:default_resolver, true) }
          general_public = general.select { |item| public_dns_ip?(item[:ip]) }
          has_general_local = general.any? { |item| loopback_dns_ip?(item[:ip]) }
        else
          lines = []
          if dns_leak.is_a?(Hash) && dns_leak[:timed_out]
            lines << '-- ℹ️ Preuves DNS non collectées (délai dépassé) ; serveurs configurés :'
          end
          configured = Array(fallback_servers).map { |entry| "-- #{sanitize_xbar(strip_leading_symbols(entry))}" }
          configured = ['-- Aucun serveur DNS détecté'] if configured.empty?
          lines.concat(configured)
        end

        if dns_style
          detail.each do |item|
            next unless item.is_a?(Hash) && item[:socket_status] == :observed
            pid_text = item[:pid] ? "PID #{item[:pid]}" : 'PID non déterminé'
            lines << "-- ℹ️ Socket du relais #{item[:ip]}:#{item[:port]} : #{sanitize_xbar(item[:process])} (#{pid_text}) ; sockets distants du même PID :"
            upstream = Array(item[:upstream_sockets])
            if upstream.empty?
              lines << '--   aucun socket distant attribué observé (ce relevé ne prouve pas l’absence de flux)'
            else
              upstream.first(8).each do |socket|
                lines << "--   #{socket[:protocol]} #{socket[:family]} #{socket[:local_host]}:#{socket[:local_port]} → #{socket[:remote_host]}:#{socket[:remote_port]} (protocole applicatif non déterminé)"
              end
            end
          end
        end

        if has_general_local && !general_public.empty?
          secure_public = general_public.count { |item| item[:status] == :secure_path_observed }
          scope = secure_public == general_public.size ? 'tous joints par le tunnel' : "dont #{secure_public} joint(s) par le tunnel"
          lines << "-- ⚠️ Configuration DNS mixte : résolveur local + #{general_public.size} résolveur(s) public(s), #{scope} ; en cas de repli, ces requêtes partent sans chiffrement DNS"
        end
        lines
      end

      # Niveaux du DNS chiffré (v5.9.8) : `present` ⚪ (usage non prouvé) ;
      # `probable` 🟡 si TOUS les résolveurs par défaut loopback = dnscrypt ;
      # amont chiffré jamais « prouvé » ici. 🔐 réservé au futur `proven`.
      def self.dns_encrypted_label(dns_encrypted, dns_leak)
        return '⚪ Non déterminé' unless dns_encrypted.is_a?(Hash)

        base = dns_encrypted[:message] || '⚪ Non déterminé'
        return base unless dns_encrypted[:level] == :present
        return base unless Array(dns_encrypted[:methods]).include?('DNSCrypt')

        detail = dns_leak.is_a?(Hash) ? dns_leak[:evidence_detail] : nil
        return base unless detail.is_a?(Array)

        defaults = detail.select { |item| item.is_a?(Hash) && item[:default_resolver] == true && loopback_dns_ip?(item[:ip]) }
        return base if defaults.empty?
        return base unless defaults.all? { |item| item[:process].to_s.downcase.include?('dnscrypt') }

        '🟡 DNSCrypt probable : résolveur par défaut = dnscrypt-proxy (amont chiffré non lu)'
      end

      # « DNS Chiffré » = présence du processus dnscrypt-proxy seulement ;
      # si le résolveur par défaut est autre/non identifié, le menu le dit.
      def self.dns_encrypted_menu_lines(dns_encrypted, dns_leak)
        return [] unless dns_encrypted.is_a?(Hash) && Array(dns_encrypted[:methods]).include?('DNSCrypt')

        detail = dns_leak.is_a?(Hash) ? dns_leak[:evidence_detail] : nil
        return [] unless detail.is_a?(Array)

        defaults = detail.select { |item| item.is_a?(Hash) && item[:default_resolver] == true && loopback_dns_ip?(item[:ip]) }
        return [] if defaults.empty?
        return [] if defaults.any? { |item| item[:process].to_s.downcase.include?('dnscrypt') }

        endpoint = defaults.map { |item| item[:port] && item[:port] != 53 ? "#{item[:ip]}:#{item[:port]}" : item[:ip].to_s }.join(', ')
        owners = defaults.map { |item| item[:process] }.compact.uniq
        line = if !owners.empty?
                 "-- ⚠️ dnscrypt-proxy est actif, mais le résolveur par défaut (#{endpoint}) est géré par #{owners.join(', ')}"
               elsif defaults.any? { |item| item[:listener] == :no_listener }
                 "-- ℹ️ dnscrypt-proxy est actif, mais le résolveur par défaut (#{endpoint}) n'a aucune écoute TCP : proxy système ou extension réseau possible ; lien non prouvé"
               else
                 "-- ℹ️ dnscrypt-proxy est actif, mais le lien avec le résolveur par défaut (#{endpoint}) n'est pas prouvé : processus non identifié"
               end
        [sanitize_xbar(line)]
      end

      def self.pf_menu_line(status, firewall)
        reason = firewall.is_a?(Hash) ? firewall[:reason].to_s.strip : ''
        case status
        when :unauthorized
          '-- 🛡️ Pare-feu PF : non vérifiable sans droits root'
        when true
          "-- 🛡️ Pare-feu PF : #{sanitize_xbar(clip(reason.empty? ? 'règle de blocage hors tunnel présente' : reason, 200))}"
        when false
          "-- 🛡️ Pare-feu PF : #{sanitize_xbar(clip(reason.empty? ? 'aucune protection PF observée' : reason, 200))}"
        end
      end

      # Sous-menu Kill Switch : raison + PF ; preuves brutes seulement en --debug.
      def self.ks_menu_lines(ks, firewall_status, firewall, debug = false)
        lines = detail_menu_lines(ks, 12, evidence: debug)
        pf_line = pf_menu_line(firewall_status, firewall)
        lines << pf_line if pf_line
        lines
      end

      def self.ks_title(ks, firewall_status)
        base = sanitize_xbar(ks[:status])
        firewall_status == :unauthorized && ks[:state] == :unknown ? "#{base} — PF illisible sans root" : base
      end

      # [emoji, couleur] du bandeau. Sans IP/pays mesurés : jamais vert, jamais de drapeau.
      def self.header_style(is_denied:, is_allowed:, vpn_active:, country_code:, ip_known:)
        return(vpn_active ? ['🔐 ❓', '#FF8C00'] : ['🌐 ❓', '#888888']) unless ip_known

        flag = EmojiHelper.country_code_to_emoji(country_code)
        emoji = is_denied ? '🚨' : (vpn_active ? "🔐 #{flag}" : "🌐 #{flag}")
        color = if is_denied
                  '#FF0000'
                elsif vpn_active && is_allowed
                  '#006400'
                elsif vpn_active
                  '#FF8C00'
                else
                  '#888888'
                end
        [emoji, color]
      end

      # Score jamais présenté comme complet si des contrôles ne sont pas vérifiés ;
      # v5.9.8 : couverture ≥ 50 % = score_label inchangé (rétrocompatible).
      def self.score_display_label(score, coverage)
        return 'N/D' if score.nil?
        # Couverture ≥ 50 % : score seul (détail N/6 en sous-menu) ; sous 50 %,
        # plafond et « N/6 » affichés.
        return "#{score}%" unless Intelligence::SecurityScore.confidence_capped?(coverage)

        shown = Intelligence::SecurityScore.display_score(score, coverage)
        suffix = "#{coverage[0]}/#{coverage[1]} vérifiés • confiance faible"
        shown < score ? "#{shown}% (plafonné) • #{suffix}" : "#{shown}% • #{suffix}"
      end

      # Sous-menu du score : couverture + contrôles sans preuve (neutres).
      # nil si tout est vérifié ou si la couverture est inconnue.
      def self.coverage_note_line(coverage, unverified)
        return nil unless coverage.is_a?(Array) && coverage.size == 2 && coverage[0] < coverage[1]

        names = unverified.is_a?(Array) && !unverified.empty? ? " • non vérifiés : #{sanitize_xbar(unverified.join(', '))}" : ''
        "-- ℹ️ #{coverage[0]}/#{coverage[1]} contrôles vérifiés#{names} (neutres, jamais comptés comme réussis)"
      end

      def self.score_label(score, coverage)
        return 'N/D' if score.nil?

        label = "#{score}%"
        if coverage.is_a?(Array) && coverage.size == 2 && coverage[0] < coverage[1]
          label += " • partiel (#{coverage[0]}/#{coverage[1]} contrôles vérifiés)"
        end
        label
      end

      def self.app_firewall_ports_line(app_firewall)
        return nil unless app_firewall.is_a?(Hash)

        case app_firewall[:enabled]
        when true
          stealth = app_firewall[:stealth] == true ? ' • mode furtif' : ''
          "-- 🛡️ Pare-feu applicatif : activé#{stealth} (filtre les connexions entrantes par application)"
        when false
          '-- 🛡️ Pare-feu applicatif : DÉSACTIVÉ (aucun filtre applicatif sur ces ports)'
        else
          '-- 🛡️ Pare-feu applicatif : non vérifiable'
        end
      end

      def self.sortable_ip(address)
        IPAddr.new(address.to_s.split('/').first.to_s).to_i
      rescue StandardError
        0
      end

      # Sous-menu Split Tunnel : routes hôte regroupées (passerelle, interface,
      # drapeaux), adresses triées, plafond max_addresses. Cas « tout couvert » :
      # décomptes seuls (l'utile est l'écart, pas l'inventaire).
      def self.split_menu_lines(split_tunnel, max_addresses = 120, fold = false)
        return [] unless split_tunnel.is_a?(Hash)

        lines = []
        reason = split_tunnel[:reason].to_s.strip
                unless reason.empty?
          wrap_reason_lines(reason).each_with_index do |part, index|
            lines << (index.zero? ? "-- ℹ️ #{part}" : "-- #{part}")
          end
        end
        return lines if split_tunnel[:timed_out]

        # v5.9.8 : routes annoncées par VPN Bypass sans route hôte corrélée,
        # nommées (information à vérifier, jamais une fuite confirmée).
        Array(split_tunnel[:missing_announced]).first(8).each do |item|
          next unless item.is_a?(Hash) && item[:address]
          where = case item[:where]
                  when :other_route then "présente via #{item[:via]} (drapeaux #{item[:flags]}), pas en route hôte physique"
                  when :ipv6        then 'IPv6 : non corrélée'
                  else 'absente de la table'
                  end
          lines << "-- ⚠️ Annoncée mais non corrélée : #{sanitize_xbar(item[:address])} (#{sanitize_xbar(where)})"
        end

        # Cas « couvert » : décomptes par groupe + écarts, pas la liste complète
        # (affichage par écarts, v5.8.1).
        covered = split_tunnel[:state] == :ok && split_tunnel[:leak] == false

        groups = {}
        others = []
        Array(split_tunnel[:evidence]).map(&:to_s).each do |raw|
          parts = raw.split
          if parts.size >= 4 && parts[0].match?(%r{\A[0-9a-fA-F:.]+(?:/\d+)?\z}) && parts[1].match?(/\A[0-9a-fA-F:.%\w]+\z/)
            (groups[[parts[1], parts[3], parts[2]]] ||= []) << parts[0]
          elsif !raw.strip.empty?
            others << raw.strip
          end
        end

        if groups.keys.any? { |(_gateway, _iface, flags)| flags.to_s.include?('1') }
          lines << "-- ℹ️ PROTO1 : marquage posé à la création de la route ; indice d'outil, pas une preuve"
        end

        remaining = max_addresses
        ordered_groups = groups.to_a.each_with_index.sort_by { |(_key, addresses), index| [-addresses.size, index] }.map(&:first)
        ordered_groups.each do |(gateway, iface, flags), addresses|
          marker = flags.to_s.include?('1') ? ' • marquage PROTO1' : ''
          lines << "-- #{addresses.size} route(s) hôte via #{sanitize_xbar(gateway)} (#{sanitize_xbar(iface)}) • drapeaux #{sanitize_xbar(flags)}#{marker}"
          next if covered
          ordered = addresses.sort_by { |address| sortable_ip(address) }
          shown = ordered.first(remaining)
          remaining -= shown.size
          # fold : adresses en sous-menu replié ; comportement par défaut inchangé.
          address_prefix = fold ? '----' : '--'
          shown.each_slice(4) { |chunk| lines << "#{address_prefix} #{chunk.map { |address| sanitize_xbar(address) }.join(' · ')}" }
          lines << "-- … +#{ordered.size - shown.size} adresse(s)" if shown.size < ordered.size
        end

        if covered
          lines << "-- ℹ️ Aucun écart : exceptions confirmées (adresses non énumérées)"
        end

        others.first(12).each { |item| lines << "-- #{sanitize_xbar(clip(item, 200))}" }
        lines << "-- … +#{others.size - 12} autre(s)" if others.size > 12
        lines
      end

      def self.firewall_label(status)
        case status
        when true then '🟡 Règle PF détectée (protection non validée)'
        when false then '🔴 Non sécurisé / désactivé'
        when :unauthorized then '🟡 Non vérifiable (droits insuffisants)'
        else '⚪ Non vérifiable'
        end
      end
      private

      def self.sanitize_xbar(str)
        VPNChecker::Helpers.clean_str(str, 'Inconnu').gsub('|', '/').gsub("\n", ' ').strip
      end
    end
  end

  class Application
    # Routes corrélées < routes annoncées : Split rétrograde :ok -> :unknown
    # avant le calcul du score (preuves conservées).
    def self.reconcile_split_tunnel(split_result, vpnb_status)
      return split_result unless split_result.is_a?(Hash) && vpnb_status.is_a?(Hash)
      return split_result unless split_result[:state] == :ok
      return split_result unless vpnb_status[:state] == :detected

      active = vpnb_status[:active_route_count]
      # v5.9.8 : décompte par destination unique quand le détecteur le fournit ;
      # repli sur declared_count (anciens résultats, tests).
      correlated = split_result[:declared_unique_count]
      correlated = split_result[:declared_count] unless correlated.is_a?(Integer)
      return split_result unless active.is_a?(Integer) && correlated.is_a?(Integer)
      return split_result unless active > correlated

      missing = active - correlated
      named = Array(split_result[:missing_announced]).any?
      # Écart exposé une seule fois : raison courte ici, détail en sous-menu.
      reason = "Réconciliation incomplète : #{correlated}/#{active} routes VPN Bypass corrélées ; #{missing} route(s) annoncée(s) absente(s) de la table" +
               (named ? '.' : '. Cause non déterminée.')
      split_result.merge(
        state: :unknown, confidence: [split_result[:confidence].to_i, 45].min,
        leak: nil, detected: true, unknown: true, severity: :unknown,
        reason: reason,
        message: "🟡 Split Tunnel à réconcilier (#{correlated}/#{active} corrélées ; #{missing} manquante#{missing > 1 ? 's' : ''})"
      )
    end

    def initialize
      @lru_cache = Infrastructure::AdaptiveLRUCache.new(50)
    end

    def build_context
      generate_live_context
    end

    def build_offline_context(snapshot, dns_resolver)
      Logger.warn("Connectivité externe non vérifiée par les sondes TCP ; contrôles distants différés.")
      vpn_result = Detectors::VPNDetector.new(snapshot: snapshot).detect
      vpn_active = vpn_result.is_a?(Hash) && vpn_result[:active] == true
      # Contrôles sur observations locales : restent évaluables si sondes externes
      # échouent.
      ks_result = Detectors::KillSwitchDetector.new(snapshot: snapshot).detect(vpn_active: vpn_active)
      split_result = Detectors::SplitTunnelDetector.new(snapshot: snapshot).detect(vpn_active: vpn_active)
      {
        offline: true, connectivity_unverified: true, ip_ok: false, ips: { v4: nil, v6: nil },
        geo: Intelligence::GeoLookupService.new.fallback_geo,
        ptr: nil, vpn: vpn_result,
        ks: ks_result,
        dns_leak: Detectors::BaseDetector.not_applicable_result(reason: 'Connectivité externe non vérifiée : contrôle DNS distant non exécuté.', leak: nil, detected: nil, severity: :unknown, message: '⚪ Fuites DNS non vérifiées (connectivité externe non vérifiée)'),
        webrtc_leak: Detectors::BaseDetector.not_applicable_result(reason: 'Connectivité externe non vérifiée : contrôle navigateur/distant non exécuté.', leak: nil, detected: nil, severity: :unknown, message: '⚪ WebRTC non vérifié (connectivité externe non vérifiée)'),
        tor: Detectors::BaseDetector.not_applicable_result(reason: 'Connectivité externe non vérifiée : contrôle distant non exécuté.', active: nil, message: '⚪ État Tor non vérifié'),
        ipv6: Detectors::LeakDetector.new(snapshot: snapshot).detect_ipv6_leak(snapshot, nil),
        apple_relay: Detectors::BaseDetector.not_applicable_result(reason: 'Connectivité externe non vérifiée : contrôle distant non exécuté.', active: nil, message: '⚪ Apple Relay non vérifié'),
        provider: Detectors::BaseDetector.not_applicable_result(reason: 'Connectivité externe non vérifiée : fournisseur non identifié.', provider: 'Inconnu', type: Enums::InfrastructureType[:UNKNOWN], confidence: 0),
        split_tunnel: split_result,
        dns_encrypted: Detectors::EncryptedDNSDetector.new(snapshot: snapshot).detect,
        app_firewall: Detectors::AppFirewallDetector.new.detect,
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

      ips = ip_lookup.fetch_public_ips(ipv6_lookup: snapshot.ipv6_interface_active?) || { v4: nil, v6: nil }

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
        provider: Detectors::ProviderDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        split_tunnel: Detectors::SplitTunnelDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        encrypted_dns: Detectors::EncryptedDNSDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        open_ports: Detectors::OpenPortsDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver),
        app_firewall: Detectors::AppFirewallDetector.new(snapshot: snapshot, http_client: http_client, dns_resolver: dns_resolver)
      }

      results = {}
      mutex = Mutex.new
      threads = []

      # Pré-chargement synchrone du snapshot pour éviter les conditions de course sur les threads
      snapshot.refresh!

      # Détection synchrone de l'état du VPN (nécessaire pour alimenter les autres détecteurs)
      vpn_res = detectors[:vpn].detect
      results[:vpn] = vpn_res
      vpn_active = vpn_res[:active]

      threads << Thread.new { res = detectors[:provider].detect(geo_info: geo, ip: ips[:v4]); mutex.synchronize { results[:provider] = res } }
      threads << Thread.new { res = detectors[:webrtc].detect(vpn_ip: ips[:v4]); mutex.synchronize { results[:webrtc_leak] = res } }
      threads << Thread.new { res = detectors[:tor].detect(ip: ips[:v4]); mutex.synchronize { results[:tor] = res } }
      threads << Thread.new { res = detectors[:leak].detect_ipv6_leak(snapshot, ips[:v6]); mutex.synchronize { results[:ipv6] = res } }
      threads << Thread.new { res = detectors[:encrypted_dns].detect; mutex.synchronize { results[:dns_encrypted] = res } }
      threads << Thread.new {
        res = detectors[:open_ports].detect_result
        mutex.synchronize { results[:open_ports_status] = res; results[:open_ports] = res[:ports] }
        # Meilleur effort : si l'attribution dépasse le délai global, la liste de base est conservée.
        enriched = detectors[:open_ports].attribute_processes(res[:ports])
        mutex.synchronize { results[:open_ports] = enriched }
      }
      threads << Thread.new { res = Infrastructure::FirewallChecker.check_result; mutex.synchronize { results[:firewall] = res; results[:firewall_status] = res[:firewall_status] } }
      threads << Thread.new { res = detectors[:app_firewall].detect; mutex.synchronize { results[:app_firewall] = res } }
      threads << Thread.new { res = Intelligence::PerformanceMonitor.measure(internet_available: true); mutex.synchronize { results[:perf] = res } }
      threads << Thread.new { res = detectors[:ks].detect(vpn_active: vpn_active); mutex.synchronize { results[:ks] = res } }
      threads << Thread.new { res = detectors[:dns_leak].detect(vpn_active: vpn_active); mutex.synchronize { results[:dns_leak] = res } }
      threads << Thread.new { res = detectors[:split_tunnel].detect(vpn_active: vpn_active); mutex.synchronize { results[:split_tunnel] = res } }

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + VPNChecker::Config::THREADS_DEADLINE
      threads.each do |t|
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        t.join([remaining, 0.0].max) if remaining > 0
      end
      threads.each do |t|
        next unless t.alive?
        t.kill
        t.join(0.05)
      end

      vpn_result          = results[:vpn]
      provider_result     = results[:provider] || Detectors::BaseDetector.timeout_result(provider: 'Inconnu', type: Enums::InfrastructureType[:UNKNOWN])
      webrtc_result       = results[:webrtc_leak] || Detectors::BaseDetector.timeout_result(leak: nil, message: '⚪ Non vérifiable (timeout)')
      tor_result          = results[:tor] || Detectors::BaseDetector.timeout_result(active: nil, message: '🟡 État Tor non vérifiable (délai dépassé)')
      ipv6_result         = results[:ipv6] || Detectors::BaseDetector.timeout_result(leak: nil, message: '⚪ Non vérifiable (timeout)', active: false)
      dns_encrypted       = results[:dns_encrypted] || Detectors::BaseDetector.timeout_result(encrypted: nil, methods: [], message: '⚪ Non vérifié (délai dépassé)')
      open_ports_result   = results[:open_ports] || []
      firewall_check      = results[:firewall] || Infrastructure::FirewallChecker.check_result
      firewall_status     = firewall_check[:firewall_status]
      app_firewall_result = results[:app_firewall] || Detectors::BaseDetector.timeout_result(enabled: nil, message: '⚪ Non vérifié (délai dépassé)')
      open_ports_status   = results[:open_ports_status] || Detectors::BaseDetector.timeout_result(ports: [], reason: 'Collecte des ports non terminée (délai) : liste vide ≠ aucun port.')
      perf                = results[:perf] || { latency: nil, jitter: nil }
      ks_result = results[:ks] || Detectors::BaseDetector.timeout_result(status: '🟡 Kill Switch non vérifiable (délai dépassé)', broken: nil, reason: 'Le détecteur n’a pas terminé dans le délai imparti.')
      dns_leak_result     = results[:dns_leak] || Detectors::BaseDetector.timeout_result(leak: nil, message: '⚪ Non vérifiable (timeout)')
      split_tunnel_result = results[:split_tunnel] || Detectors::BaseDetector.timeout_result(leak: nil, message: '🟡 Split Tunnel non vérifiable (délai dépassé)')

      # Même instant logique verdict/score/rendu : CLI lue une fois, réconciliation
      # avant SecurityScore.calculate.
      vpnb_status = Infrastructure::VPNBypassSource.status
      split_tunnel_result = self.class.reconcile_split_tunnel(split_tunnel_result, vpnb_status)

      dns_consistency     = calculate_dns_consistency(dns_resolver)
      ip_ok               = !Infrastructure::SecureDiskCache.invalid_value?(ips[:v4])

      base_context = {
        ips: ips, geo: geo, ptr: ptr_val, vpn: vpn_result, ks: ks_result,
        dns_leak: dns_leak_result, webrtc_leak: webrtc_result, tor: tor_result,
        ipv6: ipv6_result, provider: provider_result,
        split_tunnel: split_tunnel_result, vpnb_status: vpnb_status, dns_encrypted: dns_encrypted,
        open_ports: open_ports_result,
        dns_consistency: dns_consistency,
        dns_servers: format_dns_servers(dns_resolver),
        calculated_tunnel_dns: dns_resolver.detected_tunnel_dns,
        perf: perf, interface: snapshot.default_interface, ip_ok: ip_ok, offline: false,
        firewall_status: firewall_status,
        firewall: firewall_check,
        app_firewall: app_firewall_result,
        open_ports_status: open_ports_status
      }

      calculated_score = Intelligence::SecurityScore.calculate(base_context)
      score_coverage = Intelligence::SecurityScore.coverage(base_context)
      live_context_data = Renderers::ContextBuilder.new.generate_live_context(snapshot, geo)

      base_context.merge(
        sec_score: calculated_score,
        score_coverage: score_coverage,
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
      dns_servers = Array(dns_resolver.dns_servers).compact
      return '⚪ Non vérifiable' if dns_servers.empty?

      parsed = dns_servers.map do |server|
        addr = IPAddr.new(server) rescue nil
        [server, addr]
      end.select { |_server, addr| !addr.nil? }
      return '⚪ Non vérifiable' if parsed.empty?

      has_local = parsed.any? do |_server, addr|
        addr.loopback? || addr.private?
      end
      has_trusted_public = parsed.any? do |server, addr|
        addr.ipv4? && TRUSTED_DNS.include?(server)
      end

      if has_local && has_trusted_public
        '🟡 Configuration DNS mixte (heuristique)'
      else
        # Cette méthode ne prouve pas à elle seule le chemin réseau des requêtes.
        '⚪ Configuration observée, chemin non vérifié'
      end
    end

    def format_dns_servers(dns_resolver)
      # Étiqueteur unique du renderer (charte, point 17) ; corrige la rétention
      # d'`addr` entre itérations de l'ancienne version.
      dns_resolver.dns_servers
                  .map { |dns| Renderers::XbarRenderer.dns_server_label(dns) }
                  .uniq
    end
  end

  
  end

begin
  arg_action = ARGV[0].to_s.strip.downcase
  if arg_action == 'dnscrypt-audit'
    data = VPNChecker::Renderers::DNSCryptConfigAudit.run!
    VPNChecker::Renderers::DNSCryptConfigAudit.menu_lines(data).each { |line| puts line }
    exit 0
  elsif arg_action == 'dnscrypt-block-probe'
    data = VPNChecker::Renderers::DNSCryptBlockProbe.run!
    VPNChecker::Renderers::DNSCryptBlockProbe.menu_lines(data).each { |line| puts line }
    exit 0
  elsif arg_action == 'dns-stack-audit'
    data = VPNChecker::Renderers::DNSStackAudit.run!
    VPNChecker::Renderers::DNSStackAudit.menu_lines(data).each { |line| puts line }
    exit 0
  elsif arg_action == 'dns-diag'
    data = VPNChecker::Renderers::DNSDiag.run!
    VPNChecker::Renderers::DNSDiag.menu_lines(data).each { |line| puts line }
    exit 0
  elsif arg_action == 'dns-probe'
    data = VPNChecker::Renderers::ManualDNSProbe.run!
    VPNChecker::Renderers::ManualDNSProbe.menu_lines(data).each { |line| puts line }
    exit 0
  elsif arg_action == 'purge'
    VPNChecker::Infrastructure::SecureDiskCache.purge_all!
    puts "Cache purgé !"
    exit 0
  elsif ARGV.include?('--version')
    puts "VPN Checker v#{VPNChecker::APP_VERSION}"
    exit 0
  elsif ARGV.include?('--commands')
    actual = File.basename(__FILE__)
    VPNChecker.control_commands(actual).each { |line| puts line }
    unless actual == VPNChecker.expected_file_name
      puts "⚠️ Nom de fichier attendu pour v#{VPNChecker::APP_VERSION} : #{VPNChecker.expected_file_name} (actuel : #{actual})"
    end
    exit 0
  elsif VPNChecker::RUN_TESTS
    VPNChecker::TestRunner.run!
  else
    VPNChecker::Application.new.render
  end

# Rescue global de rendu
rescue StandardError => e
  VPNChecker::Logger.error("Crash application: #{e.class} - #{e.message}\n#{e.backtrace.first(3).join("\n")}")
  puts "⚠️ 🌐 | color=red"
  puts "---"
  puts "VPN Checker Erreur | font=Menlo"
  puts "---"
  puts "Message: #{VPNChecker::Renderers::XbarRenderer.send(:sanitize_xbar, e.message)}"
end
