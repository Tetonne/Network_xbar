#!/usr/bin/env ruby
# frozen_string_literal: true
# script pour macOS (Catalina... Sequoia) avec ruby 2.6 dans l'application xbar.app

require 'digest'
require 'ipaddr'
require 'json'
require 'set'
require 'socket'
require 'net/http'
require 'uri'
require 'fileutils'
require 'timeout'
require 'tmpdir'
require 'open3'
require 'openssl'
require 'base64'
require 'logger'
require 'yaml'
require 'time'

# ==============================================================================
# 0. CONFIGURATION EXTERNALISÉE (YAML)
# ==============================================================================
CONFIG_DATA = <<~YAML
  app_version: "v3.1.6"
  thread_timeout: 1.0
  debug_errors: true
  allowed_countries: ["NL", "CH", "PL", "RO", "US"]
  deny_countries: ["FR"]
  ping_hosts: ["1.1.1.1", "8.8.8.8"]
  trusted_dns: 
    - "1.1.1.1"
    - "1.0.0.1"
    - "8.8.8.8"
    - "8.8.4.4"
    - "9.9.9.9"
    - "149.112.112.112"
    - "127.0.0.1"
    - "2606:4700:4700::1111"
    - "2606:4700:4700::1001"
    - "2001:4860:4860::8888"
    - "2001:4860:4860::8844"
    - "2620:fe::fe"
    - "2620:fe::9"
    - "::1"
  known_safe_dns_asns: ["13335", "15169", "19281", "34939", "212772"]
  known_proton_asn: ["212238", "51852"]
  apple_relay_asns: ["6185", "714", "54114", "213426"]
  vpn_provider_keywords:
    proton: "ProtonVPN"
    mullvad: "Mullvad"
    nordvpn: "NordVPN"
    surfshark: "Surfshark"
    expressvpn: "ExpressVPN"
    ivpn: "IVPN"
    cyberghost: "CyberGhost"
    pia: "Private Internet Access"
    m247: "M247"
    datacamp: "DataCamp"
    leaseweb: "Leaseweb"
    digitalocean: "DigitalOcean"
    ovh: "OVH"
    choopa: "Choopa"
    vultr: "Vultr"
    hetzner: "Hetzner"
  dns_providers:
    "1.1.1.1": "☁️ Cloudflare"
    "1.0.0.1": "☁️ Cloudflare"
    "2606:4700:4700::1111": "☁️ Cloudflare"
    "2606:4700:4700::1001": "☁️ Cloudflare"
    "8.8.8.8": "🟦 Google"
    "8.8.4.4": "🟦 Google"
    "2001:4860:4860::8888": "🟦 Google"
    "2001:4860:4860::8844": "🟦 Google"
    "9.9.9.9": "🌐 Quad9"
    "149.112.112.112": "🌐 Quad9"
    "2620:fe::fe": "🌐 Quad9"
    "2620:fe::9": "🌐 Quad9"
    "94.140.14.14": "🛡️ AdGuard"
    "94.140.15.15": "🛡️ AdGuard"
    "45.90.28.0": "🧬 NextDNS"
    "45.90.30.0": "🧬 NextDNS"
    "194.242.2.2": "🦈 Mullvad DNS"
    "194.242.2.3": "🦈 Mullvad DNS"
    "76.76.2.0": "🎛️ ControlD"
    "76.76.10.0": "🎛️ ControlD"
    "208.67.222.222": "🔓 OpenDNS"
    "208.67.220.220": "🔓 OpenDNS"
    "185.228.168.9": "🧼 CleanBrowsing"
    "185.228.169.9": "🧼 CleanBrowsing"
    "193.110.81.0": "🇪🇺 DNS0"
    "185.253.5.0": "🇪🇺 DNS0"
    "127.0.0.1": "🔐 DNSCrypt / Proxy Local"
    "::1": "🔐 DNSCrypt / Proxy Local"
  colors:
    secure: "#006400"
    warn: "#FF9500"
    alert: "#FF3B30"
YAML

class AppConfig
  def initialize
    @config = YAML.safe_load(CONFIG_DATA)
    @mutex = Mutex.new
  end

  def self.instance
    @instance ||= Mutex.new.synchronize { @instance || new }
  end

  def get(key)
    @mutex.synchronize { @config[key.to_s] }
  end
end

# ==============================================================================
# 1. LOGS ET SÉCURITÉ DE BASE
# ==============================================================================

class StructuredLogger
  def initialize(log_file = STDOUT)
    @logger = Logger.new(log_file)
    @logger.formatter = ->(severity, datetime, _progname, msg) {
      { timestamp: datetime.iso8601, severity: severity, message: msg }.to_json + "\n"
    }
    @mutex = Mutex.new
  end

  def self.instance
    @instance ||= Mutex.new.synchronize { @instance || new }
  end

  def debug(msg)
    @mutex.synchronize { @logger.debug(msg) }
  end

  def info(msg)
    @mutex.synchronize { @logger.info(msg) }
  end

  def warn(msg)
    @mutex.synchronize { @logger.warn(msg) }
  end

  def error(msg)
    @mutex.synchronize { @logger.error(msg) }
  end
end

DEBUG     = ARGV.include?("--debug")
JSON_MODE = ARGV.include?("--json")

def debug(msg)
  warn "[DEBUG] #{msg}" if DEBUG
end

class SecurityManager
  def initialize
    @mutex = Mutex.new
  end

  def self.instance
    @instance ||= Mutex.new.synchronize { @instance || new }
  end

  def encryption_key
    @encryption_key ||= @mutex.synchronize do
      computer = `scutil --get ComputerName`.chomp rescue "mac"
      host     = `scutil --get LocalHostName`.chomp rescue "local"
      user     = ENV['USER'] || 'default'
      Digest::SHA256.digest("#{computer}#{host}#{user}")
    end
  end

  def encrypt_data(data)
  return nil if data.to_s.empty?
  
  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.encrypt
  
  # 1. On s'assure de l'affectation stricte de la clé secrète de 32 octets
  cipher.key = encryption_key
  
  # 2. Configuration sécurisée de l'IV
  iv = cipher.random_iv # Génère automatiquement l'IV avec la bonne longueur
  cipher.iv = iv
  
  # 3. Chiffrement des données fondamentales
  encrypted = cipher.update(data.to_s) + cipher.final
  
  # 4. Extraction obligatoire du tag d'authentification propre au mode GCM
  tag = cipher.auth_tag
  
  payload = {
    v: 1,
    iv: Base64.strict_encode64(iv),
    tag: Base64.strict_encode64(tag),
    data: Base64.strict_encode64(encrypted)
  }
  Base64.strict_encode64(JSON.generate(payload))
rescue StandardError => e
  StructuredLogger.instance.error("encrypt_data failed: #{e.class} - #{e.message}")
  nil
end

  def decrypt_data(encoded_data)
    return nil if encoded_data.to_s.strip.empty?
    payload = JSON.parse(Base64.strict_decode64(encoded_data)) rescue nil
    return nil unless payload && payload["v"] == 1
    
    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.decrypt
    cipher.key = encryption_key
    cipher.iv = Base64.strict_decode64(payload["iv"])
    cipher.auth_tag = Base64.strict_decode64(payload["tag"])
    
    encrypted = Base64.strict_decode64(payload["data"])
    cipher.update(encrypted) + cipher.final
  rescue StandardError => e
    StructuredLogger.instance.error("decrypt_data failed: #{e.class} - #{e.message}")
    nil
  end
end

def log_secure(message)
  return unless DEBUG
  encrypted_msg = SecurityManager.instance.encrypt_data("[#{Time.now.strftime('%Y-%m-%dT%H:%M:%S%z')}] #{message}")
  if encrypted_msg
    warn "[SECURE-LOG] #{encrypted_msg}"
  else
    warn "[SECURE-LOG-FAIL] Chiffrement échoué"
  end
end

# ==============================================================================
# 2. CACHE COUCHE & GESTION THREAD-SAFE SINGLETONS
# ==============================================================================

class LRUCachePro
  Entry = Struct.new(:value, :ts, :loading, keyword_init: true)

  def initialize(max_size: 500, ttl_default: 30)
    @max_size = max_size
    @ttl_default = ttl_default
    @data = {}
    @order = []
    @mutex = Mutex.new
    @stats = { hit: 0, miss: 0, expired: 0, stampede_block: 0 }
  end

  def self.instance
    @instance ||= Mutex.new.synchronize { @instance || new }
  end

  def fetch(key, ttl: nil)
    ttl ||= @ttl_default
    now = Time.now.to_i
    cleanup_expired(now)

    @mutex.synchronize do
      entry = @data[key]
      if entry && (now - entry.ts < ttl)
        @stats[:hit] += 1
        touch(key)
        return entry.value
      end
      if entry && entry.loading
        @stats[:stampede_block] += 1
        return entry.value
      end
      @stats[:miss] += 1
      @data[key] = Entry.new(value: nil, ts: now, loading: true)
    end

    value = yield

    @mutex.synchronize do
      evict_if_needed
      @data[key] = Entry.new(value: value, ts: now, loading: false)
      @order << key
    end
    value
  end

  def fetch_geo_provider(url_str, timeout: 1.5)
    uri = URI(url_str)
    ResilienceEngine.instance.execute_with_backoff do
      Net::HTTP.start(uri.host, uri.port,
               use_ssl: true,
               verify_mode: OpenSSL::SSL::VERIFY_PEER,
               open_timeout: timeout,
               read_timeout: timeout) do |http|
        res = http.get(uri.request_uri)
        return JSON.parse(res.body) if res.is_a?(Net::HTTPSuccess)
      end
    end
  rescue StandardError => e
    StructuredLogger.instance.error("fetch_geo_provider fail pour #{url_str}: #{e.message}")
    nil
  end

  def stats
    @mutex.synchronize { @stats.dup }
  end

  private

  def touch(key)
    @order.delete(key)
    @order << key
  end

  def evict_if_needed
    while @order.size > @max_size
      old = @order.shift
      @data.delete(old)
    end
  end

  def cleanup_expired(now)
    @mutex.synchronize do
      @data.each do |k, v|
        if v && (now - v.ts > @ttl_default * 2)
          @data.delete(k)
          @order.delete(k)
          @stats[:expired] += 1
        end
      end
    end
  end
end

class StateManager
  def initialize
    @runtime_ctx = { using_public_ip: false, fallback_used: false }
    @mutex = Mutex.new
  end

  def self.instance
    @instance ||= Mutex.new.synchronize { @instance || new }
  end

  def get_ctx(key)
    @mutex.synchronize { @runtime_ctx[key] }
  end

  def set_ctx(key, val)
    @mutex.synchronize { @runtime_ctx[key] = val }
  end

  def system_state
    memoized("system_state", 5) do
      ifconfig_out, _ = Open3.capture2("ifconfig")
      scutil_out, _   = Open3.capture2("scutil", "--nwi")
      route_out, _    = Open3.capture2("route", "-n", "get", "default")
      {
        ifconfig: ifconfig_out,
        scutil: scutil_out,
        route: route_out
      }
    end
  end

  def memoized(key, ttl = 30)
    stack = (Thread.current[:memo_stack] ||= [])
    return yield if stack.include?(key)
    stack << key
    begin
      LRUCachePro.instance.fetch(key, ttl: ttl) { yield }
    ensure
      stack.delete_at(stack.rindex(key) || 0)
    end
  end
end

def memoized(key, ttl = 30, &block)
  StateManager.instance.memoized(key, ttl, &block)
end

class ResilienceEngine
  def initialize
    @circuit_breakers = {}
    @mutex = Mutex.new
  end

  def self.instance
    @instance ||= Mutex.new.synchronize { @instance || new }
  end

  def execute_with_backoff(max_retries = 2)
    retries = 0
    begin
      yield
    rescue StandardError => e
      if retries < max_retries
        sleep_time = 0.3 * (2**retries)
        sleep(sleep_time)
        retries += 1
        retry
      else
        raise e
      end
    end
  end

  def execute_with_circuit_breaker(url, max_failures: 3, reset_after: 60)
    key = Digest::SHA256.hexdigest(url)
    @mutex.synchronize do
      @circuit_breakers[key] ||= { failures: 0, last_failure: nil }
    end

    now = Time.now
    if @circuit_breakers[key][:failures] >= max_failures && now - @circuit_breakers[key][:last_failure] < reset_after
      debug("Circuit breaker open for #{url}")
      return nil
    end

    execute_with_backoff do
      result = yield
      @mutex.synchronize { @circuit_breakers[key][:failures] = 0 }
      result
    end
  rescue StandardError => e
    @mutex.synchronize do
      @circuit_breakers[key][:failures] += 1
      @circuit_breakers[key][:last_failure] = now
    end
    raise e
  end
end

# ==============================================================================
# 3. UTILS RESEAU IP ET PROTECTIONS
# ==============================================================================

module IPGuard
  module_function
  MULTICAST_V4 = IPAddr.new('224.0.0.0/4')
  MULTICAST_V6 = IPAddr.new('ff00::/8')

  def parse(ip)
    return nil if ip.nil?
    IPAddr.new(ip.to_s.split('%').first.strip)
  rescue IPAddr::InvalidAddressError
    nil
  end

  def localhost?(ip)
    addr = parse(ip)
    addr ? addr.loopback? : false
  end

  def private_ip?(ip)
    addr = parse(ip)
    addr ? addr.private? : false
  end

  def sanitize(ip)
    addr = parse(ip)
    return nil unless addr
    return nil if addr.loopback? || addr.link_local? || multicast?(addr)
    ip
  end

  def multicast?(addr)
    (addr.ipv4? && MULTICAST_V4.include?(addr)) || (addr.ipv6? && MULTICAST_V6.include?(addr))
  end

  def valid_format?(ip)
    !parse(ip).nil?
  end
end

module DiskCache
  CACHE_DIR = File.join(Dir.tmpdir, "xbar_vpn_check2").freeze

  class << self
    def setup
      FileUtils.mkdir_p(CACHE_DIR)
      File.chmod(0700, CACHE_DIR) if File.directory?(CACHE_DIR)
    rescue StandardError => e
      StructuredLogger.instance.error("DiskCache.setup: #{e.message}")
    end

    def safe_json_parse(data)
      return nil if data.nil? || data.empty?
      JSON.parse(data)
    rescue JSON::ParserError
      nil
    end

    def fetch(key, ttl: 3600)
      setup
      file_key = Digest::SHA256.hexdigest(key)
      cache_file = File.join(CACHE_DIR, "cache.#{file_key}.json")

      if File.exist?(cache_file) && (Time.now - File.mtime(cache_file) < ttl)
        begin
          encrypted = File.read(cache_file)
          decrypted = SecurityManager.instance.decrypt_data(encrypted)
          cached = safe_json_parse(decrypted)
          return cached["data"] if cached&.key?("data")
        rescue StandardError
        end
      end

      value = yield

      begin
        if value
          tmp = "#{cache_file}.tmp.#{$$}"
          encrypted = SecurityManager.instance.encrypt_data(JSON.generate({ "data" => value }))
          File.write(tmp, encrypted)
          File.chmod(0600, tmp)
          File.rename(tmp, cache_file)
        end
      rescue StandardError => e
        StructuredLogger.instance.error("DiskCache.write: #{e.message}")
      end
      value
    end
  end
end

# ==============================================================================
# 4. ÉVOLUTIONS DEMANDÉES (CLASSES TOTALEMENT ENCAPSULÉES)
# ==============================================================================

class ProcessSnapshot
  def self.instance
    @instance ||= Mutex.new.synchronize { @instance || new }
  end

  def get
    @proc_cache ||= { ts: 0, value: Set.new }
    now = Time.now.to_i
    return @proc_cache[:value] if now - @proc_cache[:ts] < 5

    stdout, status = Open3.capture2("ps", "-A", "-o", "comm=")
    return Set.new unless status.success?
    value = stdout.lines.map { |l| File.basename(l.strip).downcase }.to_set
    @proc_cache = { ts: now, value: value }
    value
  rescue StandardError => e
    StructuredLogger.instance.error("process_snapshot fail: #{e.message}")
    Set.new
  end
end

class IPFetcher
  def self.instance
    @instance ||= Mutex.new.synchronize { @instance || new }
  end

  def fetch
    StateManager.instance.memoized("public_ip", 300) do
      urls = [
        { url: "https://api64.ipify.org?format=text", ipv: :v4, timeout: 1.0 },
        { url: "https://api.ipify.org?format=text", ipv: :v4, timeout: 1.0 },
        { url: "https://checkip.amazonaws.com", ipv: :v4, timeout: 1.5 },
        { url: "https://api6.ipify.org?format=text", ipv: :v6, timeout: 1.5 },
        { url: "https://v6.ident.me", ipv: :v6, timeout: 2.0 }
      ].uniq { |entry| entry[:url] }

      queue = Thread::Queue.new
      threads = urls.map do |entry|
        Thread.new do
          uri = URI(entry[:url])
          ResilienceEngine.instance.execute_with_circuit_breaker(entry[:url]) do
            Net::HTTP.start(uri.host, uri.port,
                           use_ssl: true,
                           verify_mode: OpenSSL::SSL::VERIFY_PEER,
                           open_timeout: entry[:timeout],
                           read_timeout: entry[:timeout]) do |http|
              res = http.get(uri.request_uri)
              if res.is_a?(Net::HTTPSuccess)
                ip = res.body.to_s.strip
                sanitized = IPGuard.sanitize(ip)
                next unless sanitized
                addr = IPGuard.parse(sanitized)
                next unless addr
                queue.push({ ip: sanitized, version: addr.ipv4? ? :v4 : :v6 })
              end
            end
          end
        rescue StandardError => e
          StructuredLogger.instance.error("HTTP request failed for #{entry[:url]}: #{e.class} - #{e.message}")
        end
      end

      result = []
      success_count = 0
      begin
        timeout_val = AppConfig.instance.get(:thread_timeout) || 1.0
        Timeout.timeout(timeout_val) do
          while (entry = queue.pop(true) rescue nil)
            result << entry
            result.uniq! { |e| e[:ip] }
            success_count += 1
          end
        end
      rescue Timeout::Error
        StructuredLogger.instance.warn("Timeout expired for fetch_ip (#{success_count}/#{urls.size} succeeded)")
      ensure
        threads.each { |th| th.kill rescue nil }
        threads.each { |th| th.join rescue nil }
      end

      ipv4 = result.find { |e| e[:version] == :v4 }&.dig(:ip)
      final_ip = ipv4 || result.first&.dig(:ip) || last_known_good_ip
      store_last_known_good_ip(final_ip) if final_ip && IPGuard.valid_format?(final_ip)
      final_ip
    end
  end

  def last_known_good_ip
    DiskCache.setup
    path = File.join(DiskCache::CACHE_DIR, "last_good_ip.json")
    return nil unless File.exist?(path)
    data = JSON.parse(File.read(path)) rescue nil
    return nil unless data && data["ip"] && data["ts"]
    return nil if Time.now.to_i - data["ts"] > 86_400
    ip = data["ip"]
    (IPGuard.valid_format?(ip) && IPGuard.sanitize(ip)) ? ip : nil
  end

  def store_last_known_good_ip(ip)
    return unless ip.is_a?(String) && IPGuard.sanitize(ip)
    DiskCache.setup
    path = File.join(DiskCache::CACHE_DIR, "last_good_ip.json")
    tmp  = "#{path}.tmp.#{$$}"
    File.write(tmp, JSON.generate(ip: ip, ts: Time.now.to_i))
    File.chmod(0600, tmp)
    File.rename(tmp, path)
  rescue StandardError => e
    StructuredLogger.instance.error("store_last_known_good_ip: #{e.message}")
  end
end



class GeoLookup
  def self.instance
    @instance ||= Mutex.new.synchronize { @instance || new }
  end

def local_geo_fallback
  {
    "country_code" => "🏳️",
    "org" => "Réseau Local / Inconnu",
    "isp" => "Inconnu",
    "asn" => nil,
    "asn_org" => "Inconnu"
  }
end


def lookup(ip)
  cleaned_ip = ip.to_s.strip
  return local_geo_fallback unless IPGuard.sanitize(cleaned_ip)

  StateManager.instance.memoized("geo_ram_cache_#{cleaned_ip}", 86_400) do
    DiskCache.fetch("geo_v9_#{cleaned_ip}", ttl: 86_400) do
      urls = [
        { url: "https://ipwho.is/#{cleaned_ip}", parser: "ipwho", priority: 1 },
        { url: "https://ip-api.com/json/#{cleaned_ip}?fields=status,countryCode,org,as,isp", parser: "ipapi", priority: 2 },
        { url: "https://ipinfo.io/#{cleaned_ip}/json", parser: "ipinfo", priority: 3 }
      ].sort_by { |entry| entry[:priority] }

      final_result = nil
      urls.each do |entry|
        raw = LRUCachePro.instance.fetch_geo_provider(entry[:url])
        result = normalize_geo(raw, entry[:parser])
        if result
          final_result = result
          break
        end
      end
      
      final_result || local_geo_fallback
    end
  end
end



  private

  def normalize_geo(data, provider)
    return nil if data.nil? || data.empty?
    case provider
    when "ipinfo"
      return nil if data["bogon"] == true
      {
        "country_code" => data["country"],
        "org" => data["org"],
        "isp" => data["org"],
        "asn" => data["asn"] ? "AS#{data["asn"]}" : nil,
        "asn_org" => data["org"]
      }
    when "ipwho"
      return nil if data["success"] == false
      conn = data["connection"] || {}
      {
        "country_code" => data["country_code"] || data["country"],
        "org" => conn["org"],
        "isp" => conn["isp"],
        "asn" => conn["asn"] ? "AS#{conn["asn"]}" : nil,
        "asn_org" => conn["org"]
      }
    when "ipapi"
      return nil if data["status"] == "fail"
      asn_num = data["as"] ? data["as"].split(" ").first : nil
      {
        "country_code" => data["countryCode"],
        "org" => data["org"],
        "isp" => data["isp"],
        "asn" => asn_num,
        "asn_org" => data["org"]
      }
    end
  end
end

class ProxyDetector
  def self.instance
    @instance ||= Mutex.new.synchronize { @instance || new }
  end

  def detected?
    return true if ENV['HTTP_PROXY'] || ENV['HTTPS_PROXY'] || ENV['SOCKS_PROXY']
    stdout, status = Open3.capture2("networksetup", "-getwebproxy", "Wi-Fi")
    status.success? && stdout.include?("Enabled: Yes")
  rescue StandardError
    false
  end
end

# Rétrocompatibilité du module NetworkAnalyzer sans casser le reste du script
module NetworkAnalyzer
  module_function
  def fetch_ip; IPFetcher.instance.fetch; end
  def geo(ip); GeoLookup.instance.lookup(ip); end
  def proxy_detected?; ProxyDetector.instance.detected?; end
  
  def split_tunneling?
    stdout, status = Open3.capture2("netstat", "-rn")
    return false unless status.success?
    vpn_interfaces = %w[utun wg tailscale tun ipsec]
    default_routes = stdout.lines.select { |l| l.start_with?("default") }
    vpn_routes = stdout.lines.count { |l| vpn_interfaces.any? { |iface| l.include?(iface) } }
    has_non_vpn_default = default_routes.any? { |line| !vpn_interfaces.any? { |iface| line.include?(iface) } }
    has_non_vpn_default && vpn_routes > 0
  rescue StandardError
    false
  end
end

# ==============================================================================
# 5. DIAGNOSTICS ET OUTILS SCRIPT D'ORIGINE
# ==============================================================================

module NetTools
  TEST_HOSTS = [["1.1.1.1", 53], ["8.8.8.8", 53]].freeze
  module_function
  def internet?
    TEST_HOSTS.any? do |host, port|
      begin
        Socket.tcp(host, port, connect_timeout: 1) { true }
      rescue StandardError
        false
      end
    end
  end
end

unless NetTools.internet?
  puts "⚠️ Hors ligne | dropdown=false"
  exit 0
end

def flag(country)
  return "🏳️" unless country.is_a?(String) && country.match?(/\A[A-Z]{2}\z/)
  StateManager.instance.memoized("flag_#{country}", 86400) do
    country.upcase.chars.map { |c| (0x1F1E6 + c.ord - 65).chr(Encoding::UTF_8) }.join
  end
rescue StandardError
  "🏳️"
end


module DNSAnalyzer
  module_function

  def collect
    stdout, status = Open3.capture2("scutil", "--dns")
    return collect_fallback unless status.success?
    dns_list = stdout.scan(/nameserver\[\d+\]\s*:\s*([0-9a-fA-F:\.]+)/i).flatten.uniq.select { |ip| IPGuard.valid_format?(ip) }
    dns_list.empty? ? collect_fallback : dns_list
  rescue StandardError
    []
  end

  def collect_fallback
    stdout, _ = Open3.capture2("networksetup", "-getdnsservers", "Wi-Fi")
    stdout.lines.map(&:strip).select { |ip| IPGuard.valid_format?(ip) }
  rescue StandardError
    []
  end

  def normalize(dns_list, vpn_active)
    local, vpn, public_dns = [], [], []
    dns_list.each do |ip|
      next unless IPGuard.valid_format?(ip)
      if IPGuard.localhost?(ip)
        local << ip
      elsif IPGuard.private_ip?(ip)
        vpn_active ? vpn << ip : local << ip
      else
        public_dns << ip
      end
    end
    { local: local.uniq, vpn: vpn.uniq, public: public_dns.uniq }
  end

  def health(public_dns, vpn_dns, vpn_active, _current_ip_geo = nil)
    public_dns ||= []
    vpn_dns ||= []
    all_dns = public_dns + vpn_dns
    all_dns += collect.select { |ip| ip.include?(":") }
    
    doh_active = doh_detect
    dot_active = dot_detect
    encryption_active = vpn_dns.any? || public_dns.include?("127.0.0.1") || public_dns.include?("::1") || doh_active || dot_active
    
    leak = false
    leak_reasons = []

    if vpn_active
      scutil_out, _ = Open3.capture2("scutil", "--dns")
      dns_interfaces = scutil_out.scan(/nameserver\[\d+\]\s*:\s*([0-9a-fA-F:\.]+)\s*\(([^)]+)\)/).map { |_, ip, iface| [ip, iface] }

      trusted = AppConfig.instance.get(:trusted_dns) || []
      dns_interfaces.each do |dns_ip, iface|
        next if trusted.include?(dns_ip)
        next if iface.include?("utun") || iface.include?("wg") || iface.include?("tun") || iface.include?("tailscale")
        if iface.include?("en") || iface.include?("Wi-Fi")
          leak = true
          leak_reasons << { dns: dns_ip, interface: iface, type: "DNS Query Bypassing VPN Tunnel" }
        end
      end
    end

    status = if leak
               :dns_leak
             elsif encryption_active
               :dns_secure
             else
               :dns_uncertain
             end
    { leak: leak, ipv6_leak: false, encryption: encryption_active, isolation: vpn_active ? !leak : encryption_active, status: status, leak_reasons: leak_reasons }
  end

  def consistency(vpn_detected, local, vpn, public_dns)
    return "🟢 Cohérent (Réseau Standard)" unless vpn_detected
    has_vpn_dns = vpn.any?
    has_pub_dns = public_dns.any?
    case
    when has_vpn_dns && !has_pub_dns
      "🔐 Sécurisé (Tunnel DNS Exclusif)"
    when has_vpn_dns && has_pub_dns
      "🟡 Mixte (Tunnel + Résolveurs Publics)"
    when has_pub_dns
      "⚠️ Danger (Fuite DNS probable)"
    else
      "🟢 Sécurisé (DNS Local/Inconnu)"
    end
  end

  def detect_encryption_type(dns_split, doh_active)
    dns_split ||= { public: [], vpn: [], local: [] }
    public_dns = dns_split[:public] || []
    vpn_dns = dns_split[:vpn] || []
    if doh_active
      "🔏 DNS-over-HTTPS (DoH)"
    elsif dot_detect
      "🔒 DNS-over-TLS (DoT)"
    elsif public_dns.include?("127.0.0.1") || public_dns.include?("::1")
      "🔐 Profil macOS Natif ou Local (DoT/DoH/DNSCrypt)"
    elsif !vpn_dns.empty?
      "🛡️ Chiffré via Tunnel VPN (Interne)"
    else
      "❌ Non chiffré (Clair / Standard)"
    end
  end

  def doh_detect(domain = "cloudflare.com")
    StateManager.instance.memoized("doh_#{domain}", 60) do
      begin
        uri = URI("https://cloudflare-dns.com/dns-query?name=#{domain}&type=A")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.open_timeout = 0.5
        http.read_timeout = 0.8
        req = Net::HTTP::Get.new(uri)
        req["accept"] = "application/dns-json"
        res = http.request(req)
        res.is_a?(Net::HTTPSuccess) ? JSON.parse(res.body)["Status"] == 0 : false
      rescue StandardError
        false
      end
    end
  end

  def dot_detect
    StateManager.instance.memoized("dot_port_853_check", 30) do
      begin
        Socket.tcp("1.1.1.1", 853, connect_timeout: 0.8) { true }
      rescue StandardError
        false
      end
    end
  end
end

module InfrastructureAnalyzer
  module_function

  def analyze(geo_info, vpn_ctx = nil)
    return [:unknown, "Fournisseur Inconnu"] if geo_info.nil?
    asn = geo_info["asn"].to_s
    org = geo_info["org"].to_s
    isp = geo_info["isp"].to_s
    text = "#{asn} #{org} #{isp} #{geo_info["asn_org"]}".downcase.strip
    provider = resolve_provider(text, vpn_ctx)
    type = classify_type(text)
    [type, provider]
  end

  def resolve_provider(text, vpn_ctx)
    if text.include?("proton") || (vpn_ctx && vpn_ctx[:proton])
      "ProtonVPN"
    elsif text.include?("mullvad")
      "Mullvad"
    else
      provider_name = "Fournisseur Inconnu"
      keywords = AppConfig.instance.get(:vpn_provider_keywords) || {}
      keywords.each do |keyword, name|
        if text.include?(keyword.to_s)
          provider_name = name
          break
        end
      end
      provider_name
    end
  end

  def classify_type(text)
    if %w[proton mullvad nordvpn surfshark expressvpn ivpn cyberghost pia private\ internet\ access].any? { |p| text.include?(p) }
      :vpn
    elsif %w[aws amazon gcp google\ cloud azure microsoft oracle\ cloud].any? { |p| text.include?(p) }
      :cloud
    elsif %w[ovh leaseweb m247 contabo digitalocean linode vultr hetzner].any? { |p| text.include?(p) }
      :hosting
    else
      :isp
    end
  end
end

module VPNDetector
  module_function

  def active_vpn_interfaces
    ifconfig_out = StateManager.instance.system_state[:ifconfig]
    ifconfig_out.scan(/^([a-z0-9]+):/i).flatten.select do |iface|
      iface.start_with?("utun") || iface.start_with?("wg") || iface.start_with?("ipsec") || iface.start_with?("tailscale") || iface.start_with?("tun")
    end
  end

  def wireguard_mtu_detected
    ifconfig_out = StateManager.instance.system_state[:ifconfig]
    mtus = ifconfig_out.scan(/mtu\s+(\d+)/i).flatten.map(&:to_i)
    mtus.include?(1420) || ifconfig_out.scan(/(utun\d+):.*mtu\s+(\d+)/m).any? do |_, mtu_val|
      mtu = mtu_val.to_i
      mtu > 576 && mtu <= 1432
    end
  end

  def active_vpn_sockets_detected
    StateManager.instance.memoized("vpn_sockets_scan", 10) do
      target_ports = [51820, 1194, 500, 4500, 853]
      detected = false
      lsof_args = target_ports.flat_map { |port| ["-iUDP:#{port}", "-iTCP:#{port}"] }
      stdout, status = Open3.capture2("lsof", "-nP", *lsof_args)
      
      if status.success?
        stdout.lines.each do |line|
          target_ports.each do |port|
            if line.include?(":#{port}") || (line.include?("->") && line.include?(".#{port} "))
              detected = true
              break
            end
          end
          break if detected
        end
      end
      detected
    end
  rescue StandardError
    false
  end

  def orphan_tunnels_detected(procs)
    utuns = active_vpn_interfaces.select { |i| i.start_with?("utun") || i.start_with?("tun") }
    return false if utuns.empty?
    vpn_processes = %w[wireguard wg tailscaled zerotier openvpn proton tunnel]
    any_proc_alive = vpn_processes.any? { |p| procs.any? { |x| x.include?(p) } }
    utuns.any? && !any_proc_alive
  end

  def active_default_interface
    route_out = StateManager.instance.system_state[:route]
    match = route_out.match(/interface:\s*([a-z0-9]+)/i)
    match ? match[1] : nil
  rescue StandardError
    nil
  end

  def utun_default_route?
    iface = active_default_interface
    return false unless iface
    iface.start_with?("utun") || iface.start_with?("wg") || iface.start_with?("tailscale") || iface.start_with?("tun")
  end

  def verify_process_signature(process_name)
    StateManager.instance.memoized("signature_verify_#{process_name}", 3600) do
      stdout, status = Open3.capture2("which #{process_name}")
      next false unless status.success?
      binary_path = stdout.strip
      _, sig_status = Open3.capture2("codesign", "-v", binary_path)
      sig_status.success?
    end
  rescue StandardError
    false
  end

  def vpn_state(procs = process_snapshot_global, geo_info = nil)
    @vpn_state_cache ||= { ts: 0, value: nil }
    now = Time.now.to_i
    return @vpn_state_cache[:value] if @vpn_state_cache[:value] && (now - @vpn_state_cache[:ts] < 8)

    vpn_processes = %w[wireguard wg tailscaled zerotier-one openvpn protonvpn proton ProtonVPNService]
    proc_active = vpn_processes.any? { |p| procs.any? { |x| x.include?(p.downcase) } }
    scutil_out = StateManager.instance.system_state[:scutil]
    ifconfig_out = StateManager.instance.system_state[:ifconfig]
    utuns = active_vpn_interfaces
    utun_route = utun_default_route?
    has_vpn_sockets = active_vpn_sockets_detected
    has_vpn_mtu = wireguard_mtu_detected

    interface_active = scutil_out.include?("utun") || scutil_out.include?("tun") || ifconfig_out.include?("POINTOPOINT") || !utuns.empty? || utun_route || has_vpn_mtu
    vpn_active_confirmed = (proc_active && interface_active) || (has_vpn_sockets && interface_active)

    proton_wireguard = vpn_active_confirmed && (utun_route || utuns.any? || procs.any? { |x| x.include?("wg") || x.include?("wireguard") })
    proton_detected = vpn_active_confirmed && (procs.any? { |p| p.include?("proton") && p.include?("vpn") } || scutil_out.downcase.include?("proton") || (utun_route && !utuns.empty? && procs.any? { |p| p.include?("proton") }) || proton_wireguard)

    infra_type, vpn_provider = InfrastructureAnalyzer.analyze(geo_info, { proton: proton_detected })
    confidence_score = vpn_confidence(vpn_active_confirmed, vpn_provider, infra_type, has_vpn_mtu, has_vpn_sockets, procs)

    signature_trusted = true
    %w[wireguard tailscaled openvpn].each do |binary|
      if procs.include?(binary)
        signature_trusted = verify_process_signature(binary)
        break
      end
    end

    result = {
      active: vpn_active_confirmed,
      wireguard: vpn_active_confirmed && (procs.include?("wireguard") || procs.include?("wg-quick") || has_vpn_mtu || (ifconfig_out.include?("wg") && ifconfig_out.include?("POINTOPOINT"))),
      tailscale: vpn_active_confirmed && procs.include?("tailscaled"),
      zerotier: vpn_active_confirmed && procs.include?("zerotier-one"),
      openvpn: ifconfig_out.include?("tun") || procs.include?("openvpn"),
      proton: proton_detected,
      confidence: confidence_score,
      provider: vpn_provider,
      infrastructure: infra_type,
      signature_verified: signature_trusted,
      heuristics: { mtu_match: has_vpn_mtu, sockets_match: has_vpn_sockets, orphan_leak: orphan_tunnels_detected(procs) }
    }
    @vpn_state_cache = { ts: now, value: result }
    result
  end

  def vpn_confidence(vpn_active_confirmed, vpn_provider, infra_type, has_vpn_mtu, has_vpn_sockets, procs)
    score = 0
    score += 55 if vpn_active_confirmed
    score += 35 if vpn_provider != "Fournisseur Inconnu"
    case infra_type
    when :vpn then score += 20
    when :hosting then score += 5
    when :cloud then score += 2
    end
    score += 15 if has_vpn_mtu
    score += 15 if has_vpn_sockets
    score = 100 if vpn_active_confirmed && procs.include?("tailscaled")
    score = [score, 95].max if vpn_active_confirmed && procs.include?("zerotier-one")
    [[score, 0].max, 100].min
  end
end

def global_network_context
  StateManager.instance.memoized("global_net_ctx", 10) do
    ip = IPFetcher.instance.fetch
    ip = IPGuard.sanitize(ip)
    procs = ProcessSnapshot.instance.get  # ✅ Utilise ProcessSnapshot
    geo_info = ip ? StateManager.instance.memoized("geo_#{ip}", 300) { GeoLookup.instance.lookup(ip) } : GeoLookup.instance.local_geo_fallback
    vpn_st = VPNDetector.vpn_state(procs, geo_info)
    tor_active = TorDetector.active?(ip, procs)  # ✅ Utilise TorDetector
    apple_relay = apple_relay_ip?(ip, geo_info)  # ✅ Utilise apple_relay_ip?

    # Calcul du type de connexion
    connection_type = if vpn_st[:active]
                         "Tunnel VPN"
                       elsif vpn_st[:infrastructure] == :isp
                         "Ligne Directe (ISP)"
                       else
                         "Infrastructure Cloud / Hébergement"
                       end

    {
      ip: ip,
      geo: geo_info,
      vpn_state: vpn_st,
      dns: DNSAnalyzer.collect,
      perf: PerformanceMonitor.measure_network_perf,
      procs: procs,
      connection_type: connection_type,  # ✅ Ajout
      apple_relay: apple_relay,          # ✅ Ajout
      tor: tor_active                      # ✅ Ajout
    }
  end
end

# ==============================================================================
# MODULES MANQUANTS (À AJOUTER ICI)
# ==============================================================================

module TorDetector
  TOR_CACHE_FILE = File.join(DiskCache::CACHE_DIR, "tor_exit_nodes.json")
  $tor_state ||= { ts: Time.at(0), ips: Set.new }
  $cache_mutex ||= Mutex.new

  module_function

  def tor?(ip)
    return false unless IPGuard.sanitize(ip)
    StateManager.instance.memoized("tor_check_#{ip}", 1800) { tor_fetch_exit_nodes.include?(IPGuard.parse(ip).to_s) }
  end

  def tor_process?(procs = ProcessSnapshot.instance.get)
    procs.include?("tor") || procs.include?("obfs4proxy")
  rescue StandardError
    false
  end

  def tor_socks?
    StateManager.instance.memoized("tor_socks", 30) do
      begin
        socket = TCPSocket.new("127.0.0.1", 9050)
        socket.write("\x05\x01\x00")
        response = socket.readpartial(2)
        socket.close
        response == "\x05\x00"
      rescue StandardError
        false
      end
    end
  end

  def active?(ip, procs)
    tor?(ip) || tor_process?(procs) || tor_socks?
  end

  def tor_fetch_exit_nodes
    now = Time.now
    $cache_mutex.synchronize do
      return $tor_state[:ips] if (now - $tor_state[:ts]) < 14_400 && !$tor_state[:ips].empty?
    end

    begin
      if File.exist?(TOR_CACHE_FILE)
        cached = JSON.parse(File.read(TOR_CACHE_FILE)) rescue nil
        if cached.is_a?(Hash) && cached["ts"] && cached["ips"].is_a?(Array)
          if Time.now.to_i - cached["ts"].to_i < 14_400
            ips = Set.new(cached["ips"])
            $cache_mutex.synchronize { $tor_state = { ts: Time.now, ips: ips } }
            return ips
          end
        end
      end
    rescue StandardError
    end

    downloaded_ips = Set.new
    begin
      uri = URI("https://check.torproject.org/exit-addresses")
      body = Net::HTTP.start(uri.host, uri.port,
                            use_ssl: true,
                            verify_mode: OpenSSL::SSL::VERIFY_PEER,
                            open_timeout: 2.0,
                            read_timeout: 4.0) do |http|
        response = http.get(uri.request_uri)
        response.is_a?(Net::HTTPSuccess) ? response.body : nil
      end

      body.to_s.each_line do |line|
        next unless line.start_with?("ExitAddress")
        ip = line.split(" ", 2).last.to_s.strip
        downloaded_ips.add(ip) if IPGuard.valid_format?(ip)
      end
    rescue StandardError
    end

    if downloaded_ips.any?
      begin
        tmp_file = "#{TOR_CACHE_FILE}.tmp.#{$$}"
        File.write(tmp_file, JSON.generate({ ts: Time.now.to_i, ips: downloaded_ips.to_a }))
        File.chmod(0600, tmp_file)
        File.rename(tmp_file, TOR_CACHE_FILE)
      rescue StandardError
      end
      $cache_mutex.synchronize { $tor_state = { ts: Time.now, ips: downloaded_ips } }
      return downloaded_ips
    end

    $cache_mutex.synchronize { return $tor_state[:ips] unless $tor_state[:ips].empty? }
    Set.new
  end
end

def apple_relay_ip?(ip, geo_data = nil)
  return false unless IPGuard.sanitize(ip)
  geo_data ||= {}
  org = geo_data["org"].to_s.downcase
  asn = geo_data["asn"].to_s.upcase.gsub("AS", "")
  (AppConfig.instance.get(:apple_relay_asns) || []).include?(asn) ||
    org.include?("apple-relay") ||
    org.include?("icloud data protection")
end

# ==============================================================================
# MODULE PERFORMANCE
# ==============================================================================
module PerformanceMonitor
  PING_HOSTS = %w[1.1.1.1 8.8.8.8].freeze

  module_function

    def measure_network_perf
    LRUCachePro.instance.fetch("network_perf_live_metrics", ttl: 4) do
      latency_values = []

      threads = PING_HOSTS.map do |host|
        Thread.new do
          begin
            stdout, status = Open3.capture2("ping", "-c", "2", "-t", "1", host)
            if status.success?
              times = stdout.scan(/time=([0-9.]+)\s*ms/).flatten.map(&:to_f)
              times unless times.empty?
            end
          rescue
            nil
          end
        end
      end

      threads.each { |t| res = t.value; latency_values.concat(res) if res }

      if latency_values.empty?
        { latency: "--", jitter: "--" }
      else
        avg_latency = (latency_values.sum / latency_values.size.to_f).round(1)
        diffs = []
        latency_values.each_cons(2) { |a, b| diffs << (a - b).abs }
        avg_jitter = diffs.empty? ? (avg_latency * 0.05).round(1) : (diffs.sum / diffs.size.to_f).round(1)
        { latency: "#{avg_latency} ms", jitter: "#{avg_jitter} ms" }
      end
    end
  rescue StandardError
    { latency: "--", jitter: "--" }
  end
end



# ==============================================================================
# 13. ENGINE DE SORTIE & RENDER (XBAR) - FIX DÉFINITIF LATENCE / JITTER
# ==============================================================================
def render_xbar
  # Récupération du contexte global généré par le refactor
  ctx_global = global_network_context
  vpn_st     = ctx_global[:vpn_state]
  geo_data   = ctx_global[:geo]
  raw_dns    = ctx_global[:dns]

  vpn_active = vpn_st[:active]
  dns_split  = DNSAnalyzer.normalize(raw_dns, vpn_active)
  d_health   = DNSAnalyzer.health(dns_split[:public], dns_split[:vpn], vpn_active, geo_data)

  # Récupération résiliente et dynamique des vraies mesures de performance
  perf = nil
  if ctx_global.is_a?(Hash) && ctx_global[:perf]
    perf = ctx_global[:perf]
  elsif defined?(PerformanceMonitor) && PerformanceMonitor.respond_to?(:measure_network_perf)
    perf = PerformanceMonitor.measure_network_perf
  end
  
  # Structuration propre des fallbacks d'affichage (-- ms au lieu de 0 ms si KO/Indisponible)
  display_latency = (perf && perf[:latency]) ? perf[:latency].to_s : "-- ms"
  display_jitter  = (perf && perf[:jitter])  ? perf[:jitter].to_s  : "-- ms"

  # Configuration centralisée via AppConfig
  app_version   = AppConfig.instance.get(:app_version) || "v3.1.5"
  colors        = AppConfig.instance.get(:colors) || {}
  color_secure  = colors['secure'] || "#006400"
  color_warn    = colors['warn']   || "#FF9500"
  color_alert   = colors['alert']  || "#FF3B30"
  dns_providers = AppConfig.instance.get(:dns_providers) || {}

  # Gestion du Mode JSON
  if JSON_MODE
    puts JSON.generate({
      version: app_version,
      timestamp: Time.now.to_i,
      metrics: {
        ip: ctx_global[:ip],
        country: geo_data['country_code'],
        provider: vpn_st[:provider],
        score: vpn_st[:confidence],
        latency: perf ? (perf[:latency] || 0) : 0,
        jitter: perf ? (perf[:jitter] || 0) : 0
      }
    })
    exit 0
  end

  # Construction des variables d'affichage
  title_flag = flag(geo_data['country_code'])
  is_secure  = vpn_st[:confidence] >= 85 && !d_health[:leak]
  color      = is_secure ? color_secure : (vpn_st[:confidence] >= 55 ? color_warn : color_alert)

  title_main = vpn_active ? "🔐 #{title_flag}" : "🏠 #{title_flag}"
  
  # 1. Barre supérieure MacOS Xbar
  puts "#{title_main} | color=#{color} dropdown=true"
  puts "---"
  puts "VPN Checker #{app_version} | font=Menlo"
  puts "---"
  
  # 2. Section Identité Réseau & Géolocalisation
  puts "IP Publique: #{ctx_global[:ip] || 'Inconnue'}"
  puts "🌍 Pays: #{geo_data['country_code']} #{title_flag} #{is_secure ? '✅ [SÉCURISÉ]' : '⚠️ [NON SÉCURISÉ]'}"
  puts "Fournisseur: #{geo_data['org']} • Infrastructure: #{vpn_st[:infrastructure].to_s.upcase}"

  # Identification dynamique du Tunnel
  tunnels = {
    "WireGuard" => vpn_st[:wireguard],
    "OpenVPN"   => vpn_st[:openvpn],
    "Tailscale" => vpn_st[:tailscale],
    "ZeroTier"  => vpn_st[:zerotier]
  }
  tunnel_label = tunnels.find { |_, active| active }&.first || "Aucun"
  
  conn_type = ctx_global[:connection_type] || "standard"
  puts "Connexion: #{conn_type} • 🌐 Tunnel : #{tunnel_label}"
  puts "🏢 Hébergement : #{geo_data['org'].to_s.upcase}" if vpn_st[:infrastructure] == :hosting
  puts "---"
  
  # 3. Section Sécurité Réseau & Heuristiques
  puts "Sécurité Réseau:"
  vpn_status = vpn_active ? "Actif (Confiance: #{vpn_st[:confidence]}%)" : "Inactif"
  puts "• Score Global: #{vpn_st[:confidence]}%"
  puts "• Statut VPN: #{vpn_status}"
  puts "• Split Tunneling: #{NetworkAnalyzer.split_tunneling? ? '⚠️ Oui (Altéré)' : '🟢 Non (Global)'}"
  puts "• Proxy Direct: #{ProxyDetector.instance.detected? ? '⚠️ Actif' : '🟢 Aucun'}"
  puts "• Fournisseur VPN détecté: #{vpn_st[:provider]}" if vpn_active

  # Statut du Kill Switch basé sur les tunnels orphelins
  ks_broken = vpn_st[:heuristics][:orphan_leak]
  puts ks_broken ? "🚨 Kill Switch FAIL" : "• Kill Switch: ✓ Actif"

  dns_enc_label = DNSAnalyzer.detect_encryption_type(dns_split, DNSAnalyzer.doh_detect)
  puts "• Fuite DNS (Leak): #{d_health[:leak] ? '⚠️ Oui' : '🟢 Non'} • Fuite DNS IPv6: #{d_health[:ipv6_leak] ? '🚨 Détectée' : '🟢 Aucune'}"
  puts "• DNS Chiffré: #{dns_enc_label.include?('Non chiffré') ? '❌ Non' : '🟢 Oui'} • 🛡️ DNS Isolation : #{d_health[:isolation] ? 'safe' : 'unsafe'}"
  
  apple_relay = ctx_global[:apple_relay] ? "Actif" : "Inactif"
  puts "• Apple Private Relay: #{apple_relay}"

  # Consistance DNS
  consistency = DNSAnalyzer.consistency(vpn_active, dns_split[:local], dns_split[:vpn], dns_split[:public])
  consistency_map = {
    "🟢 Cohérent (Réseau Standard)" => "🟢 Cohérent",
    "🔐 Sécurisé (Tunnel DNS Exclusif)" => "🟢 Sécurisé",
    "🟡 Mixte (Tunnel + Résolveurs Publics)" => "🟡 Mixte",
    "⚠️ Danger (Fuite DNS probable)" => "🚨 Danger"
  }
  puts "🔄 Consistance : #{consistency_map[consistency] || consistency}"
  
  tor_status = ctx_global[:tor] ? "🟡 Actif" : "🟢 Inactif"
  puts "🧅 Tor Network : #{tor_status}"
  puts "---"
  
  # 4. Section Serveurs DNS
  puts "DNS Servers Detected :"
  all_dns = raw_dns || []
  if all_dns.empty?
    puts "-- Aucun serveur détecté (Système par défaut)"
  else
    grouped = Hash.new { |h, k| h[k] = [] }
    all_dns.uniq.each do |ip|
      label = if dns_providers.key?(ip)
                dns_providers[ip]
              elsif IPGuard.private_ip?(ip) || IPGuard.localhost?(ip)
                vpn_active ? "🔐 VPN Private DNS" : "🏠 DNS Local / Routeur"
              else
                "🌐 DNS Public Alternatif"
              end
      grouped[label] << ip
    end
    grouped.each { |label, ips| puts "-- #{label} (#{ips.uniq.join(', ')})" }
  end
  puts "---"
  
  # 5. Section Métriques de Performance (Résolue, Dynamique avec Fallback propre)
  puts "Performances réseau:"
  puts "• Latence standard: #{display_latency} • Jitter: #{display_jitter}"
  puts "---"
  
  # 6. Empreinte Unique du Diagnostic
  fp = Digest::SHA256.hexdigest("#{ctx_global[:ip]}_#{geo_data['asn']}")[0..11]
  puts "Empreinte Réseau (Fingerprint): #{fp} | color=#888888"
end

render_xbar
