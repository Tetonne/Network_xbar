#!/usr/bin/env ruby
# frozen_string_literal: true
# script optimisé pour macOS xbar.app (Ruby 2.6+)
# script pour macOS (Catalina... Sequoia) avec ruby 2.6 dans l'application xbar.app
# debug : cd ~/Library/Application\ Support/xbar/plugins/
# debug : ruby VPN-flag294.txt --debug
# debug : ruby -cw VPN-flag294.txt
# rm -rf "$(ruby -e "require 'tmpdir'; print File.join(Dir.tmpdir, 'xbar_vpn_check2')")"
# script optimisé pour macOS xbar.app (Ruby 2.6+)


require 'digest'
require 'ipaddr'
require 'json'
require 'set'
require 'socket'
require 'net/http'
require 'uri'
require 'resolv'
require 'fileutils'
require 'timeout'
require 'tmpdir'
require 'openssl'
require 'open3'
require 'thread'
require 'monitor'

$runtime_ctx ||= {}
$runtime_ctx[:using_public_ip] = false
$runtime_ctx[:fallback_used] = false
$tor_state ||= { ts: Time.at(0), ips: Set.new }
$cache_mutex ||= Monitor.new

THREAD_TIMEOUT = 1.2
DEBUG_ERRORS = true

def log_error(e, context = "")
  warn "[ERROR] #{context}: #{e.class} - #{e.message}" if DEBUG_ERRORS
end

$metrics = Hash.new { |h,k| h[k] = [] }

def track(metric, value)
  $metrics[metric] << value
end

def cache_stats
  $CACHE.stats
end

# ==============================================================================
# 0. Langues
# ==============================================================================

I18N = {
  fr: {
    vpn_checker: "VPN Checker",
    public_ip: "IP Publique",
    country: "Pays",
    provider: "Fournisseur",
    infrastructure: "Infrastructure",
    connection: "Connexion",
    active: "Actif",
    inactive: "Inactif",
    suspected: "Suspecté",
    tunnels_none: "Aucun",
    hosting: "Hébergement",
    security_score: "Score Sécurité",
    privacy_score: "Score Confidentialité",
    vpn_tunnel: "Tunnel VPN",
    direct_isp: "Ligne Directe (ISP)",
    cloud_hosting: "Infrastructure Cloud / Hébergement",
    unknown_infra: "Infrastructure Inconnue"
  },

  en: {
    vpn_checker: "VPN Checker",
    public_ip: "Public IP",
    country: "Country",
    provider: "Provider",
    infrastructure: "Infrastructure",
    connection: "Connection",
    active: "Active",
    inactive: "Inactive",
    suspected: "Suspected",
    tunnels_none: "None",
    hosting: "Hosting",
    security_score: "Security Score",
    privacy_score: "Privacy Score",
    vpn_tunnel: "VPN Tunnel",
    direct_isp: "Direct ISP Connection",
    cloud_hosting: "Cloud / Hosting Infrastructure",
    unknown_infra: "Unknown Infrastructure"
  }
}.freeze

LANGUAGE =
  ((`defaults read -g AppleLanguages 2>/dev/null` =~ /en/) ? :en : :fr)

def t(key)
  I18N.dig(LANGUAGE, key) ||
    I18N.dig(:fr, key) ||
    key.to_s
end

# ==============================================================================
# 1. CONFIGURATION & GLOBALES
# ==============================================================================
APP_VERSION = "v3.0.1".freeze

ALLOWED_COUNTRIES = %w[NL CH PL RO US].freeze
DENY_COUNTRIES    = %w[FR].freeze
PING_HOSTS        = %w[1.1.1.1 8.8.8.8].freeze

TRUSTED_DNS       = %w[
  1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 127.0.0.1
  2606:4700:4700::1111 2606:4700:4700::1001 2001:4860:4860::8888 2001:4860:4860::8844
  2620:fe::fe 2620:fe::9 ::1
].freeze

VPN_PROVIDERS_ASN = %w[proton mullvad nordvpn surfshark expressvpn ivpn cyberghost].freeze

VPN_PROVIDER_KEYWORDS = {
  "proton"          => "ProtonVPN",
  "mullvad"         => "Mullvad",
  "nordvpn"         => "NordVPN",
  "surfshark"       => "Surfshark",
  "expressvpn"      => "ExpressVPN",
  "ivpn"            => "IVPN",
  "cyberghost"      => "CyberGhost",
  "pia"             => "Private Internet Access",
  "m247"            => "M247",
  "datacamp"        => "DataCamp",
  "leaseweb"        => "Leaseweb",
  "digitalocean"    => "DigitalOcean",
  "ovh"             => "OVH",
  "choopa"          => "Choopa",
  "vultr"           => "Vultr",
  "airvpn"          => "AirVPN",
  "perfect_privacy" => "Perfect Privacy",
  "windscribe"      => "Windscribe",
  "hide_me"         => "Hide.me",
  "purevpn"         => "PureVPN",
  "fastvpn"         => "Namecheap FastVPN",
  "mojie"           => "Mojie VPN",
  "mozilla"         => "Mozilla VPN",
  "hetzner"         => "Hetzner"
}.freeze

KNOWN_PROTON_ASN = %w[212238 51852].freeze
KNOWN_VPN_ASN    = %w[212238 51852].freeze

NORMALIZED_UNKNOWN = %w[?? LO N/A NULL UNKNOWN --].freeze

HOSTING_PATTERNS = [
  /m247/,
  /leaseweb/,
  /contabo/,
  /digitalocean/,
  /vultr/,
  /ovh/,
  /hetzner/,
  /worldstream/,
  /scaleway/,
  /choopa/
].freeze

DNS_PROVIDERS = {
  "1.1.1.1"         => "☁️ Cloudflare", 
  "1.0.0.1"         => "☁️ Cloudflare",
  "8.8.8.8"         => "🟦 Google",     
  "8.8.4.4"         => "🟦 Google",
  "9.9.9.9"         => "🌐 Quad9",      
  "149.112.112.112" => "🌐 Quad9",
  "127.0.0.1"       => "🔐 DNSCrypt"
}.freeze

# Couleurs d'interface (Utilisées par xbar / SwiftBar)
COLOR_SECURE = "#006400".freeze
COLOR_WARN   = "#FF9500".freeze
COLOR_ALERT  = "#FF3B30".freeze

# Arguments d'exécution
DEBUG     = ARGV.include?("--debug")
JSON_MODE = ARGV.include?("--json")

# Méthode utilitaire de journalisation
def debug(msg)
  warn "[DEBUG] #{msg}" if DEBUG
end

# ==============================================================================
# 2. COUCHE RÉSILIENCE & CACHE
# ==============================================================================
require 'timeout'
require 'fileutils'
require 'ipaddr'
require 'json'
require 'tmpdir'

module Resilient
  module_function

  def with_timeout(seconds = 4)
    Timeout.timeout(seconds, StandardError) do
      yield
    end
  rescue Timeout::Error
    debug("Timeout déclenché (#{seconds}s)")
    nil
  rescue StandardError => e
    warn "[DEBUG] Critique execution error: #{e.class} - #{e.message}" if defined?(DEBUG) && DEBUG
    nil
  end
end

def memoized(key, ttl = 30)
  stack = (Thread.current[:memo_stack] ||= [])

  return yield if stack.include?(key)

  # Protection récursion + réentrance
  stack << key

  begin
    # Assure la liaison avec DiskCache si $CACHE n'est pas instancié
    cache_engine =
  defined?($DISK_CACHE) ?
  $DISK_CACHE :
  DiskCache
    cache_engine.fetch(key, ttl: ttl) do
      yield
    end
  ensure
    # Safe remove (évite rindex nil edge case)
    idx = stack.rindex(key)
    stack.delete_at(idx) if idx
  end
end


module IPGuard
  module_function

  MULTICAST_V4 = IPAddr.new('224.0.0.0/4').freeze

  def parse(ip)
    return nil if ip.nil?

    str = ip.to_s.split('%').first.strip
    IPAddr.new(str)
  rescue IPAddr::InvalidAddressError
    nil
  end

  def localhost?(ip)
    addr = parse(ip)
    !!addr&.loopback?
  end

  def private_ip?(ip)
    addr = parse(ip)
    !!addr&.private?
  end

  def ipv4_multicast?(addr)
    addr.ipv4? && MULTICAST_V4.include?(addr)
  end

  def blocked?(addr)
    addr.loopback? ||
      addr.link_local? ||
      ipv4_multicast?(addr)
  end

  def sanitize(ip)
    addr = parse(ip)
    return nil unless addr
    return nil if blocked?(addr)

    addr.to_s
  end

  def valid_format?(ip)
    !parse(ip).nil?
  end
end


module DiskCache
  CACHE_DIR = File.join(Dir.tmpdir, "xbar_vpn_check2")

  class << self
    def setup
      FileUtils.mkdir_p(CACHE_DIR)
    rescue StandardError => e
      debug("Cache dir error: #{e}")
    end

    def safe_json_parse(str)
      JSON.parse(str)
    rescue JSON::ParserError, TypeError
      nil
    end

    def safe_key(key)
      key.to_s.gsub(/[^a-zA-Z0-9_\-]/, '_')[0, 200]
    end

    def cache_path(key)
      File.join(CACHE_DIR, "#{safe_key(key)}.cache")
    end

    def fetch(key, ttl:)
      setup

      cache_file = cache_path(key)
      # CORRECTION: Utilisation du temps UNIX Epoch réel car le cache est persistant sur disque
      now = Time.now.to_i

      begin
        File.open(cache_file, "r") do |f|
          f.flock(File::LOCK_SH)

          data = safe_json_parse(f.read)
          next unless data.is_a?(Hash)

          ts = data["timestamp"].to_i rescue 0
          payload = data["payload"]

          if ts > 0 && (now - ts) < ttl
            return payload
          end
        end
      rescue Errno::ENOENT
        # Fichier absent, traitement normal (cache miss)
      rescue StandardError => e
        debug("Cache read error #{key}: #{e}")
      end

      value = yield

      tmp = "#{cache_file}.tmp.#{Process.pid}.#{Thread.current.object_id}"

      begin
        File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, 0o644) do |f|
          f.flock(File::LOCK_EX)

          f.write(JSON.generate(
            "timestamp" => now,
            "payload" => value
          ))

          f.flush
          f.fsync
        end

        File.rename(tmp, cache_file)
      rescue StandardError => e
        debug("Cache write error #{key}: #{e}")
        File.unlink(tmp) if File.exist?(tmp)
      end

      value
    end
  end
end

# Initialisation de la globale pour assurer la compatibilité avec la méthode memoized
$DISK_CACHE = DiskCache

# ==============================================================================
# class LRUCache
# ==============================================================================

class LRUCachePro
  Entry = Struct.new(:value, :ts, :loading)

  def initialize(max_size: 300, ttl_default: 30, cleanup_interval: 15)
    @max_size = max_size
    @ttl_default = ttl_default
    @cleanup_interval = cleanup_interval

    @data = {}          # key => Entry
    @lru = {}           # key => true (ordre d'insertion)
    @loading_cv = {}    # key => ConditionVariable

    @mutex = Mutex.new

    @stats = {
      hit: 0,
      miss: 0,
      expired: 0,
      stampede_wait: 0
    }

    @stop = false
    @cleanup_thread = start_cleanup_thread
  end

  def fetch(key, ttl: nil)
    ttl ||= @ttl_default
    now = Time.now.to_i

    cv = nil
    value = nil

    @mutex.synchronize do
      entry = @data[key]

      # HIT
      if entry && !expired?(entry, now, ttl)
        @stats[:hit] += 1
        touch(key)
        return entry.value
      end

      # MISS but already loading => wait
      if entry&.loading
        @stats[:stampede_wait] += 1
        cv = (@loading_cv[key] ||= ConditionVariable.new)
        cv.wait(@mutex)
        entry = @data[key]
        return entry&.value
      end

      # MISS => mark loading
      @stats[:miss] += 1
      @data[key] = Entry.new(nil, now, true)
      touch(key)
      cv = (@loading_cv[key] ||= ConditionVariable.new)
    end

    begin
      value = yield
    rescue => e
      @mutex.synchronize do
        @data.delete(key)
        @lru.delete(key)
        @loading_cv.delete(key)
        cv.broadcast if cv
      end
      raise e
    end

    @mutex.synchronize do
      evict_if_needed
      @data[key] = Entry.new(value, now, false)
      touch(key)

      cv = @loading_cv.delete(key)
      cv.broadcast if cv
    end

    value
  end

  def stats
    @mutex.synchronize { @stats.dup }
  end

  def stop
    @stop = true
    @cleanup_thread&.join
  end

  private

  def expired?(entry, now, ttl)
    (now - entry.ts) >= ttl
  end

  def touch(key)
    @lru.delete(key)
    @lru[key] = true
  end

  def evict_if_needed
    while @lru.size > @max_size
      old_key = @lru.shift&.first
      next unless old_key
      @data.delete(old_key)
      @loading_cv.delete(old_key)
    end
  end

  def start_cleanup_thread
    Thread.new do
      Thread.current.abort_on_exception = true

      until @stop
        sleep @cleanup_interval
        cleanup_expired
      end
    end
  end

  def cleanup_expired
    now = Time.now.to_i

    @mutex.synchronize do
      @data.each do |k, v|
        next unless v
        if !v.loading && (now - v.ts > @ttl_default * 2)
          @data.delete(k)
          @lru.delete(k)
          @loading_cv.delete(k)
          @stats[:expired] += 1
        end
      end
    end
  end
end

$MEM_CACHE  = LRUCachePro.new

# ==============================================================================
# 3. UTILS SYSTÈME MAC & RÉSEAU DE BASE
# ==============================================================================

def global_network_context
  memoized("global_net_ctx", 10) do
    ip_raw = fetch_ip
    ip = IPGuard.sanitize(ip_raw)

    {
      bandwidth: bandwidth_stats,
      ip: ip,
      geo: safe_geo(ip),
      vpn_state: safe_vpn_state,
      dns: safe_dns,
      perf: safe_network_perf
    }
  end
end

def safe_geo(ip)
  return local_geo_fallback(nil) unless ip
  geo(ip)
rescue StandardError
  local_geo_fallback(nil)
end

def safe_vpn_state
  vpn_state
rescue StandardError
  :unknown
end

def safe_dns
  system_dns
rescue StandardError
  []
end

def safe_network_perf
  measure_network_perf
rescue StandardError
  {}
end

def bandwidth_stats

  out, = Open3.capture2(
    "netstat",
    "-ib"
  )
  rx = 0
  tx = 0
  out.each_line do |line|
    cols = line.split
    next unless cols.size > 9
    rx += cols[6].to_i
    tx += cols[9].to_i
  end
  {
    rx_mb: (rx / 1024.0 / 1024).round(1),
    tx_mb: (tx / 1024.0 / 1024).round(1)
  }
rescue
  {
    rx_mb: 0,
    tx_mb: 0
  }
end


def process_snapshot
  @process_snapshot ||= { ts: 0, value: Set.new }
  now = Process.clock_gettime(Process::CLOCK_MONOTONIC).to_i

  if (now - @process_snapshot[:ts]) < 5
    return @process_snapshot[:value]
  end

  stdout, = Open3.capture2("ps", "-A", "-o", "comm=")

  value = stdout.each_line.map do |l|
    File.basename(l.strip).downcase
  end.to_set

  @process_snapshot = {
    ts: now,
    value: value.freeze
  }

  value
rescue StandardError
  @process_snapshot[:value]
end

def process_snapshot_global
  @proc_cache ||= { ts: 0, value: Set.new }
  now = Time.now.to_i

  return @proc_cache[:value] if now - @proc_cache[:ts] < 5

  stdout, = Open3.capture2("ps", "-A", "-o", "comm=")

  value = stdout.lines.map { |l| File.basename(l.strip).downcase }.to_set

  @proc_cache = { ts: now, value: value }
  value
end

def macos_process_active?(name)
  return false unless name

  process_snapshot.include?(name.to_s.downcase)
end


def brew_binary_path(binary)
  return nil unless binary.is_a?(String)

  @binary_paths ||= {}

  @binary_paths[binary] ||= begin
    safe = binary.gsub(/[^a-zA-Z0-9_\-]/, '')
    return safe if safe.empty?

    paths = [
      "/opt/homebrew/bin/#{safe}",
      "/usr/local/bin/#{safe}",
      "/usr/bin/#{safe}"
    ]

    paths.find { |path| File.exist?(path) } || safe
  end
end

module NetTools
  TEST_HOSTS = [["1.1.1.1", 53], ["8.8.8.8", 53]].freeze
  module_function

  def internet?
    TEST_HOSTS.any? do |host, port|
      begin
        Timeout.timeout(1) do
          Socket.tcp(host, port, connect_timeout: 1) { true }
        end
      rescue StandardError
        false
      end
    end
  end
end

unless NetTools.internet?
  warn "⚠️ Hors ligne | dropdown=false"
  exit!(0)
end

# ==============================================================================
# 4. MOTEUR DE PROTOCOLE IP & VALIDATIONS / CIRCUIT BREAKER
# ==============================================================================
def valid_ip?(ip)
  !IPGuard.sanitize(ip).nil?
end

def flag(country)
  return "🏳️" unless country.is_a?(String)

  code = country.strip.upcase
  return "🏳️" unless code.match?(/\A[A-Z]{2}\z/)

  memoized("flag_#{code}", 86_400) do
    code.each_char.map do |c|
      (0x1F1E6 + c.ord - 65).chr(Encoding::UTF_8)
    end.join
  end
rescue StandardError
  "🏳️"
end

def register_failure(host)
  data = load_circuit_breaker

  host_data =
    data[host] ||= {
      "count" => 0,
      "ts" => Time.now.to_i
    }

  host_data["count"] += 1
  host_data["ts"] = Time.now.to_i

  save_circuit_breaker(data)
end

def register_success(host)
  data = load_circuit_breaker

  data.delete(host)

  save_circuit_breaker(data)
end


def load_circuit_breaker
  @circuit_cache ||= begin
    path = File.join(DiskCache::CACHE_DIR, "circuit_breaker.json")

    if File.exist?(path)
      data = JSON.parse(File.read(path))
      data.is_a?(Hash) ? data : {}
    else
      {}
    end
  rescue JSON::ParserError, TypeError
    {}
  end
end

def save_circuit_breaker(data)
  return unless data.is_a?(Hash)

  @circuit_cache = data

  DiskCache.setup

  path = File.join(DiskCache::CACHE_DIR, "circuit_breaker.json")
  tmp  = "#{path}.tmp.#{Process.pid}.#{Thread.current.object_id}"

  File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, 0o644) do |f|
    f.write(JSON.generate(data))
    f.flush
    f.fsync
  end

  File.rename(tmp, path)
rescue StandardError
  File.unlink(tmp) if File.exist?(tmp)
  nil
end

def circuit_open?(host)
  return false unless host.is_a?(String)

  data = load_circuit_breaker
  host_data = data[host] ||= { "count" => 0, "ts" => 0 }

  now = Time.now.to_i

  # reset window
  if now - host_data["ts"].to_i > 300
    host_data["count"] = 0
    host_data["ts"] = now
    save_circuit_breaker(data)
    return false
  end

  host_data["count"].to_i >= 3
end

# ==============================================================================
# 5. DÉTECTEURS RÉSEAU (IP, Geo, ASN, Apple Relay, Tor)
# ==============================================================================

def last_known_good_ip
  path = File.join(DiskCache::CACHE_DIR, "last_good_ip.json")
  return nil unless File.exist?(path)

  data = JSON.parse(File.read(path))
  return nil unless data.is_a?(Hash)

  ip = data["ip"]
  ip = ip.to_s.strip

  return ip if IPGuard.sanitize(ip)
  nil
rescue JSON::ParserError, TypeError
  nil
end

def store_last_known_good_ip(ip)
  return unless ip.is_a?(String) && IPGuard.sanitize(ip)

  DiskCache.setup

  path = File.join(DiskCache::CACHE_DIR, "last_good_ip.json")
  tmp  = "#{path}.tmp.#{Process.pid}.#{Thread.current.object_id}"

  File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, 0o644) do |f|
    f.write(JSON.generate({ ip: ip, ts: Time.now.to_i }))
    f.flush
    f.fsync
  end

  File.rename(tmp, path)
rescue StandardError
  File.unlink(tmp) if File.exist?(tmp)
end

def fetch_ip
  memoized("public_ip", 120) do
    DiskCache.fetch("ip_primary_v4", ttl: 120) do

      providers = [
        "https://api64.ipify.org?format=text",
        "https://checkip.amazonaws.com"
      ]

      ip = nil

      providers.each do |url|
        begin
          uri = URI(url)

          if circuit_open?(uri.host)
            debug("Circuit ouvert #{uri.host}")
            next
          end

          res = Net::HTTP.start(
            uri.host,
            uri.port,
            use_ssl: true,
            open_timeout: 1.2,
            read_timeout: 1.2
          ) do |http|
            http.get(uri.request_uri)
          end

          if res.is_a?(Net::HTTPSuccess)

            register_success(uri.host)

            candidate =
              IPGuard.sanitize(
                res.body.to_s.strip
              )

            if candidate
              ip = candidate
              break
            end
          else
            register_failure(uri.host)
          end

        rescue StandardError

          register_failure(uri.host)

          next
        end
      end

      if ip
        store_last_known_good_ip(ip)
        ip
      else
        last_known_good_ip
      end
    end
  end
end

def refresh_last_known_good_ip
  ip = fetch_ip
  return unless ip && IPGuard.sanitize(ip)

  store_last_known_good_ip(ip)
rescue StandardError
  nil
end

def fetch_ipv6
  memoized("public_ipv6", 300) do
    uri = URI("https://api64.ipify.org?format=text")

    res = Net::HTTP.start(
      uri.host,
      uri.port,
      use_ssl: true,
      open_timeout: 1.5,
      read_timeout: 1.5
    ) { |http| http.get(uri.request_uri) }

    return nil unless res.is_a?(Net::HTTPSuccess)

    ip = res.body.to_s.strip
    parsed = IPAddr.new(ip)

    return nil unless parsed.ipv6?
    return nil if parsed.loopback? || parsed.link_local?

    ip
  rescue IPAddr::InvalidAddressError, StandardError
    nil
  end
end

def fetch_geo_provider(url)
  uri = URI(url)

  return nil if circuit_open?(uri.host)

  begin
    res = Timeout.timeout(3) do
      Net::HTTP.start(
        uri.host,
        uri.port,
        use_ssl: true,
        open_timeout: 1.5,
        read_timeout: 2.0
      ) do |http|
        http.get(uri.request_uri)
      end
    end

    if res.is_a?(Net::HTTPSuccess)
      register_success(uri.host)
      JSON.parse(res.body.to_s)
    else
      register_failure(uri.host)
      nil
    end

  rescue
    register_failure(uri.host)
    nil
  end
end

def fallback_local_ip
  Socket.ip_address_list
        .select(&:ipv4?)
        .map(&:ip_address)
        .find do |ip|
          IPGuard.valid_format?(ip) &&
            !IPGuard.localhost?(ip) &&
            IPGuard.private_ip?(ip)
        end
rescue StandardError
  nil
end

def local_geo_fallback(_ip)
  {
    "country_code" => "??",
    "org" => "Réseau Local",
    "isp" => "Fallback",
    "asn" => "AS0000",
    "asn_org" => "Local / Non routé"
  }
end

def geo(ip)
  cleaned_ip = ip.to_s.strip

  return local_geo_fallback(cleaned_ip) unless IPGuard.sanitize(cleaned_ip)

  DiskCache.fetch("geo_v8_#{cleaned_ip}", ttl: 86_400) do

    providers = [
      [
        "ipwho",
        "https://ipwho.is/#{cleaned_ip}"
      ],
      [
        "ipapi",
        "https://ipapi.co/#{cleaned_ip}/json/"
      ]
    ]

    providers.each do |provider, url|

      begin
        raw = fetch_geo_provider(url)

        normalized =
          normalize_geo(raw, provider)

        return normalized if normalized
      rescue
      end
    end

    local_geo_fallback(cleaned_ip)
  end
end

def geo_with_ip_cache(ip)
  return local_geo_fallback(nil) unless ip

  memoized("geo_for_#{ip}", 86_400) do
    geo(ip)
  end
end

def geo_ipv6
  ipv6 = fetch_ipv6
  return nil unless ipv6

  geo(ipv6)
rescue StandardError
  nil
end


def normalize_geo(data, provider)
  return nil unless data.is_a?(Hash)

  case provider
  when "ipwho"
    return nil if data["success"] == false

    conn = data["connection"] || {}

    {
      "country_code" => data["country_code"] || data["country"],
      "org" => conn["org"],
      "isp" => conn["isp"],
      "asn" => conn["asn"],
      "asn_org" => conn["org"]
    }

  when "ipapi"
    return nil if data["error"]

    {
      "country_code" => data["country_code"] || data["country"],
      "org" => data["org"],
      "isp" => data["org"],
      "asn" => data["asn"],
      "asn_org" => data["org"]
    }
  end
end

def apple_relay_ip?(ip, geo_info = nil)
  return false unless IPGuard.sanitize(ip)

  geo_info = geo_info.is_a?(Hash) ? geo_info : {}

  org = geo_info["org"].to_s.downcase
  asn = normalize_asn(geo_info["asn"])

  return true if direct_apple_match?(org, asn)
  return true if apple_asn_match?(asn)

  false
end

def normalize_asn(asn)
  return nil unless asn

  asn.to_s
     .upcase
     .sub(/^AS/, "")
     .gsub(/[^\d]/, "")
end

def direct_apple_match?(org, asn)
  return false unless org

  org.include?("apple") ||
    org.include?("icloud") ||
    asn == "714"
end

def apple_asn_match?(asn)
  return false unless asn

  # ASN Apple officiel
  asn == "714"
end


def ipv6_leak?(ipv4_geo, ipv6_geo, vpn_active)

  return false unless vpn_active
  return false unless ipv6_geo

  ipv4_asn = normalize_asn(ipv4_geo["asn"])
  ipv6_asn = normalize_asn(ipv6_geo["asn"])

  ipv4_country = ipv4_geo["country_code"]
  ipv6_country = ipv6_geo["country_code"]

  return true if ipv4_country != ipv6_country
  return true if ipv4_asn != ipv6_asn

  false
end

def download_apple_relay_csv_raw
  DiskCache.fetch("apple_relay_ranges_int_v4", ttl: 86_400) do

    uri = URI(
      "https://mask-api.icloud.com/egress-ip-ranges.csv"
    )

    return [] if circuit_open?(uri.host)

    begin
      response = Timeout.timeout(3.0) do
        Net::HTTP.start(
          uri.host,
          uri.port,
          use_ssl: true,
          open_timeout: 1.5,
          read_timeout: 2.0
        ) do |http|
          http.get(uri.request_uri)
        end
      end

      unless response.is_a?(Net::HTTPSuccess)
        register_failure(uri.host)
        return []
      end

      register_success(uri.host)

      response.body.to_s.each_line.filter_map do |line|

        cidr = line.split(",").first&.strip

        next unless cidr&.include?("/")

        begin
          net = IPAddr.new(cidr)

          {
            start: net.to_i,
            stop: net.to_i + net.num_addresses - 1
          }

        rescue IPAddr::InvalidAddressError
          nil
        end
      end

    rescue StandardError

      register_failure(uri.host)

      []
    end
  end
end

def private_relay?(public_ip, precompiled_ranges)
  return false unless public_ip.is_a?(String)
  return false if IPGuard.private_ip?(public_ip) || IPGuard.localhost?(public_ip)

  ranges = precompiled_ranges.is_a?(Array) ? precompiled_ranges : []
  return false if ranges.empty?

  ip = begin
  IPAddr.new(public_ip)
rescue IPAddr::InvalidAddressError
  nil
end

return false unless ip
ip_int = ip.to_i

  ranges.any? do |range|
    start_val = range["start"] || range[:start]
    stop_val  = range["stop"]  || range[:stop]

    next false unless start_val && stop_val

    ip_int >= start_val && ip_int <= stop_val
  end
end

def tor_fetch_exit_nodes
  $cache_mutex.synchronize do
    return $tor_state[:ips] if Time.now - $tor_state[:ts] < 14_400
  end

  uri = URI(
    "https://check.torproject.org/exit-addresses"
  )

  return Set.new if circuit_open?(uri.host)

  raw = Resilient.with_timeout(3) do
    begin
      Net::HTTP.start(
        uri.host,
        uri.port,
        use_ssl: true,
        open_timeout: 1.5,
        read_timeout: 2.0
      ) do |http|
        res = http.get(uri.request_uri)

        if res.is_a?(Net::HTTPSuccess)
          register_success(uri.host)
          res.body
        else
          register_failure(uri.host)
          nil
        end
      end

    rescue StandardError

      register_failure(uri.host)

      nil
    end
  end

  ips = Set.new

  raw.to_s.each_line do |line|

    next unless line.start_with?("ExitAddress")

    ip = line.split.last

    begin
      ips << IPAddr.new(ip).to_s
    rescue
    end
  end

  $cache_mutex.synchronize do
    $tor_state = {
      ts: Time.now,
      ips: ips.freeze
    }
  end

  ips
end

def tor?(ip)
  return false unless IPGuard.sanitize(ip)

  memoized("tor_check_#{ip}", 1800) do
    tor_fetch_exit_nodes.include?(
      IPGuard.parse(ip).to_s
    )
  end
end

def tor_process?
  stdout, = Open3.capture2("pgrep", "-x", "tor")
  !stdout.strip.empty?
rescue
  false
end

def tor_socks?
  memoized("tor_socks", 30) do
    begin
      socket = TCPSocket.new("127.0.0.1", 9050)

      socket.write("\x05\x01\x00")

      response = socket.readpartial(2)

      socket.close

      response == "\x05\x00"
    rescue
      false
    end
  end
end

# ==============================================================================
# 6. INFRASTRUCTURE & ANALYSE DE SÉCURITÉ RÉSEAU
# ==============================================================================
def active_utun_interfaces
  stdout, = Open3.capture2("ifconfig")

  stdout.scan(/^utun\d+:/)
        .map { |x| x.delete(":") }
        .uniq
rescue StandardError
  []
end

def vpn_state 
  @vpn_state_cache ||= {
    ts: 0,
    value: nil
  }

  now = Time.now.to_i

  if @vpn_state_cache[:value] &&
     (now - @vpn_state_cache[:ts] < 10)
    return @vpn_state_cache[:value]
  end

  procs = process_snapshot_global.to_a.map(&:downcase)

  vpn_processes = %w[
    wireguard
    wg
    tailscaled
    zerotier-one
    openvpn
    protonvpn
    proton
    mullvad
    ivpn
    nordvpn
    surfshark
    tunnelblick
    viscosity
  ]

  vpn_process_detected =
    vpn_processes.any? do |p|
      procs.any? { |x| x.include?(p) }
    end

  utuns = active_utun_interfaces

  vpn_score = 0

  vpn_score += 70 if vpn_process_detected
  vpn_score += 10 if utuns.size >= 3

  active = vpn_score >= 60

  result = {
    active: active,

    wireguard: procs.any? { |x| x.include?("wireguard") || x == "wg" },

    tailscale: procs.any? { |x| x.include?("tailscaled") },

    zerotier: procs.any? { |x| x.include?("zerotier-one") },

    proton: procs.any? { |x| x.include?("proton") },

    utun_count: utuns.size,

    vpn_score: vpn_score
  }

  @vpn_state_cache = {
    ts: now,
    value: result
  }

  result
end

def vpn_by_asn?(geo_data)
  return false unless geo_data.is_a?(Hash)

  org = geo_data["org"].to_s.downcase
  asn = normalize_asn(geo_data["asn"])

  return true if KNOWN_VPN_ASN.include?(asn)

  VPN_PROVIDER_KEYWORDS.keys.any? do |keyword|
    org.include?(keyword)
  end
end

def classify_infra(asn, org)
  text = "#{asn} #{org}".to_s.downcase

  return :unknown if text.empty?

  vpn_patterns = %w[
    proton mullvad nordvpn surfshark
    expressvpn ivpn cyberghost pia
  ]

  hosting_patterns = %w[
    ovh leaseweb m247 contabo
    digitalocean vultr hetzner
    worldstream scaleway choopa
  ]

  cloud_patterns = [
    "amazon",
    "aws",
    "google cloud",
    "gcp",
    "azure",
    "oracle cloud"
  ]

  isp_patterns = [
    "orange",
    "kpn",
    "ziggo",
    "xs4all",
    "freedom internet",
    "vodafone",
    "proximus",
    "bouygues",
    "telecom"
  ]

  return :vpn if vpn_patterns.any? { |x| text.include?(x) }
  return :hosting if hosting_patterns.any? { |x| text.include?(x) }
  return :cloud if cloud_patterns.any? { |x| text.include?(x) }
  return :isp if isp_patterns.any? { |x| text.include?(x) }

  :unknown
end

#--------------------
def vpn_provider_name(org)
  return nil unless org.is_a?(String)

  org_down = org.downcase.strip
  return nil if org_down.empty?

  VPN_PROVIDER_KEYWORDS.each do |keyword, name|
    next unless keyword && name
    return name if org_down.include?(keyword)
  end

  nil
end


def resolve_vpn_provider(org, asn, _isp = nil, vpn_ctx = nil)

  org_s = org.to_s.downcase
  asn_s = normalize_asn(asn)

  return "ProtonVPN" if vpn_ctx&.dig(:proton)

  if KNOWN_PROTON_ASN.include?(asn_s)
    return "ProtonVPN"
  end

  provider = vpn_provider_name(org_s)

  return provider if provider

  if vpn_ctx&.dig(:active)
    return "VPN Actif (Provider masqué)"
  end

  "Fournisseur Inconnu"
end

def connection_type(infra_type, vpn_enabled)
  vpn = vpn_enabled == true

  return t(:vpn_tunnel) if vpn

  case infra_type
  when :isp
    t(:direct_isp)
  when :cloud, :hosting
    t(:cloud_hosting)
  else
    t(:unknown_infra)
  end
end


def vpn_confidence(vpn_enabled_real, vpn_provider, infra, dns_split = nil)
  score = 0

  score += 60 if vpn_enabled_real

  if vpn_provider &&
     vpn_provider != "Fournisseur Inconnu"
    score += 20
  end

  case infra
  when :vpn
    score += 20
  when :hosting
    score += 15
  when :cloud
    score += 8
  end

  if dns_split &&
     dns_split[:vpn].any?
    score += 10
  end

  [[score,0].max,100].min
end

def generate_security_score_v3(
  public_ip,
  dns_health,
  dns_status,
  tor_active,
  vpn_active,
  dns_encrypted,
  vpn_confidence,
  infra_type,
  ipv6_leak = false
)

  dns_health ||= {}

  security = 50
  killswitch_score = 100
  privacy  = 50

  #
  # IP valide
  #

  if IPGuard.sanitize(public_ip)
    security += 5
  else
    security -= 10
  end

  #
  # VPN
  #

  if vpn_active
    security += 10
    privacy += 25
  end

  if vpn_confidence.to_i >= 80
    privacy += 10
  elsif vpn_confidence.to_i >= 60
    privacy += 5
  end

  #
  # DNS chiffré
  #

  if dns_encrypted
    security += 10
    privacy += 10
  end

  #
  # DNS
  #

  case dns_status

  when :dns_secure
    security += 10
    privacy += 5

  when :dns_uncertain
    security -= 5

  when :dns_leak
    security -= 30
    privacy -= 20
  end

  #
  # Leak DNS confirmé
  #

  if dns_health[:leak]
    security -= 20
    privacy -= 20
  end

  #
  # IPv6 leak
  #

  if ipv6_leak
    security -= 20
    privacy -= 20
  end

  #
  # Tor
  #

  if tor_active
    privacy += 20
    security += 5
  end

  #
  # Infrastructure
  #

  case infra_type

  when :hosting
    security -= 5

  when :cloud
    security -= 3
  end

  security = [[security, 0].max, 100].min
  security += ((killswitch_score - 50) / 10.0).round
  privacy  = [[privacy, 0].max, 100].min

  security += killswitch_score / 10

  {
    security: security,
    privacy: privacy,
    overall: ((security + privacy) / 2.0).round
  }
end



#--------------------

def network_fingerprint(ip, geo_data)
  geo_data = geo_data.is_a?(Hash) ? geo_data : {}

  ip_s  = ip.to_s.strip
  asn   = geo_data["asn"].to_s.strip
  org   = geo_data["org"].to_s.strip.downcase

  # normalisation ASN (AS1234 → 1234)
  asn = asn.gsub(/^AS/i, "").strip

  seed = [ip_s, asn, org].join("|")

  Digest::SHA256.hexdigest(seed)[0..14]
rescue
  "unknown_fp"
end

def fingerprint_changed?(fp)
  return false unless fp.is_a?(String) && !fp.empty?

  path = File.join(DiskCache::CACHE_DIR, "last_fp")

  old =
    if File.exist?(path)
      File.read(path).to_s.strip
    end

  DiskCache.setup

  tmp = "#{path}.tmp.#{Process.pid}"

  begin
    File.write(tmp, fp)
    File.rename(tmp, path)
  rescue
    File.unlink(tmp) if File.exist?(tmp)
  end

  return false if old.nil? || old.empty?
  old != fp
end


def vpn_rotation(current_ip, geo)
  geo = geo.is_a?(Hash) ? geo : {}

  path = File.join(DiskCache::CACHE_DIR, "vpn_rotation.json")

  old =
    if File.exist?(path)
      begin
        JSON.parse(File.read(path))
      rescue
        {}
      end
    else
      {}
    end

  current = {
    "ip" => current_ip.to_s.strip,
    "asn" => geo["asn"].to_s.strip,
    "country" => geo["country_code"].to_s.strip
  }

  DiskCache.setup

  tmp = "#{path}.tmp.#{Process.pid}"

  begin
    File.write(tmp, JSON.generate(current))
    File.rename(tmp, path)
  rescue
    File.unlink(tmp) if File.exist?(tmp)
  end

  return nil unless old.is_a?(Hash) && !old.empty?

  changed =
    old["ip"] != current["ip"]
    old["asn"] != current["asn"]
    old["country"] != current["country"]

  return nil unless changed

  {
    old_country: old["country"],
    new_country: current["country"],
    old_asn: old["asn"],
    new_asn: current["asn"]
  }
end

def vpn_history_store(ip, geo, vpn_active)
  return unless vpn_active

  path = File.join(
    DiskCache::CACHE_DIR,
    "vpn_history.json"
  )

  history =
    if File.exist?(path)
      JSON.parse(File.read(path))
    else
      []
    end

  history << {
    ts: Time.now.to_i,
    ip: ip,
    country: geo["country_code"],
    asn: geo["asn"]
  }

  history = history.last(100)

  File.write(path, JSON.pretty_generate(history))
rescue
end

def vpn_history_load
  path = File.join(
    DiskCache::CACHE_DIR,
    "vpn_history.json"
  )

  return [] unless File.exist?(path)

  JSON.parse(File.read(path))
rescue
  []
end

def vpn_history_stats

  history = vpn_history_load

  return {
    countries_seen: 0,
    asn_seen: 0,
    ip_seen: 0,
    rotations_24h: 0,
    entropy: 0
  } if history.empty?

  countries =
    history.map { |h| h["country"] }.compact.uniq

  asns =
    history.map { |h| h["asn"] }.compact.uniq

  ips =
    history.map { |h| h["ip"] }.compact.uniq

  now = Time.now.to_i

  recent =
    history.select do |h|
      now - h["ts"].to_i <= 86_400
    end

  rotations = 0

  recent.each_cons(2) do |a,b|

    rotations += 1 if
      a["ip"] != b["ip"] ||
      a["asn"] != b["asn"] ||
      a["country"] != b["country"]
  end

entropy =
  countries.size * 8 +
  asns.size * 5 +
  ips.size * 2

entropy = [[entropy, 0].max, 100].min

{
  countries_seen: countries.size,
  asn_seen: asns.size,
  ip_seen: ips.size,
  rotations_24h: rotations,
  entropy: entropy
}
end

def anomaly_score(
  dns_leak,
  ipv6_leak,
  webrtc_leak,
  vpn_active,
  fp_changed,
  rotation,
  infra_type
)

  score = 0

  score += 40 if dns_leak
  score += 25 if ipv6_leak
  score += 15 if webrtc_leak

  score += 10 if fp_changed
  score += 10 if rotation

  if vpn_active &&
     infra_type == :isp
    score += 25
  end

  [[score,0].max,100].min
end


def multi_vpn_detection(vpn_ctx)
  count = 0

  count += 1 if vpn_ctx[:wireguard]
  count += 1 if vpn_ctx[:tailscale]
  count += 1 if vpn_ctx[:zerotier]
  count += 1 if vpn_ctx[:proton]

  count >= 2
end

def webrtc_leak?
  false
end

def ip_reputation_score(ip)
  return 0 unless ip

  geo_data = geo(ip)

  score = 100

  score -= 30 if tor?(ip)

  score -= 20 if vpn_by_asn?(geo_data)

  infra =
    classify_infra(
      geo_data["asn"],
      geo_data["org"]
    )

  score -= 15 if infra == :hosting

  [[score, 0].max, 100].min
rescue
  50
end


def killswitch_broken?(
  vpn_active,
  ip,
  infra_type,
  dns_leak = false,
  ipv6_leak = false
)

  return false unless vpn_active

  return true if dns_leak
  return true if ipv6_leak

  infra_type == :isp
end

def killswitch_score(
  vpn_active,
  dns_leak,
  ipv6_leak,
  infra_type,
  dns_public_count = 0
)

  return 100 unless vpn_active

  score = 100

  score -= 60 if dns_leak
  score -= 40 if ipv6_leak

  if infra_type == :isp
    score -= 50
  end

  if dns_public_count > 0
    score -= [dns_public_count * 5, 20].min
  end

  [[score, 0].max, 100].min
end




def country_status(country)
  return "⚪" unless country.is_a?(String)

  c = country.strip.upcase
  return "⚪" if c.empty? || NORMALIZED_UNKNOWN.include?(c)

  return "🟢" if ALLOWED_COUNTRIES.map(&:upcase).include?(c)
  return "🔴" if DENY_COUNTRIES.map(&:upcase).include?(c)

  "🟠"
end

# ==============================================================================
# 7. COUCHE SYSTEM DNS & HEALTH ANALYSIS
# ==============================================================================

# 1. Collecte et extraction des données brutes
def system_dns
  DiskCache.fetch("dns_system_v2", ttl: 300) do
    stdout, status = Open3.capture2("scutil", "--dns")
    return [] unless status&.success?
    return [] unless stdout.is_a?(String)

    stdout.scan(/nameserver\[\d+\]\s*:\s*([0-9a-fA-F:\.]+)/)
          .flatten
          .map(&:strip)
          .uniq
          .select { |ip| valid_ip?(ip) }
  rescue StandardError
    []
  end
end

# 2. Normalisation et classification des IPs
def normalize_dns_pack(dns_list, vpn_active)
  dns_list = Array(dns_list)

  local = []
  vpn = []
  public_dns = []

  dns_list.each do |ip|
    next unless IPGuard.valid_format?(ip)

    ip_s = ip.to_s.strip

    if IPGuard.localhost?(ip_s)
      local << ip_s

    elsif IPGuard.private_ip?(ip_s)
      vpn_active ? vpn << ip_s : local << ip_s

    elsif TRUSTED_DNS.include?(ip_s)
      public_dns << ip_s

    else
      public_dns << ip_s
    end
  end

  {
    local: local.uniq,
    vpn: vpn.uniq,
    public: public_dns.uniq
  }
end

# 3. Détections de protocoles et fonctionnalités spécifiques
def doh_detect(domain = "cloudflare.com")
  memoized("doh_#{domain}", 300) do

    endpoints = [
      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query",
      "https://dns.quad9.net/dns-query"
    ]

    success_count = 0
    valid_response = false

    endpoints.each do |endpoint|
      uri = URI("#{endpoint}?name=#{domain}&type=A")

      return false if circuit_open?(uri.host)

      begin
        res = Timeout.timeout(1.8) do
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          http.open_timeout = 0.6
          http.read_timeout = 1.2

          req = Net::HTTP::Get.new(uri)
          req["accept"] = "application/dns-json"

          http.request(req)
        end

        next unless res.is_a?(Net::HTTPSuccess)

        register_success(uri.host)

        json = JSON.parse(res.body.to_s)

        if json.is_a?(Hash) && json["Status"] == 0
          success_count += 1
          valid_response = true
        end

      rescue
        register_failure(uri.host)
        next
      end
    end

    # 🔥 LOGIQUE FINALE AMÉLIORÉE

    return false unless valid_response

    # DoH considéré actif seulement si au moins 2 providers répondent
    success_count >= 2
  end
end

def dnssec_enabled?
  return false unless brew_binary_path("dig")

  out, status = Open3.capture2("dig", "cloudflare.com", "+dnssec")

  return false unless status.success?

  # plus robuste
  out.include?("RRSIG") && out.include?("ad")
rescue
  false
end

# 4. Analyse de cohérence et de santé (Haut niveau)
def dns_consistency(vpn_detected, local_dns, vpn_dns, public_dns)
  local_dns   ||= []
  vpn_dns     ||= []
  public_dns  ||= []

  return "🟢 Cohérent (Sans VPN)" unless vpn_detected == true

  if vpn_dns.any? && public_dns.empty?
    "🟢 Sécurisé (Tunnel DNS VPN)"
  elsif vpn_dns.any? && public_dns.any?
  "🟡 DNS Mixte (à vérifier)"
  elsif public_dns.any? && !vpn_dns.any?
    "⚠️ DNS Leak possible"
  else
    "🟢 Sécurisé"
  end
end

def dns_health_check(public_dns, vpn_dns, vpn_active, vpn_detected)
  public_dns = Array(public_dns)
  vpn_dns    = Array(vpn_dns)

  leak = vpn_active == true &&
         public_dns.any? &&
         vpn_dns.empty?

  doh_active = doh_detect

  encryption_active =
    vpn_dns.any? ||
    public_dns.include?("127.0.0.1") ||
    public_dns.include?("::1") ||
    doh_active == true

  isolation_safe =
    vpn_active ? !leak : encryption_active

  status =
    if leak
      :dns_leak
    elsif encryption_active
      :dns_secure
    else
      :dns_uncertain
    end

  {
    leak: leak,
    encryption: encryption_active,
    isolation: isolation_safe,
    status: status
  }
end

def network_integrity_check(raw, dns_health)
  interface = raw[:interface]
  proxy = raw[:proxy]
  dot = raw[:dot]
  doh = raw[:doh_extended]

  vpn = raw[:vpn_state] && raw[:vpn_state][:active]
  geo = raw[:geo] || {}

  org = geo["org"].to_s.downcase
  asn = geo["asn"].to_s

  score = 100
  issues = []

  # -------------------------
  # DNS LAYER (TRÈS IMPORTANT)
  # -------------------------
  if dns_health[:leak]
    score -= 45
    issues << :dns_leak
  end

  unless doh
    score -= 12
    issues << :no_doh
  end

  score -= 5 unless dot

  # -------------------------
  # TRANSPORT LAYER
  # -------------------------
  if proxy
    score -= 30
    issues << :proxy_detected
  end

  if vpn && proxy
    score -= 20
    issues << :vpn_proxy_conflict
  end

  # -------------------------
  # INFRA SIGNALS
  # -------------------------
  if org.include?("m247") || org.include?("leaseweb") || org.include?("ovh")
    score -= 10
    issues << :datacenter_asn
  end

  # -------------------------
  # INTERFACE CONSISTENCY
  # -------------------------
  if interface.nil? || interface == "unknown"
    score -= 8
    issues << :unknown_interface
  end

  # -------------------------
  # FINAL NORMALIZATION
  # -------------------------
  score = [[score, 0].max, 100].min

  risk_level =
    case score
    when 90..100 then :clean
    when 70..89 then :low_risk
    when 40..69 then :medium_risk
    else :high_risk
    end

  {
    score: score,
    issues: issues.uniq,
    risk_level: risk_level
  }
end


# ==============================================================================
# 7.B NETWORK INTELLIGENCE (DoH / DoT / Proxy / Interface / MITM signals)
# ==============================================================================

# 1. Collecte d'informations sur l'interface et proxy
def active_network_interface
  stdout, = Open3.capture2("route", "get", "default")
  stdout.each_line do |l|
    return $1 if l =~ /interface:\s+(\w+)/
  end
  "unknown"
rescue
  "unknown"
end

def proxy_detected?
  env = ENV

  return true if env["HTTP_PROXY"] || env["http_proxy"]
  return true if env["HTTPS_PROXY"] || env["https_proxy"]
  return true if env["ALL_PROXY"] || env["all_proxy"]

  false
end

# 2. Détection avancée des protocoles de chiffrement réseau
def dot_detected?
  # DNS over TLS (port 853)
  begin
    Socket.tcp("1.1.1.1", 853, connect_timeout: 0.8) { true }
  rescue
    false
  end
end

def doh_detected_extended
  doh_detect("cloudflare.com") ||
  doh_detect("google.com") ||
  doh_detect("quad9.net")
end

# 3. Heuristiques de sécurité et scoring (Haut niveau)
def mitm_risk?(dns_health, proxy, vpn_active)
  # --- Approche 1 : Analyse contextuelle sous VPN (Heuristique passive) ---
  if vpn_active
    # Si le trafic DNS fuit hors du VPN alors qu'un proxy est actif, 
    # c'est un signal fort d'interception (ex: Charles Proxy, Burp, ou équipement tiers).
    return true if dns_health[:leak] && proxy
    return false
  end

  # --- Approche 2 : Vérification croisée hors VPN (Analyse active) ---
  # Si nous ne sommes pas sous VPN, on valide la cohérence des réponses DoH.
  # On utilise 'doh_detect' (qui interroge par défaut cloudflare.com via 1.1.1.1).
  begin
    # Si la requête DoH standard échoue ou est bloquée/altérée
    cf_ok = doh_detect("cloudflare.com")
    
    # On croise avec un second résolveur de confiance (ex: google ou quad9)
    alt_ok = doh_detect("google.com")

    # Si les deux résolveurs divergent ou échouent à fournir une réponse valide,
    # on suspecte une tentative d'interception ou de falsification DNS (MITM).
    if !cf_ok && !alt_ok
      true # Risque de MITM détecté (Pas de réponse ou réponses altérées)
    else
      false # Les résolutions de confiance sont fonctionnelles et cohérentes
    end
  rescue StandardError
    # En cas d'erreur réseau critique non gérée par doh_detect, on ne bloque pas
    false
  end
end

def entropy_network_score(history_stats)
  return 0 unless history_stats.is_a?(Hash)

  base =
    history_stats[:countries_seen].to_i * 10 +
    history_stats[:asn_seen].to_i * 6 +
    history_stats[:ip_seen].to_i * 3

  [[base, 100].min, 0].max
end

# ==============================================================================
# 8. TRUE LAZY PROXY PATTERN #class RealLazyCtxV2
# ==============================================================================
debug("STRUCTURE OK AVANT RealLazyCtx")

class RealLazyCtxV2
  def initialize(raw, &block)
    @raw = raw
    @block = block
    @evaluated = nil
    @mutex = Mutex.new
  end

  def get(key)
    @mutex.synchronize do
      # On évalue le bloc une seule fois à la demande (Lazy Loading global)
      @evaluated ||= @block.call
      @evaluated[key]
    end
  end

  def [](key)
    get(key)
  end
end

# ==============================================================================
# build_ctx_lazy_v2
# ==============================================================================

def build_ctx_lazy_v2(raw)
  RealLazyCtxV2.new(raw) do

    geo = raw[:geo] || {}
    geo_for_fp = geo.is_a?(Hash) ? geo : {}

    scores = generate_security_score_v3(
      raw[:ip],
      raw[:dns_health_check],
      raw[:dns_status],
      raw[:tor_exit],
      raw[:vpn_enabled_real],
      raw[:dns_encrypted],
      raw[:vpn_confidence_score],
      raw[:infra_type],
      raw[:ipv6_leak]
    )

    {
      ip: raw[:ip],

      isp: raw[:geo]["isp"] ||
           raw[:geo]["org"] ||
           raw[:geo]["asn_org"],

      network_type: raw[:infra_type],

      connection_type: connection_type(
        raw[:infra_type],
        raw[:vpn_enabled_real]
      ),

      country: raw[:geo]["country_code"],

      vpn: raw[:vpn_enabled_real],
      vpn_suspected: raw[:vpn_suspected],
      vpn_confidence: raw[:vpn_confidence_score],
      vpn_provider: raw[:vpn_provider],

      history_stats: raw[:history_stats],
      anomaly_score: raw[:anomaly_score],

      tor: raw[:tor_exit],
      tor_process: raw[:tor_proc],
      tor_socks: raw[:tor_socks_status],

      reputation_score: raw[:reputation_score],
      killswitch_score: raw[:killswitch_score],
      multi_vpn: raw[:multi_vpn],
      bandwidth: raw[:bandwidth],
      webrtc_leak: raw[:webrtc_leak],

      wireguard: raw[:wireguard_on],
      tailscale: raw[:tailscale_on],
      zerotier: raw[:zerotier_on],

      ipv6: raw[:ipv6],
      ipv6_leak: raw[:ipv6_leak],

      dnssec: dnssec_enabled?,

      dns_leak: raw[:dns_leak],
      dns_encrypted: raw[:dns_encrypted],
      dns_status: raw[:dns_status],
      dns_isolation: raw[:dns_isolation],

      dns_local: raw[:dns_local],
      dns_vpn: raw[:dns_vpn],
      dns_public: raw[:dns_public],

      latency: raw[:lat],
      jitter: raw[:jit],

      apple_relay: raw[:apple_relay_detected],

      fingerprint: network_fingerprint(
        raw[:ip],
        geo_for_fp
      ),

      security_score: scores[:security],
      privacy_score: scores[:privacy],
      score: scores[:overall],

      dns_consistency: dns_consistency(
        raw[:vpn_enabled_real],
        raw[:dns_local],
        raw[:dns_vpn],
        raw[:dns_public]
      )
    }
  end
end

# ==============================================================================
# 9. ENGINE EXECUTION MAIN BLOCK
# ==============================================================================
def run_pipeline
  results = {}
  threads = []

  threads << Thread.new do
    results[:dns] = system_dns rescue []
  end

  threads << Thread.new do
    results[:perf] = measure_network_perf rescue { latency: 999, jitter: 0 }
  end

  threads << Thread.new do
    results[:tor_proc] = tor_process? rescue false
  end

  threads << Thread.new do
    results[:tor_socks] = tor_socks? rescue false
  end

  threads << Thread.new do
    ip = fetch_ip
    ip = IPGuard.sanitize(ip)
    results[:ip] = ip
    results[:geo] = ip ? geo_with_ip_cache(ip) : local_geo_fallback(nil)
  end

  threads.each(&:join)
  results
end

def build_raw_context
  bandwidth = bandwidth_stats

  ctx_net = global_network_context

  ip = ctx_net[:ip]
  geo_info = ctx_net[:geo] || local_geo_fallback(nil)

  dns_list = ctx_net[:dns] || []

  vpn_ctx = vpn_state

  dns_split = normalize_dns_pack(
    dns_list,
    vpn_ctx[:active]
  )

  dns_health = dns_health_check(
    dns_split[:public],
    dns_split[:vpn],
    vpn_ctx[:active],
    vpn_ctx[:active]
  )

  {
    ip: ip,
    geo: geo_info,

    dns: dns_list,

    perf: ctx_net[:perf],

    vpn_state: vpn_ctx,

    tor_proc: tor_process?,
    tor_socks: tor_socks?,

    ipv6: fetch_ipv6,
    ipv6_geo: geo_ipv6,

    bandwidth: bandwidth,

    interface: active_network_interface,
    proxy: proxy_detected?,
    dot: dot_detected?,
    doh_extended: doh_detected_extended,

    dns_health: dns_health,

    network_integrity: network_integrity_check(
      {
        interface: active_network_interface,
        proxy: proxy_detected?,
        dot: dot_detected?,
        doh_extended: doh_detected_extended,
        vpn_state: vpn_ctx,
        geo: geo_info
      },
      dns_health
    )
  }
end

# ==============================================================================
# 10. MAIN
# ==============================================================================

module UI
  def self.print_if(condition, text)
    puts text if condition
  end

  def self.print_if_active(condition, text)
    puts text if condition
  end

  def self.print_if_warning(condition, label, warning_text)
    puts "#{label}: #{warning_text}" if condition
  end
end

def main
  STDOUT.set_encoding('utf-8') if STDOUT.respond_to?(:set_encoding)

  raw = build_raw_context 

  vpn_ctx = raw[:vpn_state] || { active: false, wireguard: false, tailscale: false, zerotier: false }

  clean_public_ip   = raw[:ip].to_s.strip
  geo_info          = raw[:geo] || {}
  active_dns        = raw[:dns]
  perf              = raw[:perf] || { latency: 999, jitter: 0 }
  tor_proc          = raw[:tor_proc]
  tor_socks_status  = raw[:tor_socks]

  local_ip = fallback_local_ip
  current_ip = (!clean_public_ip.empty? ? clean_public_ip : local_ip).to_s.strip
  tor_exit = !current_ip.empty? ? tor?(current_ip) : false

  # Utilisation d'une initialisation sécurisée pour $runtime_ctx si non défini globalement
  $runtime_ctx ||= {}
  $runtime_ctx[:using_public_ip] = !clean_public_ip.empty?
  $runtime_ctx[:fallback_used]   = clean_public_ip.empty? && !local_ip.nil?

  asn  = geo_info["asn"].to_s
  org  = geo_info["org"].to_s
  isp  = geo_info["isp"].to_s

  infra_source = "#{org} #{isp} #{geo_info["asn_org"]}".downcase.strip
  infra_type = classify_infra(asn, infra_source)

  debug("CURRENT_IP=#{current_ip}")
  debug("GEO_INFO=#{geo_info.inspect}")

  datacenter_proxy = (infra_type == :hosting)

  vpn_enabled_real = !!(vpn_ctx[:active] || vpn_ctx[:wireguard] || vpn_ctx[:tailscale] || vpn_ctx[:zerotier])

  dns_split = normalize_dns_pack(active_dns, vpn_enabled_real)

  confidence = vpn_confidence(
    vpn_enabled_real,
    resolve_vpn_provider(org, asn, isp, vpn_ctx),
    infra_type,
    dns_split
  )
  
  vpn_detected = vpn_enabled_real || (infra_type == :vpn && confidence >= 75)
  vpn_suspected = !vpn_enabled_real && $runtime_ctx[:using_public_ip] && (infra_type == :vpn || confidence >= 70) && !killswitch_broken?(vpn_enabled_real, current_ip, infra_type)

  debug("DNS_LOCAL=#{dns_split[:local].inspect}")
  debug("DNS_VPN=#{dns_split[:vpn].inspect}")
  debug("DNS_PUBLIC=#{dns_split[:public].inspect}")

  dns_health = dns_health_check(dns_split[:public], dns_split[:vpn], vpn_enabled_real, vpn_detected)

  interface = raw[:interface]
  proxy     = raw[:proxy]
  dot       = raw[:dot]
  doh_ext   = raw[:doh_extended]

  net_integrity = network_integrity_check(
    {
      interface: interface,
      proxy: proxy,
      dot: dot,
      doh_extended: doh_ext,
      vpn_state: vpn_ctx,
      geo: geo_info
    },
    dns_health
  )

  mitm = mitm_risk?(dns_health, proxy, vpn_enabled_real)

  webrtc_leak = webrtc_leak?
  reputation = ip_reputation_score(current_ip)
  multi_vpn = multi_vpn_detection(vpn_ctx)

  vpn_history_store(
    current_ip,
    geo_info,
    vpn_enabled_real
  )

  apple_relay_detected = apple_relay_ip?(current_ip, geo_info)
  ipv6_leak_detected = ipv6_leak?(geo_info, raw[:ipv6_geo], vpn_enabled_real)

  rotation = vpn_enabled_real ? vpn_rotation(current_ip, geo_info) : nil
  
  fp = network_fingerprint(current_ip, geo_info)
  fp_changed = fingerprint_changed?(fp)

  anomaly = anomaly_score(
    dns_health[:leak],
    ipv6_leak_detected,
    webrtc_leak,
    vpn_enabled_real,
    fp_changed,
    rotation,
    infra_type
  )

  anomaly += 15 if proxy
  anomaly += 10 if !dot
  anomaly += 10 if !doh_ext
  anomaly += 20 if mitm
  anomaly = [[anomaly, 0].max, 100].min

  # Correction de l'appel : Ajout des arguments requis par la signature de killswitch_broken?
  killswitch = killswitch_broken?(
    vpn_enabled_real,
    current_ip,
    infra_type,
    dns_health[:leak],
    ipv6_leak_detected
  )

  killswitch_score_value = killswitch_score(
    vpn_enabled_real,
    dns_health[:leak],
    ipv6_leak_detected,
    infra_type,
    dns_split[:public].size
  )

  # Récupération sécurisée des stats d'historique (évite le NameError)
  history_stats_data = defined?(vpn_history_stats) ? vpn_history_stats : {}

  raw_data = {
    ip:                    current_ip,
    geo:                   geo_info,
    infra_type:            infra_type,
    dns_list:              active_dns,
    dns_split:             dns_split,
    dns_status:            dns_health[:status],
    dns_encrypted:         dns_health[:encryption],
    dns_isolation:         dns_health[:isolation],
    dns_local:             dns_split[:local],
    dns_vpn:               dns_split[:vpn],
    dns_public:            dns_split[:public],
    dns_leak:              dns_health[:leak],
    dns_health_check:      dns_health,
    vpn_detected:          vpn_detected,
    vpn_suspected:         vpn_suspected,
    vpn_confidence_score:  confidence,
    vpn_enabled_real:      vpn_enabled_real,
    vpn_state:             vpn_ctx,
    vpn_provider:          resolve_vpn_provider(org, asn, isp, vpn_ctx),
    tor_proc:              tor_proc,
    tor_socks_status:      tor_socks_status,
    tor_exit:              tor_exit,
    lat:                   perf[:latency],
    jit:                   perf[:jitter],
    apple_relay_detected:  apple_relay_detected,
    ipv6:                  raw[:ipv6],
    ipv6_geo:              raw[:ipv6_geo],
    ipv6_leak:             ipv6_leak_detected,
    webrtc_leak:           webrtc_leak,
    reputation_score:      reputation,
    history_stats:         history_stats_data,
    anomaly_score:         anomaly,
    multi_vpn:             multi_vpn,
    killswitch_score:      killswitch_score_value,
    bandwidth:             raw[:bandwidth],
    wireguard_on:          vpn_ctx[:wireguard],
    tailscale_on:          vpn_ctx[:tailscale],
    zerotier_on:           vpn_ctx[:zerotier]
  }

  ctx = build_ctx_lazy_v2(raw_data)

  # Définition par défaut de APP_VERSION si non existante
  app_ver = defined?(APP_VERSION) ? APP_VERSION : "1.0.0"

  if defined?(JSON_MODE) && JSON_MODE
    puts JSON.generate({
      webrtc_leak:      webrtc_leak,
      reputation_score: reputation,
      multi_vpn:        multi_vpn,
      bandwidth:        raw[:bandwidth],
      software: { name: "xbar-vpn-flag", version: app_ver },
      network: {
        ip:                 ctx.get(:ip),
        country:            ctx.get(:country),
        provider:           geo_info["asn_org"],
        asn:                geo_info["asn"],
        infrastructure_type: ctx.get(:network_type).to_s.upcase,
        connection_type:     ctx.get(:connection_type),
        latency_ms:          ctx.get(:latency),
        jitter_ms:           ctx.get(:jitter),
        fingerprint:         ctx.get(:fingerprint)
      },
      security: {
        vpn_active:            ctx.get(:vpn),
        vpn_suspected:         ctx.get(:vpn_suspected),
        vpn_confidence:        ctx.get(:vpn_confidence),
        vpn_enabled_interface: ctx.get(:vpn),
        vpn_provider_resolved: ctx.get(:vpn_provider),
        apple_private_relay:   ctx.get(:apple_relay),
        tor_exit_node:         ctx.get(:tor),
        tor_local_process:     ctx.get(:tor_process),
        tor_local_socks:       ctx.get(:tor_socks),
        wireguard:             ctx.get(:wireguard),
        tailscale:             ctx.get(:tailscale),
        zerotier:              ctx.get(:zerotier),
        security_score:        ctx.get(:security_score),
        privacy_score:         ctx.get(:privacy_score),
        overall_score:         ctx.get(:score)
      },
      dns: {
        servers:       active_dns,
        leak_detected: ctx.get(:dns_leak),
        dns_health_check: raw_data[:dns_health_check],
        encrypted:     ctx.get(:dns_encrypted),
        consistency:   ctx.get(:dns_consistency)
      }
    })
  else
    # Fallbacks pour les couleurs et méthodes de traduction si manquantes
    color_secure = defined?(COLOR_SECURE) ? COLOR_SECURE : "#00ff00"
    
    # Méthode helper de traduction locale sécurisée
    def self.safe_t(key)
      defined?(t) ? t(key) : key.to_s.upcase
    end

    # Méthode helper pour les drapeaux sécurisée
    def self.safe_flag(code)
      defined?(flag) ? flag(code) : "🏳️"
    end

    icon = ctx.get(:vpn) ? "🔐" : "🔓"
    country_code = raw.dig(:geo, "country_code")
    flag_emoji = safe_flag(country_code)
    menu_color = ctx.get(:vpn) ? color_secure : "#ffff00"

    # 1. Header
    puts "#{icon} #{flag_emoji} | color=#{menu_color} dropdown=true"
    puts "---"
    puts "VPN Checker #{app_ver}"
    puts "---"

    # 2. Identité réseau
    puts "#{safe_t(:public_ip)}: #{ctx.get(:ip)}"
    puts "🌍 #{safe_t(:country)}: #{country_code} #{flag_emoji}"
    puts "#{safe_t(:provider)}: #{ctx.get(:isp)} • Infrastructure: #{ctx.get(:network_type)}"
    puts "Connexion: #{ctx.get(:connection_type)}"
    puts "---"

    # 3. Tunnels
    tunnels = []
    tunnels << "🛡️ WireGuard" if vpn_ctx[:wireguard]
    tunnels << "🛸 Tailscale" if vpn_ctx[:tailscale]
    tunnels << "🪐 ZeroTier" if vpn_ctx[:zerotier]

    if tunnels.empty?
      puts "🌐 Tunnel (WireGuard, Tailscale, ZeroTier) : Aucun"
    else
      puts "🌐 Tunnels : #{tunnels.join(' + ')}"
    end

    puts "🏢 Hébergement : #{geo_info['org']}" if datacenter_proxy

    puts "---"

    # 4. VPN / sécurité globale
    vpn_label =
      if ctx.get(:vpn)
        "Actif"
      elsif ctx.get(:vpn_confidence).to_i >= 70
        "Suspecté"
      else
        "Inactif"
      end

    security_icon =
      case ctx.get(:security_score).to_i
      when 90..100 then "🟢"
      when 75..89 then "🟡"
      else "🔴"
    end

    privacy_icon =
      case ctx.get(:privacy_score).to_i
      when 90..100 then "🔒"
      when 75..89 then "🟡"
      else "🔴"
    end

    puts "Sécurité Réseau: #{security_icon}"
    puts "🛡️Security : #{ctx.get(:security_score)}% • #{privacy_icon} 👤Privacy : #{ctx.get(:privacy_score)}% • ⭐ Global : #{ctx.get(:score)}%"
    puts "• Statut VPN: #{vpn_label} (Confiance: #{ctx.get(:vpn_confidence)}%)"
    puts "• Fournisseur VPN détecté: #{ctx.get(:vpn_provider)}"

    puts "🚨 Kill Switch FAIL" if killswitch

    ks_icon =
      case ctx.get(:killswitch_score).to_i
      when 90..100 then "🟢"
      when 70..89 then "🟡"
      else "🔴"
      end

    puts "#{ks_icon} Kill Switch Score : #{ctx.get(:killswitch_score)}%"

    # 5. DNS et fuites
    puts "DNS Chiffré: #{ctx.get(:dns_encrypted) ? '🟢 Oui' : 'Non'}"

    iso_status = ctx.get(:dns_isolation) ? "safe" : "at risk"
    puts "🛡️ DNS Isolation : #{iso_status} • 🔄 Consistance : #{ctx.get(:dns_consistency)}"

    UI.print_if_active(ctx.get(:dnssec), "• DNSSEC 🟢")

    UI.print_if_warning(dns_health[:leak], "• DNS Leak", "⚠️ Détecté")
    UI.print_if_warning(ipv6_leak_detected, "• IPv6 Leak", "⚠️ Détecté")

    # 6. Anonymat / privacy
    UI.print_if_active(ctx.get(:apple_relay), "• Apple Private Relay : 🟢")

    UI.print_if(tor_exit, "🧅 Tor Network : 🔴 Nœud de sortie actif")
    UI.print_if((tor_proc || tor_socks_status), "🧅 Tor Network : 🟡 Local actif")

    puts "🌐 WebRTC Leak : #{ctx.get(:webrtc_leak) ? '⚠️ Oui' : '🟢 Non'}"
    puts "---"
    puts "🧠 Network Integrity"

    ni = net_integrity

    risk_icon =
      case ni[:risk_level]
      when :clean then "🟢"
      when :low_risk then "🟡"
      when :medium_risk then "🟠"
      else "🔴"
      end

    puts "• Score intégrité réseau: #{risk_icon} #{ni[:score]}/100"

    label =
      case ni[:risk_level]
      when :clean then "Réseau sain"
      when :low_risk then "Anomalies mineures"
      when :medium_risk then "Comportement suspect"
      else "Risque réseau élevé"
      end

    puts "• Statut: #{label}"

    if ni[:issues] && ni[:issues].any?
      puts "• Signaux détectés:"
      ni[:issues].each do |i|
        readable =
          case i
          when :proxy_detected then "Proxy actif détecté"
          when :dns_leak then "Fuite DNS"
          when :no_doh then "Pas de DoH détecté"
          when :vpn_proxy_conflict then "Conflit VPN / Proxy"
          when :datacenter_asn then "ASN datacenter suspect"
          when :unknown_interface then "Interface réseau inconnue"
          else i.to_s
          end

        puts "   - #{readable}"
      end
    else
      puts "• Aucun signal d’anomalie"
    end

    puts "🏆 Réputation IP : #{ctx.get(:reputation_score)}/100"
    puts "🔀 Multi VPN : #{ctx.get(:multi_vpn) ? 'Oui' : 'Non'}"

    history = ctx.get(:history_stats) || {}
    puts "📚 Pays vus : #{history[:countries_seen]} • 🏢 ASN vus : #{history[:asn_seen]} • 🌍 IP vues : #{history[:ip_seen]}"
    puts "🔄 Rotations 24h : #{history[:rotations_24h]}"

    entropy = history[:entropy].to_i
    anomaly_val = ctx.get(:anomaly_score).to_i

    entropy_icon = entropy <= 20 ? "🟢" : entropy <= 50 ? "🟡" : "🔴"
    anomaly_icon = anomaly_val <= 20 ? "🟢" : anomaly_val <= 50 ? "🟡" : "🔴"

    puts "Entropy : #{entropy_icon} #{entropy}% • Anomaly : #{anomaly_icon} #{anomaly_val}%"

    puts "---"

    # 8. DNS servers
    puts "DNS Servers Detected :"

    all_dns_detected = [
      ctx.get(:dns_local),
      ctx.get(:dns_vpn),
      ctx.get(:dns_public)
    ].compact.flatten.uniq

    if all_dns_detected.empty?
      puts "-- Aucun serveur détecté (Système par défaut)"
    else
      grouped_dns = Hash.new { |h, k| h[k] = [] }

      all_dns_detected.each do |dns_ip|
        label_dns =
          if defined?(DNS_PROVIDERS) && DNS_PROVIDERS.key?(dns_ip)
            DNS_PROVIDERS[dns_ip]
          elsif defined?(IPGuard) && (IPGuard.private_ip?(dns_ip) || IPGuard.localhost?(dns_ip))
            ctx.get(:vpn) ? "🔐 VPN Private DNS" : "🏠 DNS Local / Routeur"
          else
            "🌐 DNS Public Alternatif"
          end

        grouped_dns[label_dns] << dns_ip
      end

      grouped_dns.each do |l, ips|
        puts "-- #{l} (#{ips.uniq.join(', ')})"
      end
    end

    puts "---"

    # 9. Events
    puts "⚠️ Infrastructure modifiée" if fp_changed

    if rotation
      puts "---"
      puts "🔄 Rotation VPN détectée"
      puts "-- #{rotation[:old_country]} → #{rotation[:new_country]}"
      puts "-- AS#{rotation[:old_asn]} → AS#{rotation[:new_asn]}"
    end

    # 10. Performance
    puts "---"
    puts "Performances réseau:"
    bw = ctx.get(:bandwidth) || {}

    puts "• RX : #{bw[:rx_mb]} MB • TX : #{bw[:tx_mb]} MB"
    puts "• Latence standard: #{ctx.get(:latency)} ms • Jitter: #{ctx.get(:jitter)} ms"

    # 11. Fingerprint
    puts "---"
    puts "Empreinte Réseau (Fingerprint): #{ctx.get(:fingerprint)} | color=#888888"
  end
end

main
