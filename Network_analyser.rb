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
require 'fileutils'
require 'timeout'
require 'tmpdir'
require 'open3'
require 'openssl'
require 'openssl'
require 'base64'


$runtime_ctx ||= { using_public_ip: false, fallback_used: false }
$tor_state ||= { ts: Time.at(0), ips: {} }
$cache_mutex ||= Mutex.new

THREAD_TIMEOUT = 1.2
DEBUG_ERRORS = true

def log_error(e, context = "")
  warn "[ERROR] #{context}: #{e.class} - #{e.message}" if DEBUG_ERRORS
end

# ==============================================================================
# 1. CONFIGURATION & GLOBALES
# ==============================================================================
APP_VERSION = "v3.0.4"

ALLOWED_COUNTRIES = %w[NL CH PL RO US].freeze
DENY_COUNTRIES    = %w[FR].freeze
PING_HOSTS        = %w[1.1.1.1 8.8.8.8].freeze
TRUSTED_DNS       = %w[
  1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 127.0.0.1
  2606:4700:4700::1111 2606:4700:4700::1001 2001:4860:4860::8888 2001:4860:4860::8844
  2620:fe::fe 2620:fe::9 ::1
].freeze

KNOWN_SAFE_DNS_ASNS = %w[13335 15169 19281 34939 212772].freeze

VPN_PROVIDER_KEYWORDS = {
  "proton"       => "ProtonVPN",
  "mullvad"      => "Mullvad",
  "nordvpn"      => "NordVPN",
  "surfshark"    => "Surfshark",
  "expressvpn"   => "ExpressVPN",
  "ivpn"         => "IVPN",
  "cyberghost"   => "CyberGhost",
  "pia"          => "Private Internet Access",
  "m247"         => "M247",
  "datacamp"     => "DataCamp",
  "leaseweb"     => "Leaseweb",
  "digitalocean" => "DigitalOcean",
  "ovh"          => "OVH",
  "choopa"       => "Choopa",
  "vultr"        => "Vultr",
  "hetzner"      => "Hetzner"
}.freeze

KNOWN_PROTON_ASN = %w[212238 51852].freeze
APPLE_RELAY_ASNS = %w[6185 714 54114 213426].freeze

DNS_PROVIDERS = {
  "1.1.1.1" => "☁️ Cloudflare", "1.0.0.1" => "☁️ Cloudflare",
  "8.8.8.8" => "🟦 Google",     "8.8.4.4" => "🟦 Google",
  "9.9.9.9" => "🌐 Quad9",      "149.112.112.112" => "🌐 Quad9",
  "127.0.0.1" => "🔐 DNSCrypt"
}.freeze

COLOR_SECURE = "#006400"
COLOR_WARN   = "#FF9500"
COLOR_ALERT  = "#FF3B30"

DEBUG     = ARGV.include?("--debug")
JSON_MODE = ARGV.include?("--json")

def debug(msg)
  warn "[DEBUG] #{msg}" if DEBUG
end

# ==============================================================================
# 2. COUCHE RESILIENCE & CACHE
# ==============================================================================
def encryption_key
  @encryption_key ||= Digest::SHA256.hexdigest(
    `${'scutil --computer'}.chomp + ${'scutil --localHostName'}.chomp + ENV['USER']`
  )[0..31] # 32 bytes pour AES-256
end

def encrypt_data(data, key = encryption_key)
  cipher = OpenSSL::Cipher.new('aes-256-cbc')
  cipher.encrypt
  cipher.key = Digest::SHA256.digest(key)
  iv = cipher.random_iv
  encrypted = cipher.update(data) + cipher.final
  Base64.strict_encode64(iv + encrypted)
end


class LRUCachePro
  Entry = Struct.new(:value, :ts, :loading)

  def initialize(max_size: 300, ttl_default: 30)
    @max_size = max_size
    @ttl_default = ttl_default
    @data = {}
    @order = []
    @mutex = Mutex.new
    @stats = { hit: 0, miss: 0, expired: 0, stampede_block: 0 }
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
      @data[key] = Entry.new(nil, now, true)
    end

    value = yield

    @mutex.synchronize do
      evict_if_needed
      @data[key] = Entry.new(value, now, false)
      @order << key
    end
    value
  end

  def stats; @stats; end

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

$CACHE = LRUCachePro.new

def memoized(key, ttl = 30)
  stack = (Thread.current[:memo_stack] ||= [])
  return yield if stack.include?(key)
  stack << key
  begin
    $CACHE.fetch(key, ttl: ttl) { yield }
  ensure
    stack.delete_at(stack.rindex(key) || 0)
  end
end

module IPGuard
  module_function
  MULTICAST_V4 = IPAddr.new('224.0.0.0/4')

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
    return nil if addr.loopback? || addr.link_local? || ipv4_multicast?(addr)
    ip
  end

  def ipv4_multicast?(addr)
    addr.ipv4? && MULTICAST_V4.include?(addr)
  end

  def valid_format?(ip)
    !parse(ip).nil?
  end
end

module DiskCache
  # Utilisation du dossier Caches de l'utilisateur au lieu du dossier temporaire global
  CACHE_DIR = File.expand_path("~/Library/Caches/com.xbar.vpn_checker_v3")

  class << self
    def setup
      # Création du dossier s'il n'existe pas
      unless Dir.exist?(CACHE_DIR)
        FileUtils.mkdir_p(CACHE_DIR)
      end
      
      # Application de permissions strictes (Propriétaire : Lecture/Écriture/Exécution)
      File.chmod(0700, CACHE_DIR)
      
      # Nettoyage des vieux fichiers temporaires
      Dir.glob(File.join(CACHE_DIR, "*.tmp.*")).each do |file|
        if File.exist?(file) && (Time.now - File.mtime(file) > 7200)
          File.unlink(file) rescue nil
        end
      end
    rescue StandardError => e
      debug("Impossible de configurer le dossier de cache: #{e.message}")
    end

    def safe_json_parse(str)
      JSON.parse(str)
    rescue JSON::ParserError, TypeError
      nil
    end

    def fetch(key, ttl: 3600)
      setup
      file_key = Digest::SHA256.hexdigest(key)
      cache_file = File.join(CACHE_DIR, "cache.#{file_key}.json")

      # Lecture si le cache est valide
      if File.exist?(cache_file) && (Time.now - File.mtime(cache_file) < ttl)
        cached_data = safe_json_parse(File.read(cache_file))
        return cached_data["data"] if cached_data && cached_data.key?("data")
      end

      # Exécution du bloc si cache manquant ou expiré
      value = yield
      
      begin
        if value
          # Écriture des données
          File.write(cache_file, JSON.generate({ "data" => value }))
          # Verrouillage du fichier (Propriétaire : Lecture/Écriture uniquement)
          File.chmod(0600, cache_file)
        end
      rescue StandardError => e
        debug("Échec de l'écriture sécurisée DiskCache: #{e.message}")
      end
      
      value
    end
  end
end

# ==============================================================================
# 3. UTILS SYSTEME MAC & RESEAU DE BASE
# ==============================================================================
def fallback_local_ip
  Socket.ip_address_list.find { |ai|
    ai.ipv4? && !ai.ipv4_loopback? && !ai.ipv4_multicast? }&.ip_address || "127.0.0.1"
rescue StandardError
  "127.0.0.1"
end

def local_geo_fallback(ip)
  {
    "country_code" => "🔒",
    "org" => "Réseau Local Inconnu",
    "isp" => "Pas de réponse Géo",
    "asn" => "AS0",
    "asn_org" => "Local Session"
  }
end

def global_network_context
  @global_ctx ||= memoized("global_net_ctx", 10) do
    ip = fetch_ip
    ip = IPGuard.sanitize(ip)
    procs = process_snapshot_global
    vpn_st = vpn_state(procs)
    {
      ip: ip,
      geo: ip ? geo_with_ip_cache(ip) : local_geo_fallback(nil),
      vpn_state: vpn_st,
      dns: system_dns,
      perf: measure_network_perf,
      procs: procs
    }
  end
end

def process_snapshot_global
  @proc_cache ||= { ts: 0, value: Set.new }
  now = Time.now.to_i
  return @proc_cache[:value] if now - @proc_cache[:ts] < 5

  stdout, status = Open3.capture2("ps", "-A", "-o", "comm=")
  return Set.new unless status.success?

  value = stdout.lines.map { |l| File.basename(l.strip).downcase }.to_set
  @proc_cache = { ts: now, value: value }
  value
rescue StandardError => e
  debug("process_snapshot_global fail: #{e.message}")
  Set.new
end

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

# ==============================================================================
# 4. MOTEUR DE PROTOCOLE IP & VALIDATIONS
# ==============================================================================
def flag(country)
  return "🏳️" unless country.is_a?(String) && country.match?(/\A[A-Z]{2}\z/)
  memoized("flag_#{country}", 86400) do
    country.upcase.chars.map { |c| (0x1F1E6 + c.ord - 65).chr(Encoding::UTF_8) }.join
  end
rescue StandardError
  "🏳️"
end

# ==============================================================================
# 5. DETECTEURS RESEAU (IP, Geo, ASN, Apple Relay, Tor)
# ==============================================================================

module VPNChecker
  class Error < StandardError; end
  class NetworkError < Error; end
  class CacheError < Error; end

  def self.handle_error(e, context: "")
    case e
    when NetworkError then debug("[NETWORK] #{context}: #{e.message}")
    when CacheError then debug("[CACHE] #{context}: #{e.message}")
    else debug("[UNKNOWN] #{context}: #{e.class} - #{e.message}")
    end
  end
end

def last_known_good_ip
  path = File.join(DiskCache::CACHE_DIR, "last_good_ip.json")
  return nil unless File.exist?(path)

  data = JSON.parse(File.read(path)) rescue nil
  return nil unless data && data["ip"] && data["ts"]

  # Vérifie que le cache a moins de 24h
  return nil if Time.now.to_i - data["ts"] > 86_400

  ip = data["ip"]
  IPGuard.sanitize(ip) ? ip : nil
end

def store_last_known_good_ip(ip)
  return unless ip.is_a?(String) && IPGuard.sanitize(ip)
  path = File.join(DiskCache::CACHE_DIR, "last_good_ip.json")
  DiskCache.setup
  File.write(path, JSON.generate({ ip: ip, ts: Time.now.to_i }))
rescue StandardError
  nil
end

def with_retry(max_retries: 3, base_delay: 0.5, &block)
  retries = 0
  begin
    block.call
  rescue StandardError => e
    retries += 1
    if retries <= max_retries
      sleep(base_delay * (2 ** (retries - 1))) # Backoff exponentiel
      retry
    end
    raise
  end
end



def fetch_ip
  memoized("public_ip", 300) do
    urls = %w[
      https://api64.ipify.org?format=text
      https://checkip.amazonaws.com
      https://api.ipify.org?format=text
    ].uniq

    threads = urls.map do |url|
      Thread.new do
        uri = URI(url)
        Net::HTTP.start(uri.host, uri.port,
                       use_ssl: true,
                       open_timeout: 1.2,
                       read_timeout: 1.2) do |http|
          res = http.get(uri.request_uri)
          res.is_a?(Net::HTTPSuccess) ? IPGuard.sanitize(res.body.to_s.strip) : nil
        end
      rescue StandardError
        nil
      end
    end

    # Attend le premier résultat valide
    ip = nil
    threads.each do |t|
      result = t.value
      if result
        ip = result
        threads.each(&:kill) # Arrête les autres threads
        break
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

def fetch_geo_provider(url)
  uri = URI(url)
  req = Net::HTTP::Get.new(uri)
  req["User-Agent"] = "xbar-vpn-checker/#{APP_VERSION}"

  # Utilisation exclusive des timeouts natifs de Net::HTTP
  res = Net::HTTP.start(uri.host, uri.port, 
                        use_ssl: uri.scheme == 'https', 
                        verify_mode: OpenSSL::SSL::VERIFY_PEER, 
                        open_timeout: 1.5, 
                        read_timeout: 2.0,
                        write_timeout: 1.5) do |http|
    http.get(uri.request_uri)
  end
  
  res.is_a?(Net::HTTPSuccess) ? JSON.parse(res.body.to_s) : nil
rescue StandardError => e 
  # Cela capturera automatiquement Net::OpenTimeout et Net::ReadTimeout
  debug("fetch_geo_provider fail pour #{url}: #{e.class} - #{e.message}")
  nil
end

def geo(ip)
  cleaned_ip = ip.to_s.strip
  return local_geo_fallback(cleaned_ip) unless IPGuard.sanitize(cleaned_ip)

  DiskCache.fetch("geo_v9_#{cleaned_ip}", ttl: 86_400) do
    urls = [
      { url: "https://ipwho.is/#{cleaned_ip}", parser: "ipwho" },
      { url: "https://ip-api.com/json/#{cleaned_ip}?fields=status,countryCode,org,as,isp", parser: "ipapi" }
    ]

    threads = urls.map do |entry|
      Thread.new do
        raw = fetch_geo_provider(entry[:url])
        normalize_geo(raw, entry[:parser])
      end
    end

    # Attend tous les threads et prend le premier résultat valide
    results = threads.map(&:value).compact
    results.first || local_geo_fallback(cleaned_ip)
  end
end

def geo_with_ip_cache(ip)
  return local_geo_fallback(nil) unless ip
  memoized("geo_for_#{ip}", 86400) { geo(ip) }
end

def normalize_geo(data, provider)
  return nil if data.nil? || data.empty?
  case provider
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

def active_vpn_interfaces
  # -l affiche une liste séparée par des espaces, -u filtre celles qui sont "UP"
  stdout, status = Open3.capture2("ifconfig", "-l", "-u")
  return [] unless status.success?

  # On récupère les interfaces et on filtre celles liées aux VPN
  stdout.strip.split.select do |iface|
    iface.start_with?("utun") || iface.start_with?("wg") || iface.start_with?("ipsec")
  end
rescue StandardError => e
  debug("Erreur active_vpn_interfaces: #{e.message}")
  []
end

def active_default_interface
  # Demande explicitement à macOS l'interface utilisée pour le trafic sortant
  stdout, status = Open3.capture2("route", "-n", "get", "default")
  return nil unless status.success?

  # On cherche la ligne "interface: en0" ou "interface: utun2"
  match = stdout.match(/interface:\s*([a-z0-9]+)/i)
  match ? match[1] : nil
rescue StandardError => e
  debug("Erreur active_default_interface: #{e.message}")
  nil
end

def utun_default_route?
  iface = active_default_interface
  return false unless iface
  
  iface.start_with?("utun") || iface.start_with?("wg") || iface.start_with?("tailscale")
end



def proton_wireguard_detected?(procs, utuns, scutil_out)
  return true if procs.any? { |p| p.include?("proton") && p.include?("vpn") }
  return true if scutil_out.downcase.include?("proton")
  return true if !utuns.empty?
  false
end

def tor_fetch_exit_nodes
  $cache_mutex.synchronize do
    return $tor_state[:ips] if Time.now - $tor_state[:ts] < 14400
  end

  raw = begin
    uri = URI("https://check.torproject.org/exit-addresses")
    # Timeouts natifs gèrent la résilience
    Net::HTTP.start(uri.host, uri.port, 
                    use_ssl: true, 
                    verify_mode: OpenSSL::SSL::VERIFY_PEER, 
                    open_timeout: 1.5, 
                    read_timeout: 2.0,
                    write_timeout: 1.5) do |http|
      res = http.get(uri.request_uri)
      res.is_a?(Net::HTTPSuccess) ? res.body : nil
    end
  rescue StandardError
    debug("tor_fetch_exit_nodes fail")  # ✅ Pas de variable inutilisée
    nil
  end

  ips = {}
  raw.to_s.each_line do |line|
    next unless line.start_with?("ExitAddress")
    ip = line.split(" ", 2).last.to_s.strip
    ips[ip] = true if IPGuard.valid_format?(ip)
  end

  $cache_mutex.synchronize do
    if ips.any?
      $tor_state = { ts: Time.now, ips: ips }
    elsif $tor_state[:ips].any?
      $tor_state[:ts] = Time.now - 14400 + 900
    end
  end
  
  ips.any? ? ips : $tor_state[:ips]
end

def apple_relay_ip?(ip, geo_info = nil)
  return false unless IPGuard.sanitize(ip)
  geo_info ||= {}
  org = geo_info["org"].to_s.downcase
  asn = geo_info["asn"].to_s.upcase.gsub("AS", "")

  APPLE_RELAY_ASNS.include?(asn) || org.include?("apple-relay") || org.include?("icloud data protection")
end

def tor?(ip)
  return false unless IPGuard.sanitize(ip)
  memoized("tor_check_#{ip}", 1800) do
    tor_fetch_exit_nodes.key?(IPGuard.parse(ip).to_s)
  end
end

def tor_process?(procs = process_snapshot_global)
  # On vérifie directement dans le Set (très rapide)
  procs.include?("tor") || procs.include?("obfs4proxy")
rescue StandardError
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
    rescue StandardError => e
      debug("tor_socks? local check failed (Tor absent ou SOCKS désactivé)")
      false
    end
  end
end

# ==============================================================================
# 6. INFRASTRUCTURE & ANALYSE DE SECURITE RESEAU
# ==============================================================================
def classify_infra(asn, org)
  text = "#{asn} #{org}".downcase
  return :vpn if %w[proton mullvad nordvpn surfshark expressvpn ivpn cyberghost pia private\ internet\ access].any? { |p| text.include?(p) }
  return :cloud if %w[aws amazon gcp google\ cloud azure microsoft oracle\ cloud].any? { |p| text.include?(p) }
  return :hosting if %w[ovh leaseweb m247 contabo digitalocean linode vultr hetzner worldstream scaleway datacenter hosting].any? { |p| text.include?(p) }
  return :isp if %w[orange sfr free bouygues kpn ziggo vodafone proximus t-mobile telecom xs4all freedom internet comcast at&t charter spectrum verizon].any? { |p| text.include?(p) }
  :unknown
end

def resolve_vpn_provider(org, asn, isp, vpn_ctx = nil)
  text = "#{org} #{isp}".downcase

  return "ProtonVPN" if text.include?("proton")
  return "Mullvad" if text.include?("mullvad")

  return "ProtonVPN" if vpn_ctx && vpn_ctx[:proton]

  VPN_PROVIDER_KEYWORDS.each do |keyword, name|
    return name if text.include?(keyword)
  end

  "Fournisseur Inconnu"
end

def connection_type(infra_type, vpn_enabled)
  return "Tunnel VPN" if vpn_enabled
  infra_type == :isp ? "Ligne Directe (ISP)" : "Infrastructure Cloud / Hébergement"
end

def vpn_state(procs = process_snapshot_global)
  @vpn_state_cache ||= { ts: Time.at(0), value: nil }
  now = Time.now.to_i
  return @vpn_state_cache[:value] if @vpn_state_cache[:value] && (now - @vpn_state_cache[:ts] < 8)

  vpn_processes = %w[wireguard wg tailscaled zerotier-one openvpn protonvpn proton ProtonVPN ProtonVPNService]
  proc_active = vpn_processes.any? { |p| procs.any? { |x| x.include?(p.downcase) } }

  scutil_out, _ = Open3.capture2("scutil", "--nwi")
  ifconfig_out, _ = Open3.capture2("ifconfig")
  
  utuns = active_vpn_interfaces
  utun_route = utun_default_route?
  
  interface_active =
    scutil_out.include?("utun") ||
    ifconfig_out.include?("POINTOPOINT") ||
    !utuns.empty? ||
    utun_route

  vpn_active_confirmed = proc_active && interface_active

  proton_wireguard = vpn_active_confirmed && (utun_route || utuns.any? || procs.any? { |x| x.include?("wg") || x.include?("wireguard") })

result = {
  active: vpn_active_confirmed,
  wireguard: vpn_active_confirmed && (procs.include?("wireguard") || procs.include?("wg-quick") || ifconfig_out.include?("wg") && ifconfig_out.include?("POINTOPOINT")),
  tailscale: vpn_active_confirmed && procs.include?("tailscaled"),
  zerotier: vpn_active_confirmed && procs.include?("zerotier-one"),
  proton: vpn_active_confirmed && proton_wireguard_detected?(procs, utuns, scutil_out)
}

  @vpn_state_cache = { ts: now, value: result }
  result
end

def vpn_confidence(vpn_enabled_real, vpn_provider, infra, procs)
  score = 0
  score += 60 if vpn_enabled_real
  score += 35 if vpn_provider != "Fournisseur Inconnu"

  case infra
  when :vpn then score += 20
  when :hosting then score += 5
  when :cloud then score += 2
  end

  score = 100 if vpn_enabled_real && procs.include?("tailscaled")
  score = [score, 95].max if vpn_enabled_real && procs.include?("zerotier-one")
  [score, 100].min
end

def generate_security_score_v2(public_ip, dns_health, dns_status, tor_active, vpn_active, dns_encrypted, vpn_confidence, infra_type, country_code)
  unless IPGuard.sanitize(public_ip)
    score = 50
    score += 20 if dns_encrypted
    score -= 30 if dns_health[:leak]
    return [[score, 0].max, 100].min
  end

  score = 70
  score -= 20 if tor_active
  score += 10 if dns_encrypted
  score -= 15 if dns_health[:leak]
  score += 8  if vpn_active
  score += 6  if vpn_confidence >= 80
  score += 5  if vpn_confidence >= 50

  if DENY_COUNTRIES.include?(country_code)
    score -= 30
  elsif ALLOWED_COUNTRIES.include?(country_code)
    score += 5
  end

  case dns_status
  when :dns_secure then score += 5
  when :dns_uncertain then score -= 5
  when :dns_leak then score -= 25
  end

  case infra_type
  when :vpn     then score += 5
  when :hosting then score += 2
  when :cloud   then score -= 10
  end

  [[score, 0].max, 100].min
end

def network_fingerprint(ip, geo_data)
  Digest::SHA256.hexdigest([ip, geo_data["asn"], geo_data["org"]].join("|"))[0..14]
end

def fingerprint_changed?(fp)
  path = File.join(DiskCache::CACHE_DIR, "last_fp")
  old = File.exist?(path) ? File.read(path).strip : nil
  File.write(path, fp)
  old && old != fp
end

def vpn_rotation(current_ip, geo)
  path = File.join(DiskCache::CACHE_DIR, "vpn_rotation.json")
  old = File.exist?(path) ? JSON.parse(File.read(path)) : {}

  current = { ip: current_ip, asn: geo["asn"], country: geo["country_code"] }
  File.write(path, JSON.generate(current))
  return nil if old.empty?
  changed = old["ip"] != current[:ip] || old["asn"] != current[:asn] || old["country"] != current[:country]
  changed ? { old_country: old["country"], new_country: current[:country], old_asn: old["asn"], new_asn: current[:asn] } : nil
rescue StandardError
  nil
end

def killswitch_broken?(vpn_active, infra_type)
  return false unless vpn_active
  iface = active_default_interface
  if iface && !iface.start_with?("utun") && !iface.start_with?("wg")
    # Vérifier aussi les routes IPv6 (si disponible)
    begin
      ipv6_route, _ = Open3.capture2("route", "-n", "get", "-6", "default")
      return true if ipv6_route.include?("interface: #{iface}")
    rescue StandardError
      # Ignore si la commande échoue (macOS ancien)
    end
  end
  false
end

# ==============================================================================
# 7. COUCHE SYSTEM DNS & HEALTH ANALYSIS
# ==============================================================================
def system_dns
  # Suppression du DiskCache lourd au profit d'une exécution directe.
  # La méthode globale global_network_context applique déjà un memoized de 10s en RAM.
  stdout, status = Open3.capture2("scutil", "--dns")
  return system_dns_fallback unless status.success?
  
  dns_list = stdout.scan(/nameserver\[\d+\]\s*:\s*([0-9a-fA-F:\.]+)/i).flatten.uniq.select { |ip|
    IPGuard.valid_format?(ip)
  }
  
  dns_list.empty? ? system_dns_fallback : dns_list
rescue StandardError => e
  debug("system_dns extraction failed: #{e.message}")
  []
end

def system_dns_fallback
  stdout, _ = Open3.capture2("networksetup", "-getdnsservers", "Wi-Fi")
  stdout.lines.map(&:strip).select { |x| IPGuard.valid_format?(x) }
rescue
  []
end

def doh_detect(domain = "cloudflare.com")
  memoized("doh_#{domain}", 60) do
    begin
      uri = URI("https://cloudflare-dns.com/dns-query?name=#{domain}&type=A")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      # Définition stricte des timeouts sur la connexion
      http.open_timeout = 0.5
      http.read_timeout = 0.8
      http.write_timeout = 0.5

      req = Net::HTTP::Get.new(uri)
      req["accept"] = "application/dns-json"
      
      res = http.request(req)
      res.is_a?(Net::HTTPSuccess) ? JSON.parse(res.body)["Status"] == 0 : false
    rescue StandardError => e
      debug("doh_detect error: #{e.message}")
      false
    end
  end
end

def normalize_dns_pack(dns_list, vpn_active)
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

def dns_consistency(vpn_detected, local_dns, vpn_dns, public_dns)
  # Si aucun VPN n'est détecté, il est normal d'utiliser des résolveurs publics ou locaux
  return "🟢 Cohérent (Réseau Standard)" unless vpn_detected

  has_vpn_dns = vpn_dns.any?
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

def dns_health_check(public_dns, vpn_dns, vpn_active, current_ip_geo = nil)
  public_dns ||= []
  vpn_dns ||= []

  all_dns = public_dns + vpn_dns
  all_dns += system_dns.select { |ip| ip.include?(":") } # IPv6

  doh_active = doh_detect

  encryption_active = vpn_dns.any? || public_dns.include?("127.0.0.1") || public_dns.include?("::1") || doh_active
  leak = false
  leak_reasons = []

  if vpn_active
    public_dns.each do |dns_ip|
      next if TRUSTED_DNS.include?(dns_ip)
      dns_geo = geo_with_ip_cache(dns_ip)
      next unless dns_geo

      dns_asn = dns_geo["asn"].to_s.upcase.gsub("AS", "")
      vpn_asn = current_ip_geo&.dig("asn").to_s.upcase.gsub("AS", "")

      next if dns_asn.empty? || dns_asn == "0"
      next if KNOWN_SAFE_DNS_ASNS.include?(dns_asn)
      next if !vpn_asn.empty? && dns_asn == vpn_asn

      leak = true
      leak_reasons << { dns: dns_ip, dns_asn: dns_asn, vpn_asn: vpn_asn }
    end

    if vpn_dns.empty? && public_dns.any? && leak_reasons.empty?
      leak = true
    end
  end

  status = if leak
             :dns_leak
           elsif encryption_active
             :dns_secure
           else
             :dns_uncertain
           end

  {
    leak: leak,
    encryption: encryption_active,
    isolation: vpn_active ? !leak : encryption_active,
    status: status,
    leak_reasons: leak_reasons
  }
end

def measure_network_perf
  target = PING_HOSTS.first || "1.1.1.1"
  samples = []
  10.times do
    start = Time.now
    success = Socket.tcp(target, 53, connect_timeout: 0.25) { true } rescue false
    samples << ((Time.now - start) * 1000).round if success
    sleep(0.01)
  end
  return { latency: 999, jitter: 0 } if samples.empty?
  avg = (samples.sum / samples.size.to_f).round
  diffs = samples.each_cons(2).map { |a, b| (a - b).abs }
  { latency: avg, jitter: diffs.empty? ? 0 : (diffs.sum / diffs.size.to_f).round }
end

# ==============================================================================
# 8. TRUE LAZY PROXY PATTERN
# ==============================================================================
class RealLazyCtx
  def initialize(&block)
    @block = block
    @evaluated_data = nil
    @eval_mutex = Mutex.new
  end

  def [](key)
    @eval_mutex.synchronize { @evaluated_data ||= @block.call }
    @evaluated_data[key]
  end

  def get(key)
    self[key]
  end
end

def build_ctx_lazy(raw)
  RealLazyCtx.new do
    dns_split = raw[:dns_split]
    dns_health = raw[:dns_health]
    infra_source = "#{raw.dig(:geo, "org")} #{raw.dig(:geo, "isp")} #{raw.dig(:geo, "asn_org")}".downcase.strip
    infra_type = classify_infra(raw.dig(:geo, "asn"), infra_source)
    country_code = raw.dig(:geo, "country_code")

    {
      ip: raw[:ip],
      isp: raw.dig(:geo, "isp") || raw.dig(:geo, "org") || raw.dig(:geo, "asn_org"),
      network_type: infra_type,
      connection_type: connection_type(infra_type, raw[:vpn_enabled_real]),
      country: country_code,
      vpn: raw[:vpn_detected],
      vpn_suspected: raw[:vpn_suspected],
      vpn_confidence: raw[:vpn_confidence_score],
      vpn_provider: raw[:vpn_provider],
      vpn_enabled: raw[:vpn_enabled_real],
      apple_relay: raw[:apple_relay_detected],
      tor: raw[:tor_exit],
      tor_process: raw[:tor_proc],
      tor_socks: raw[:tor_socks_status],
      wireguard: raw[:wireguard_on],
      tailscale: raw[:tailscale_on],
      zerotier: raw[:zerotier_on],
      dns_leak: dns_health[:leak],
      dns_encrypted: dns_health[:encryption],
      dns_status: dns_health[:status],
      dns_local: raw[:dns_local],
      dns_vpn: raw[:dns_vpn],
      dns_public: raw[:dns_public],
      dns_isolation: raw[:dns_isolation],
      latency: raw[:lat],
      jitter: raw[:jit],
      fingerprint: network_fingerprint(raw[:ip], raw[:geo] || {}),
      score: generate_security_score_v2(
        raw[:ip], dns_health, dns_health[:status], raw[:tor_exit],
        raw[:vpn_enabled_real], dns_health[:encryption], raw[:vpn_confidence_score], infra_type, country_code
      ),
      dns_consistency: dns_consistency(raw[:vpn_enabled_real], dns_split[:local], dns_split[:vpn], dns_split[:public])
    }
  end
end

# ==============================================================================
# 9. ENGINE EXECUTION MAIN BLOCK
# ==============================================================================
def main
  STDOUT.set_encoding('utf-8') if STDOUT.respond_to?(:set_encoding)
  ctx_net = global_network_context

  clean_public_ip   = ctx_net[:ip]
  geo_info          = ctx_net[:geo] || local_geo_fallback(nil)
  active_dns        = ctx_net[:dns]
  perf              = ctx_net[:perf]
  vpn_ctx           = ctx_net[:vpn_state]
  procs             = ctx_net[:procs]
  tor_proc          = tor_process?
  tor_socks_status  = tor_socks?

  local_ip = fallback_local_ip
  current_ip = (clean_public_ip || local_ip).to_s.strip
  tor_exit = current_ip ? tor?(current_ip) : false

  $runtime_ctx[:using_public_ip] = !!clean_public_ip
  $runtime_ctx[:fallback_used]   = clean_public_ip.nil? && !local_ip.nil?
  asn = geo_info["asn"].to_s
  org = geo_info["org"].to_s
  isp = geo_info["isp"].to_s
  infra_source = "#{org} #{isp} #{geo_info["asn_org"]}".downcase.strip
  infra_type = classify_infra(asn, infra_source)
  datacenter_proxy = (infra_type == :hosting)

  vpn_enabled_real = vpn_ctx[:active]
  
  confidence = vpn_confidence(vpn_enabled_real, resolve_vpn_provider(org, asn, isp), infra_type, procs)
  
  vpn_detected = vpn_enabled_real || (infra_type == :vpn && confidence >= 75)
  vpn_suspected = !vpn_enabled_real && $runtime_ctx[:using_public_ip] && (infra_type == :vpn || confidence >= 60)

  dns_split = normalize_dns_pack(active_dns, vpn_enabled_real)
  
  dns_health = dns_health_check(dns_split[:public], dns_split[:vpn], vpn_enabled_real, geo_info)
  apple_relay_detected = apple_relay_ip?(current_ip, geo_info)

  raw_data = {
    ip:                    current_ip,
    geo:                   geo_info,
    dns_split:             dns_split,
    dns_health:            dns_health,
    dns_local:             dns_split[:local],
    dns_vpn:               dns_split[:vpn],
    dns_public:            dns_split[:public],
    dns_isolation:         dns_health[:isolation],
    vpn_detected:          vpn_detected,
    vpn_suspected:         vpn_suspected,
    vpn_confidence_score:  confidence,
    vpn_enabled_real:      vpn_enabled_real,
    vpn_provider:          resolve_vpn_provider(org, asn, isp, vpn_ctx),
    tor_proc:              tor_proc,
    tor_socks_status:      tor_socks_status,
    tor_exit:              tor_exit,
    lat:                   perf[:latency],
    jit:                   perf[:jitter],
    apple_relay_detected:  apple_relay_detected,
    wireguard_on:          vpn_ctx[:wireguard],
    tailscale_on:          vpn_ctx[:tailscale],
    zerotier_on:           vpn_ctx[:zerotier]
  }

  ctx = build_ctx_lazy(raw_data)
  fp_changed = fingerprint_changed?(ctx.get(:fingerprint))
  killswitch = killswitch_broken?(vpn_enabled_real, infra_type)
  rotation = vpn_enabled_real ? vpn_rotation(current_ip, geo_info) : nil

  if JSON_MODE
    puts JSON.generate({
      software: { name: "xbar-vpn-flag", version: APP_VERSION },
      network: {
        ip: ctx.get(:ip), country: ctx.get(:country), provider: geo_info["asn_org"], asn: geo_info["asn"],
        infrastructure_type: ctx.get(:network_type).to_s.upcase, connection_type: ctx.get(:connection_type),
        latency_ms: ctx.get(:latency), jitter_ms: ctx.get(:jitter), fingerprint: ctx.get(:fingerprint)
      },
      security: {
        vpn_active: ctx.get(:vpn), vpn_suspected: ctx.get(:vpn_suspected), vpn_confidence: ctx.get(:vpn_confidence),
        vpn_enabled_interface: ctx.get(:vpn_enabled), vpn_provider_resolved: ctx.get(:vpn_provider),
        apple_private_relay: ctx.get(:apple_relay), tor_exit_node: ctx.get(:tor), tor_local_process: ctx.get(:tor_process),
        tor_local_socks: ctx.get(:tor_socks), wireguard: ctx.get(:wireguard), tailscale: ctx.get(:tailscale),
        zerotier: ctx.get(:zerotier), score: ctx.get(:score)
      },
      dns: {
        servers: active_dns, leak_detected: ctx.get(:dns_leak), dns_health_check: dns_health,
        encrypted: ctx.get(:dns_encrypted), consistency: ctx.get(:dns_consistency)
      }
    })
  else
    icon = if ctx.get(:tor) || ctx.get(:tor_process) || ctx.get(:tor_socks)
             "🧅" # Niveau d'anonymat maximal ou nœud Tor
           elsif ctx.get(:vpn)
             "🔐" # Tunnel VPN traditionnel sécurisé
           elsif ctx.get(:apple_relay)
             "🍏" # Apple Private Relay (J'utilise la pomme verte pour le côté "sécurisé/natif")
           else
             "🚨" # Trafic direct en clair / Risque
           end
    country_code = geo_info["country_code"]
    flag_emoji = flag(country_code)
    
    menu_color = if DENY_COUNTRIES.include?(country_code)
                   COLOR_ALERT
                 elsif ctx.get(:vpn)
                   COLOR_SECURE
                 else
                   "#ffff00"
                 end

    puts "#{icon} #{flag_emoji} | color=#{menu_color} dropdown=true"
    puts "---"
    puts "VPN Checker #{APP_VERSION} | font=Menlo size=12"
    puts "---"
    puts "IP Publique: #{ctx.get(:ip)}"
    
    if DENY_COUNTRIES.include?(country_code)
      puts "🌍 Pays: #{country_code} #{flag_emoji} ⚠️ [NON CONFORME]"
    elsif ALLOWED_COUNTRIES.include?(country_code)
      puts "🌍 Pays: #{country_code} #{flag_emoji} ✅ [SÉCURISÉ]"
    else
      puts "🌍 Pays: #{country_code} #{flag_emoji}"
    end

    puts "Fournisseur: #{ctx.get(:isp)}"
    puts "Infrastructure: #{ctx.get(:network_type)}"
    puts "Connexion: #{ctx.get(:connection_type)}"
    puts "---"

    tunnels = []
    tunnels << "🛡️ WireGuard" if vpn_ctx[:wireguard]
    tunnels << "🛸 Tailscale" if vpn_ctx[:tailscale]
    tunnels << "🪐 ZeroTier" if vpn_ctx[:zerotier]

    if tunnels.empty?
      puts "🌐 Tunnel (WireGuard, Tailscale, ZeroTier) : Aucun"
      puts "🏢 Hébergement : #{geo_info['org']}" if datacenter_proxy
    else
      puts "🌐 Tunnels : #{tunnels.join(' + ')}"
    end
    puts "---"

    vpn_label = ctx.get(:vpn) ? "Actif" : (ctx.get(:vpn_confidence) >= 70 ? "Suspecté" : "Inactif")

    puts "Sécurité Réseau:"
    puts "• Score Global: #{ctx.get(:score)}%"
    puts "• Statut VPN: #{vpn_label} (Confiance: #{ctx.get(:vpn_confidence)}%)"
    puts "• Fournisseur VPN détecté: #{ctx.get(:vpn_provider)}"
    puts "🚨 Kill Switch FAIL" if killswitch
    puts "• Fuite DNS (Leak): #{ctx.get(:dns_leak) ? '⚠️ OUI' : '🟢 Non'}"
    puts "• DNS Chiffré: #{ctx.get(:dns_encrypted) ? '🟢 Oui' : 'Non'}"
    puts "• Apple Private Relay: #{ctx.get(:apple_relay) ? '🍏 Actif' : 'Inactif'}"

    iso_status = ctx.get(:dns_isolation) ? "safe" : "at risk"
    puts "🛡️ DNS Isolation : #{iso_status}"
    puts "🔄 Consistance : #{ctx.get(:dns_consistency)}"

    tor_status = ctx.get(:tor) ? "🔴 Nœud de sortie actif" : ((ctx.get(:tor_process) || ctx.get(:tor_socks)) ? "🟡 Local actif" : "🟢 Inactif")
    puts "🧅 Tor Network : #{tor_status}"
    puts "---"

    puts "DNS Servers Detected :"
    all_dns_detected = [ctx.get(:dns_local), ctx.get(:dns_vpn), ctx.get(:dns_public)].compact.flatten.uniq

    if all_dns_detected.empty?
      puts "-- Aucun serveur détecté (Système par défaut)"
    else
      grouped_dns = Hash.new { |h, k| h[k] = [] }
      all_dns_detected.each do |dns_ip|
        label = if DNS_PROVIDERS.key?(dns_ip)
                  DNS_PROVIDERS[dns_ip]
                elsif IPGuard.private_ip?(dns_ip) || IPGuard.localhost?(dns_ip)
                  ctx.get(:vpn) ? "🔐 VPN Private DNS" : "🏠 DNS Local / Routeur"
                else
                  "🌐 DNS Public Alternatif"
                end
        grouped_dns[label] << dns_ip
      end
      grouped_dns.each { |label, ips| puts "-- #{label} (#{ips.uniq.join(', ')})" }
    end

    if fp_changed
      puts "---"
      puts "⚠️ Infrastructure modifiée"
    end

    if rotation
      puts "---"
      puts "🔄 Rotation VPN détectée"
      puts "-- #{rotation[:old_country]} → #{rotation[:new_country]}"
      puts "-- AS#{rotation[:old_asn]} → AS#{rotation[:new_asn]}"
    end

    puts "---"
    puts "Performances réseau:"
    puts "• Latence standard: #{ctx.get(:latency)} ms • Jitter: #{ctx.get(:jitter)} ms"
    puts "---"
    puts "Empreinte Réseau (Fingerprint): #{ctx.get(:fingerprint)} | color=#888888"
  end
end

main if __FILE__ == $PROGRAM_NAME
