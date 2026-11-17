#!/usr/bin/ruby
# Reviewed local installer, executed ONLY when the guest user opens Install.command.
# Never source/eval downloaded scripts. Never print config, subprocess stderr or passwords.
require 'json'
require 'digest'
require 'fileutils'
require 'tmpdir'
require 'open3'
require 'rexml/document'

SETUP = '/Volumes/My Shared Files/setup'.freeze
ROOT = '/Library/Application Support/GoldVMSetup'.freeze
PLIST = '/Library/LaunchDaemons/local.goldvm.proxy.plist'.freeze
CCBAGA = 'CCBaga-0.2.50-macos-arm64.dmg'.freeze
CCBAGA_SHA = '0df33d29d1ac2dd9c912a65fb8ec7657ec497c2c17da1ee9ae94351ab38a8e0b'.freeze
MIHOMO_SHA = '94c6fe434317ae5c00c6bc3dd6761fe0734edbd78ae205910108be186b0d968c'.freeze
CLAUDE_ORIGIN = 'https://downloads.claude.ai/claude-code-releases'.freeze

class SetupError < StandardError; end

def fail_setup(message)
  raise SetupError, message
end

def capture(*argv)
  out, _err, status = Open3.capture3(*argv)
  fail_setup('A setup step failed. No credentials or command output have been logged.') unless status.success?
  out
end

def check_digest(path, expected)
  fail_setup('Package digest verification failed.') unless File.file?(path) && !File.symlink?(path) && Digest::SHA256.file(path).hexdigest == expected
end

def require_absent(path)
  fail_setup('An install destination already exists; this fresh-only installer will not overwrite it.') if File.exist?(path) || File.symlink?(path)
end

def reject_symlink_parents(path)
  current = '/'
  path.split('/').reject(&:empty?).each do |part|
    current = File.join(current, part)
    fail_setup('A destination contains a symbolic link.') if File.symlink?(current)
  end
end

def confirm(message, token)
  puts message
  print "Type #{token} to continue (anything else cancels): "
  STDOUT.flush
  STDIN.gets.to_s.strip == token
end

def download(url, destination, limit)
  # Explicit loopback proxy, no direct retry and no remote redirect following.
  # Proxy DNS is remote; host fence independently denies every non-node tuple.
  capture('/usr/bin/curl', '--fail', '--silent', '--show-error', '--proto', '=https',
          '--connect-timeout', '20', '--max-time', '300', '--max-filesize', limit.to_s,
          '--proxy', 'http://127.0.0.1:7890', '--noproxy', '', '-o', destination, url)
end

def apply_selected_profile
  path = File.join(SETUP, 'profile.json')
  return {'template_present' => false} unless File.file?(path)
  fail_setup('Unsafe initialization template.') if File.symlink?(path) || File.size(path) > 16384
  profile = JSON.parse(File.read(path))
  languages = {'en-US'=>'en', 'en-GB'=>'en', 'zh-Hans'=>'zh_Hans', 'zh-Hant'=>'zh_Hant', 'ja'=>'ja', 'de'=>'de', 'fr'=>'fr'}
  countries = %w[US GB JP SG DE CA AU FR NL HK]
  zones = %w[America/Los_Angeles America/New_York America/Chicago America/Toronto America/Vancouver Europe/London Europe/Berlin Europe/Paris Europe/Amsterdam Asia/Tokyo Asia/Singapore Asia/Hong_Kong Australia/Sydney Australia/Perth Etc/UTC]
  fail_setup('Unsupported initialization template.') unless profile.is_a?(Hash) && profile['version'] == 1 && languages.key?(profile['language']) && countries.include?(profile['country']) && zones.include?(profile['timezone'])
  # This is guest-side, after explicit local sudo authorization; no password in argv.
  capture('/usr/bin/sudo', '-n', '/usr/sbin/systemsetup', '-settimezone', profile['timezone'])
  actual = capture('/usr/bin/sudo', '-n', '/usr/sbin/systemsetup', '-gettimezone').split(':', 2).last.to_s.strip
  utc_aliases = %w[Etc/UTC UTC Etc/GMT GMT]
  fail_setup('Selected guest timezone did not apply; no ready claim.') unless actual == profile['timezone'] || (utc_aliases.include?(actual) && profile['timezone'] == 'Etc/UTC')
  capture('/usr/bin/defaults', 'write', '-g', 'AppleLanguages', '-array', profile['language'])
  capture('/usr/bin/defaults', 'write', '-g', 'AppleLocale', '-string', languages.fetch(profile['language']) + '_' + profile['country'])
  puts 'Guest timezone verified. Language/region preference written; logout may be required. Location Services was NOT changed by private-database edits; verify it in the guest UI.'
  {'template_present'=>true, 'timezone_verified'=>true, 'language_region_written'=>true,
   'location_services_verified'=>false, 'logout_may_be_required'=>true}
end


def install_claude(work)
  return false unless confirm('Optional: download the official native Claude Code binary through the protected proxy, verify release SHA-256 and Apple code signature, then copy to ~/.local/bin/claude. No host credentials or remote install scripts are used.', 'CLAUDE')
  version_file = File.join(work, 'claude-version')
  download(CLAUDE_ORIGIN + '/stable', version_file, 128)
  version = File.read(version_file).strip
  fail_setup('Invalid official Claude release version.') unless /\A[0-9]+\.[0-9]+\.[0-9]+\z/.match?(version)
  manifest_file = File.join(work, 'claude-manifest.json')
  download(CLAUDE_ORIGIN + '/' + version + '/manifest.json', manifest_file, 1024 * 1024)
  manifest = JSON.parse(File.read(manifest_file))
  checksum = manifest.fetch('platforms').fetch('darwin-arm64').fetch('checksum')
  fail_setup('Invalid official Claude checksum.') unless checksum.is_a?(String) && /\A[0-9a-f]{64}\z/.match?(checksum)
  binary = File.join(work, 'claude')
  download(CLAUDE_ORIGIN + '/' + version + '/darwin-arm64/claude', binary, 512 * 1024 * 1024)
  check_digest(binary, checksum)
  File.chmod(0700, binary)
  # Apple-issued Developer ID with the official documented legal organization;
  # reject unsigned/ad-hoc/unrelated developer binaries even if digest matches.
  capture('/usr/bin/codesign', '--verify', '--strict', '-R',
          '=anchor apple generic and certificate leaf[subject.O] = "Anthropic PBC"', binary)
  bin_dir = File.join(Dir.home, '.local', 'bin')
  reject_symlink_parents(bin_dir)
  target = File.join(bin_dir, 'claude')
  require_absent(target)
  FileUtils.mkdir_p(bin_dir, mode: 0700)
  FileUtils.copy_file(binary, target)
  File.chmod(0700, target)
  puts 'Claude native binary installed. Run ~/.local/bin/claude and log in yourself. Shell startup files were not modified.'
  true
end

begin
  File.umask(0077)
  fail_setup('Only the optional --claude-only argument is supported.') unless ARGV.empty? || ARGV == ['--claude-only']
  fail_setup('Run only from the setup shared folder inside the new VM.') unless File.expand_path(__dir__) == SETUP && Process.uid != 0
  # This guard deliberately refuses a host/manual run, even if the host happens
  # to mount a folder at the same path. Availability differs by macOS release:
  # missing virtualization indicator fails closed rather than guessing.
  virtualized = capture('/usr/sbin/sysctl', '-n', 'kern.hv_vmm_present').strip
  fail_setup('This installer requires a virtualized macOS guest.') unless virtualized == '1'
  fail_setup('Only Apple Silicon guests are supported.') unless capture('/usr/bin/uname', '-m').strip == 'arm64'
  check_digest(File.join(SETUP, CCBAGA), CCBAGA_SHA)
  check_digest(File.join(SETUP, 'mihomo'), MIHOMO_SHA)
  capture('/usr/bin/codesign', '--verify', '--strict', '-R',
          '=anchor apple generic and certificate leaf[subject.OU] = "JPH3Z7PPBB"', File.join(SETUP, 'mihomo'))
  if ARGV == ['--claude-only']
    work = Dir.mktmpdir('GoldVMSetup-Claude-')
    File.chmod(0700, work)
    install_claude(work)
    puts 'Claude-only attempt finished; service and CCBaga were not changed. Manager status remains awaiting_user_setup.'
    puts "Private staging retained at: #{work}"
    exit 0
  end
  [ROOT, PLIST, '/Applications/CCBaga-A.app', '/Applications/CCBaga-B.app'].each do |path|
    reject_symlink_parents(path)
    require_absent(path)
  end
  unless confirm('This fresh guest setup installs a root-owned Clash/Mihomo TUN service and official CCBaga 0.2.50 A+B applications. The service starts on boot; the host endpoint fence remains mandatory. Your macOS admin authorization is requested by sudo, never stored. Finish macOS setup/login first. This does NOT migrate accounts or authenticate Claude.', 'INSTALL')
    puts 'Cancelled without installation.'
    exit 0
  end
  work = Dir.mktmpdir('GoldVMSetup-')
  File.chmod(0700, work)
  config = File.join(work, 'config.json')
  FileUtils.copy_file(File.join(SETUP, 'config.json'), config)
  File.chmod(0600, config)
  # Validate silently. Do not log a parser error that might include proxy secrets.
  capture(File.join(SETUP, 'mihomo'), '-t', '-d', work, '-f', config)
  # sudo communicates with the terminal itself; no password appears in argv,
  # environment, files, stdout captures, or manager logs.
  fail_setup('Administrator authorization was declined.') unless system('/usr/bin/sudo', '-v')
  selected_profile = apply_selected_profile
  capture('/usr/bin/sudo', '-n', '/bin/mkdir', ROOT)
  capture('/usr/bin/sudo', '-n', '/bin/chmod', '700', ROOT)
  capture('/usr/bin/sudo', '-n', '/usr/bin/install', '-m', '700', '-o', 'root', '-g', 'wheel', File.join(SETUP, 'mihomo'), File.join(ROOT, 'mihomo'))
  capture('/usr/bin/sudo', '-n', '/usr/bin/install', '-m', '600', '-o', 'root', '-g', 'wheel', config, File.join(ROOT, 'config.json'))
  plist = File.join(work, 'local.goldvm.proxy.plist')
  xml = <<~XML
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
      <key>Label</key><string>local.goldvm.proxy</string>
      <key>ProgramArguments</key><array>
        <string>#{ROOT}/mihomo</string><string>-d</string><string>#{ROOT}</string>
        <string>-f</string><string>#{ROOT}/config.json</string>
      </array>
      <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
      <key>Umask</key><integer>63</integer>
      <key>StandardOutPath</key><string>/dev/null</string>
      <key>StandardErrorPath</key><string>/dev/null</string>
    </dict></plist>
  XML
  File.write(plist, xml)
  capture('/usr/bin/plutil', '-lint', plist)
  capture('/usr/bin/sudo', '-n', '/usr/bin/install', '-m', '644', '-o', 'root', '-g', 'wheel', plist, PLIST)
  capture('/usr/bin/sudo', '-n', '/bin/launchctl', 'bootstrap', 'system', PLIST)
  mount = File.join(work, 'ccbaga-volume')
  Dir.mkdir(mount, 0700)
  mounted = false
  begin
    capture('/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-noautoopen', '-mountpoint', mount, File.join(SETUP, CCBAGA))
    mounted = true
    ['CCBaga-A.app', 'CCBaga-B.app'].each do |app|
      source = File.join(mount, app)
      fail_setup('Official DMG application layout differs; manual review required.') unless File.directory?(source) && !File.symlink?(source)
      capture('/usr/bin/sudo', '-n', '/usr/bin/ditto', source, File.join('/Applications', app))
    end
  ensure
    # Detach only the exact mountpoint created above; never broad unmount/cleanup.
    capture('/usr/bin/hdiutil', 'detach', mount) if mounted
  end
  puts 'Clash service and CCBaga A+B copied. Gatekeeper remains enabled; no signature or quarantine bypass was performed.'
  claude = install_claude(work)
  receipt = File.join(work, 'result.json')
  File.write(receipt, JSON.generate({'clash_service_started' => true, 'ccbaga_copied' => true,
                                    'claude_binary_installed' => claude, 'guest_network_verified' => false,
                                     'initialization_profile' => selected_profile}))
  File.chmod(0600, receipt)
  puts 'Setup finished locally. Verify proxy connectivity and open the apps manually. The manager still shows awaiting_user_setup: it cannot infer completion from this read-only share. Private staging is retained for manual cleanup; it contains proxy credentials. Do not share it.'
  puts "Private staging retained at: #{work}"
rescue SetupError => error
  warn error.message
  warn 'Setup may be partial. Do not bypass the host fence or retry with direct NAT. No automatic rollback or VM operation is performed.'
  warn 'If ONLY Claude failed, retry in the guest: /bin/bash "/Volumes/My Shared Files/setup/Install.command" --claude-only'
  warn "Private staging retained at: #{work}" if defined?(work) && work
  exit 1
rescue StandardError
  warn 'Setup failed safely. Details are suppressed to avoid exposing credentials. Private partial installation/staging may remain.'
  warn 'If ONLY Claude failed, retry in the guest: /bin/bash "/Volumes/My Shared Files/setup/Install.command" --claude-only'
  warn "Private staging retained at: #{work}" if defined?(work) && work
  exit 1
end
