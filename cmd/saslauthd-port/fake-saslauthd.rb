#!/usr/bin/env ruby

require 'socket'
require 'fileutils'
require 'optparse'

$sockpath = ENV['CBAUTH_SOCKPATH'] || '/var/run/saslauthd/mux'
$ready_signal_fd = nil
$watch_stdin = false
$verbose = true
if ENV['READY_SIGNAL_FD']
  $ready_signal_fd = ENV['READY_SIGNAL_FD'].to_i
end

OptionParser.new do |o|
  o.on("--watch-stdin") do
    $watch_stdin = true
  end
  o.on("--path PATH") do |path|
    $sockpath = path
  end
  o.on("--[no-]verbose") do |v|
    $verbose = v
  end
  o.on("--ready-signal-fd FD", Integer) do |fd|
    $ready_signal_fd = fd
  end
end.parse!

def read_string(s)
  l = s.read(2)
  return unless l
  len = l.unpack("n")[0]
  s.read(len)
end

def send_string(sock, string)
  sock.write([string.bytesize].pack("n") + string)
end

def minilog(msg)
  return unless $verbose
  str = "#{Time.now} #{Thread.current}: #{msg}"
  if str[-1] != "\n"
    str << "\n"
  end
  STDERR.print str
end

minilog "starting on #{$sockpath}"

def fake_check_creds(user, pwd)
  if user != "alk" && user[0,3] == "alk"
    return false
  end
  return pwd == "AsdQwe!23"
end

def handle_socket(sock)
  while true
    user = read_string(sock)
    return unless user
    pwd = read_string(sock)
    service = read_string(sock)
    realm = read_string(sock)

    ok = fake_check_creds(user, pwd)
    res = ok ? "OK" : "NO didn't work"

    minilog "Req: u:'#{user}' pwd:'#{pwd}' svc:'#{service}' realm:'#{realm}' -> #{res}"

    send_string(sock, res)
  end
rescue Exception => exc
  minilog "Got exception: #{exc}\n#{exc.backtrace.join("\n")}\n"
ensure
  begin
    minilog "Closing connection\n"
    sock.close
  rescue Exception
    # ignore
  end
end

FileUtils.mkdir_p(File.dirname($sockpath))

%w(INT HUP TERM).each do |sig|
  Signal.trap sig do
    puts "SIG: #{sig}"
    STDOUT.flush
    Process.exit!(0)
  end
end

if $watch_stdin
  Thread.new do
    while STDIN.gets
    end
    puts "EOF on STDIN!"
    STDOUT.flush
    Process.exit!(0)
  end
end

def handle_client_sock(sock, client_addr)
  Thread.new do
    minilog "Got connection!"
    handle_socket(sock)
  end
end

Socket.unix_server_socket($sockpath) do |lsock|
  if $ready_signal_fd
    (IO.for_fd($ready_signal_fd, "w") << "ready!: #{$sockpath}\n").close()
  end
  while true
    sock, client_addr = lsock.accept()
    handle_client_sock(sock, client_addr)
  end
end
