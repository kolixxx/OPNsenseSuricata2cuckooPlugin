#!/usr/bin/env perl
#
# suricata2cuckoo.pl — daemon that watches Suricata filestore and submits
# new files to Cuckoo Sandbox via REST API.
#
# This file is vendored by the OPNsense Suricata2Cuckoo plugin.
#

use strict;
use warnings;
use Cwd qw(abs_path);
use File::Basename qw(dirname);
use Sys::Syslog;
use LWP::UserAgent;
use HTTP::Request::Common qw(POST);
use XML::XPath;
use Getopt::Long;

my $HAS_KQUEUE = 0;
my $EVFILT_VNODE = 4; # FreeBSD
my $NOTE_WRITE = 2;
my $EV_ADD = 0x1;
my $EV_CLEAR = 0x20;
eval {
 require IO::KQueue;
 IO::KQueue->import();
 $HAS_KQUEUE = 1;
 $EVFILT_VNODE = IO::KQueue::EVFILT_VNODE() if defined &IO::KQueue::EVFILT_VNODE;
 $NOTE_WRITE = IO::KQueue::NOTE_WRITE() if defined &IO::KQueue::NOTE_WRITE;
 $EV_ADD = IO::KQueue::EV_ADD() if defined &IO::KQueue::EV_ADD;
 $EV_CLEAR = IO::KQueue::EV_CLEAR() if defined &IO::KQueue::EV_CLEAR;
};
eval { require File::LibMagic; };
my $HAS_LIBMAGIC = !$@;

my $CONFIG_FILE = dirname(abs_path($0)) . "/suricata2cuckoo.conf";
my $FilestorePath = "/var/log/suricata/filestore";
my $WatchMethod = "kqueue"; # kqueue | polling
my $PollInterval = 5;
my $SettleTime = 2;
my $CuckooApiUrl = "http://127.0.0.1:8090";
my $CuckooApiToken = "";
my $CuckooVM = "Cuckoo1";
my $SyslogFacility = "daemon";
my $SyslogProgram = "suricata2cuckoo";

my %Submitted;
my %Pending;
my $SkipInitialFiles = 1;

sub read_config {
 my $path = shift;
 return 0 unless $path && -r $path;
 my $xml = XML::XPath->new(filename => $path);
 my $v;

 $v = $xml->findvalue('/cuckoomx/filestore/path');
 $FilestorePath = $v if defined $v && $v ne "";

 $v = $xml->findvalue('/cuckoomx/filestore/watch-method');
 $WatchMethod = lc($v) if defined $v && $v ne "";

 $v = $xml->findvalue('/cuckoomx/filestore/poll-interval');
 $PollInterval = int($v) if defined $v && $v ne "" && $v =~ /^\d+$/;
 $PollInterval = 5 if $PollInterval < 1;

 $v = $xml->findvalue('/cuckoomx/filestore/file-settle-time');
 $SettleTime = int($v) if defined $v && $v ne "" && $v =~ /^\d+$/;
 $SettleTime = 1 if $SettleTime < 0;

 $v = $xml->findvalue('/cuckoomx/cuckoo/api-url');
 $CuckooApiUrl = $v if defined $v && $v ne "";

 $v = $xml->findvalue('/cuckoomx/cuckoo/api-token');
 $CuckooApiToken = $v if defined $v;

 $v = $xml->findvalue('/cuckoomx/cuckoo/guest');
 $CuckooVM = $v if defined $v && $v ne "";

 $v = $xml->findvalue('/cuckoomx/logging/syslogfacility');
 $SyslogFacility = $v if defined $v && $v ne "";

 return 1;
}

sub logmsg {
 my $msg = shift or return;
 openlog($SyslogProgram, 'pid', $SyslogFacility);
 syslog('info', '%s', $msg);
 closelog();
}

sub get_package {
 my $path = shift || return "exe";
 return "exe" unless $HAS_LIBMAGIC;
 my $flm = File::LibMagic->new();
 my $desc = $flm->describe_filename($path) || "";
 if ($desc =~ /Microsoft [Office ]*PowerPoint/i) { return "ppt"; }
 if ($desc =~ /Microsoft [Office ]*Excel/i) { return "xls"; }
 if ($desc =~ /Microsoft [Office ]*Word/i ||
     $desc =~ /Composite Document File V\\d Document/i ||
     $desc =~ /Rich Text Format/i) { return "doc"; }
 if ($desc =~ /PDF Document/i) { return "pdf"; }
 if ($desc =~ /HTML document/i) { return "firefox"; }
 if ($desc =~ /PHP script/i) { return "php"; }
 return "exe";
}

sub get_submit_filename {
 my $package = shift || "exe";
 my %ext = (
  exe => "sample.exe",
  dll => "sample.dll",
  doc => "sample.doc",
  xls => "sample.xls",
  ppt => "sample.ppt",
  pdf => "sample.pdf",
  firefox => "sample.html",
  php => "sample.php",
 );
 return $ext{$package} || "sample.exe";
}

sub submit_file {
 my $file = shift || return;
 return unless -f $file && -r $file;

 my $package = get_package($file);
 my $submit_name = get_submit_filename($package);
 my $ua = LWP::UserAgent->new();
 my $url = $CuckooApiUrl . "/tasks/create/file";
 $url =~ s/\/+$//;

 logmsg("Submitting $file as $submit_name (package=$package) to Cuckoo API");

 my $tmp_dir = $ENV{TMPDIR} || $ENV{TMP} || '/tmp';
 my $tmp_file_path = "$tmp_dir/$submit_name";

 {
  open my $src_fh, '<', $file or do { logmsg("Cannot open source file $file: $!"); return; };
  open my $dst_fh, '>', $tmp_file_path or do { logmsg("Cannot create temp file $tmp_file_path: $!"); close($src_fh); return; };
  binmode($src_fh);
  binmode($dst_fh);
  my $buffer;
  while (read($src_fh, $buffer, 8192)) { print $dst_fh $buffer; }
  close($src_fh);
  close($dst_fh);
 }

 unless (-f $tmp_file_path && -r $tmp_file_path) {
  logmsg("Temporary file $tmp_file_path does not exist or is not readable");
  unlink($tmp_file_path) if -f $tmp_file_path;
  return;
 }

 my $req = POST $url,
  Content_Type => 'form-data',
  Content => [
   file => [ "$tmp_file_path" ],
   package => "$package",
   machine => "$CuckooVM",
  ];
 $req->header('Authorization' => "Bearer $CuckooApiToken") if $CuckooApiToken ne "";

 my $res = $ua->request($req);
 unlink($tmp_file_path) if -f $tmp_file_path;

 if (!$res->is_success) {
  my $err = $res->status_line;
  $err .= " (check api-token)" if $res->code == 401;
  $err .= " (check api-url)" if $res->code == 404;
  logmsg("Cuckoo API failed for $file: $err");
  if ($res->content) { logmsg("API body: " . $res->decoded_content); }
  return;
 }
 logmsg("Cuckoo API OK for $file: " . $res->decoded_content);
}

sub list_filestore_files {
 my $base = shift || return ();
 my @out;
 for my $hex (0x00 .. 0xff) {
  my $sub = sprintf "%02x", $hex;
  my $dir = $base . "/" . $sub;
  next unless -d $dir;
  if (opendir my $dh, $dir) {
   while (defined(my $e = readdir $dh)) {
    next if $e eq "." || $e eq "..";
    my $full = $dir . "/" . $e;
    push @out, $full if -f $full;
   }
   closedir $dh;
  }
 }
 return @out;
}

sub process_new_file {
 my ($path, $now) = @_;
 return if $Submitted{$path};
 if (!$Pending{$path}) { $Pending{$path} = $now; return; }
 if (($now - $Pending{$path}) >= $SettleTime) {
  submit_file($path);
  $Submitted{$path} = 1;
  delete $Pending{$path};
 }
}

sub scan_and_submit {
 my $now = time();
 my @files = list_filestore_files($FilestorePath);
 if ($SkipInitialFiles && !keys %Submitted && !keys %Pending) {
  for my $path (@files) { $Submitted{$path} = 1; }
  $SkipInitialFiles = 0;
  return;
 }
 for my $path (@files) { process_new_file($path, $now); }
 for my $path (keys %Pending) { delete $Pending{$path} unless -f $path; }
}

sub run_kqueue {
 if (!$HAS_KQUEUE) {
  logmsg("IO::KQueue not available, falling back to polling.");
  return run_polling();
 }

 my @dirs;
 for my $hex (0x00 .. 0xff) {
  my $sub = sprintf "%02x", $hex;
  my $dir = $FilestorePath . "/" . $sub;
  push @dirs, $dir if -d $dir;
 }
 if (!@dirs) { logmsg("No filestore subdirs under $FilestorePath, using polling."); return run_polling(); }

 my $kq = IO::KQueue->new() or do { logmsg("kqueue failed: $!"); return run_polling(); };
 my %fd_to_dir;
 my @dir_handles;
 for my $dir (@dirs) {
  open my $fh, "<", $dir or next;
  my $fd = fileno($fh);
  $kq->EV_SET($fd, $EVFILT_VNODE, $EV_ADD | $EV_CLEAR, $NOTE_WRITE, 0, $fh);
  $fd_to_dir{$fd} = $dir;
  push @dir_handles, $fh;
 }

 logmsg("Watching " . scalar(keys %fd_to_dir) . " filestore dirs with kqueue");
 while (1) {
  my $timeout_ms = 1000;
  my @events = $kq->kevent($timeout_ms);
  if (@events) { scan_and_submit(); } else { scan_and_submit(); }
 }
}

sub run_polling {
 logmsg("Watching filestore with polling every ${PollInterval}s");
 while (1) { scan_and_submit(); sleep $PollInterval; }
}

sub daemonize {
 my $pid = fork();
 die "fork: $!" if !defined $pid;
 exit 0 if $pid;
 POSIX::setsid() or die "setsid: $!";
 chdir "/" or die "chdir: $!";
 open STDIN, "<", "/dev/null" or die "reopen STDIN: $!";
 open STDOUT, ">>", "/dev/null" or die "reopen STDOUT: $!";
 open STDERR, ">>", "/dev/null" or die "reopen STDERR: $!";
}

sub main {
 my $no_fork = 0;
 GetOptions("config|c=s" => \$CONFIG_FILE, "no-fork" => \$no_fork) or exit 1;
 if (!read_config($CONFIG_FILE)) { warn "Cannot read config: $CONFIG_FILE\n"; exit 1; }
 if (!-d $FilestorePath) { warn "Filestore path not found: $FilestorePath\n"; exit 1; }
 daemonize() unless $no_fork;
 logmsg("Starting suricata2cuckoo daemon (filestore=$FilestorePath, method=$WatchMethod)");
 if ($WatchMethod eq "kqueue") { run_kqueue(); } else { run_polling(); }
}

eval { require POSIX; POSIX->import(qw(setsid)); };
if ($@) { *daemonize = sub { logmsg("POSIX not available, running in foreground"); }; }

main();

