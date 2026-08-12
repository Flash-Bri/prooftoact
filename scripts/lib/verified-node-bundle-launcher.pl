use strict;
use warnings;

use Cwd qw(abs_path);
use Digest::SHA qw(sha256_hex);
use Fcntl qw(O_RDONLY O_NOFOLLOW SEEK_SET);
use File::Basename qw(dirname);
use JSON::PP qw(decode_json);

sub fail_closed {
  my ($code) = @_;
  print STDERR "$code\n";
  exit 126;
}

my $self_path = abs_path($0);
defined($self_path) or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_LAUNCHER_REJECTED");
my $stage_root = dirname($self_path);
my @stage_stat = lstat($stage_root);
@stage_stat && -d _ && !-l _
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_REJECTED");
$stage_stat[4] == 0 && (($stage_stat[2] & 0022) == 0)
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_REJECTED");
$> != 0
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_PRIVILEGE_REJECTED");

@ARGV >= 2
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_ARGUMENT_REJECTED");
my ($component_name, $manifest_sha256, @component_args) = @ARGV;
$component_name =~ /\A(?:orchestrator|dvi|authority-race|recovery|supervisor|worker|finalizer)\z/
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_REJECTED");
$manifest_sha256 =~ /\A[0-9a-f]{64}\z/
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED");
defined($ENV{TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256})
  && $ENV{TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256} eq
    $manifest_sha256
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED");

for my $name (keys %ENV) {
  $name !~ /\A(?:NODE_OPTIONS|NODE_PATH|LD_PRELOAD|DYLD_.*|PERL5OPT|PERL5LIB|PERLLIB|PERL_LOCAL_LIB_ROOT)\z/
    or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_ENVIRONMENT_REJECTED");
}

my $manifest_name = "runtime-manifest-$manifest_sha256.json";
my $manifest_path = "$stage_root/$manifest_name";
sysopen(my $manifest_fh, $manifest_path, O_RDONLY | O_NOFOLLOW)
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED");
my @manifest_stat = stat($manifest_fh);
@manifest_stat && -f _ && !-l _ && $manifest_stat[3] == 1
  && $manifest_stat[4] == 0 && (($manifest_stat[2] & 0022) == 0)
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED");
local $/;
my $manifest_bytes = <$manifest_fh>;
defined($manifest_bytes) && sha256_hex($manifest_bytes) eq $manifest_sha256
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED");
my $manifest = eval { decode_json($manifest_bytes) };
$@ eq "" && ref($manifest) eq "HASH"
  && ($manifest->{schemaVersion} // "") eq
    "tideproof.integrated-live-drill-runtime-manifest.v1"
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED");

my $components = $manifest->{components};
ref($components) eq "HASH"
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED");
my $component = $components->{$component_name};
ref($component) eq "HASH"
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_REJECTED");
my $bundle_name = $component->{file} // "";
my $bundle_sha256 = $component->{sha256} // "";
$bundle_name =~ /\A$component_name-[0-9a-f]{64}\.mjs\z/
  && $bundle_sha256 =~ /\A[0-9a-f]{64}\z/
  && $bundle_name eq "$component_name-$bundle_sha256.mjs"
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_REJECTED");

my $node = $manifest->{node};
ref($node) eq "HASH"
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_NODE_REJECTED");
my $node_name = $node->{file} // "";
my $node_sha256 = $node->{sha256} // "";
$node_name =~ /\Anode-[0-9a-f]{64}\z/
  && $node_sha256 =~ /\A[0-9a-f]{64}\z/
  && $node_name eq "node-$node_sha256"
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_NODE_REJECTED");

sub open_root_owned_exact_file {
  my ($path, $expected_sha256, $code) = @_;
  sysopen(my $fh, $path, O_RDONLY | O_NOFOLLOW) or fail_closed($code);
  my @file_stat = stat($fh);
  @file_stat && -f _ && !-l _ && $file_stat[3] == 1
    && $file_stat[4] == 0 && (($file_stat[2] & 0022) == 0)
    or fail_closed($code);
  my $digest = Digest::SHA->new(256);
  $digest->addfile($fh);
  $digest->hexdigest eq $expected_sha256 or fail_closed($code);
  seek($fh, 0, SEEK_SET) or fail_closed($code);
  return $fh;
}

my $bundle_fh = open_root_owned_exact_file(
  "$stage_root/$bundle_name",
  $bundle_sha256,
  "INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_REJECTED"
);
my $node_fh = open_root_owned_exact_file(
  "$stage_root/$node_name",
  $node_sha256,
  "INTEGRATED_LIVE_DRILL_RUNTIME_NODE_REJECTED"
);
close($node_fh)
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_NODE_REJECTED");

open(STDIN, "<&", fileno($bundle_fh))
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_REJECTED");
close($bundle_fh)
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_REJECTED");

$ENV{TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT} = $component_name;
$ENV{TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256} =
  $bundle_sha256;
exec {
  "$stage_root/$node_name"
} "$stage_root/$node_name", "--disable-proto=throw", "--input-type=module", "-",
  @component_args
  or fail_closed("INTEGRATED_LIVE_DRILL_RUNTIME_EXEC_REJECTED");
