# Homebrew formula (builds from the source of the release tag). For a tap: copy to
# Formula/network-scope.rb in a repository named homebrew-<tap>.
class NetworkScope < Formula
  desc "Network scanner with service, TLS and passive OT discovery"
  homepage "https://sparkz400.github.io/network-scope/"
  url "https://github.com/Sparkz400/network-scope/archive/refs/tags/v@VERSION@.tar.gz"
  sha256 "@SHA256_SOURCE@"
  license "MIT"
  head "https://github.com/Sparkz400/network-scope.git", branch: "main"

  depends_on "rust" => :build
  # Linux users: the AUR package, the release tar.gz or the container image. The Linux build
  # needs the X11/Wayland development packages, which this formula does not declare yet.
  depends_on :macos

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_equal "network-scope #{version}", shell_output("#{bin}/network-scope-cli --version").strip
    assert_match "network-scope", shell_output("#{bin}/network-scope-cli --help")
  end
end
