class Floo < Formula
  desc "Secure, high-performance tunneling in Zig. Expose your home services or access remote ones"
  homepage "https://github.com/NTETV/floo"
  version "0.1.6"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/NTETV/floo/releases/download/v0.1.6/floo-aarch64-macos.tar.gz"
    sha256 "add1aaca7a6ac190b6960f3a9ca1ea452055a4d8b9d94cf66a3671ad340aaa71"
  else
    url "https://github.com/NTETV/floo/releases/download/v0.1.6/floo-x86_64-macos.tar.gz"
    sha256 "32e7585c6f2bab9248be2f8b82bc2a25df10b725999d23799aabe7f0208a854a"
  end

  def install
    bin.install "flooc"
    bin.install "floos"
    doc.install "README.md"
    (pkgshare/"examples").install "flooc.toml.example"
    (pkgshare/"examples").install "floos.toml.example"
  end

  def caveats
    <<~EOS
      Example configuration files are installed to:
        #{pkgshare}/examples/

      To get started:
        1. Copy example configs: cp #{pkgshare}/examples/*.toml.example .
        2. Edit configs with your settings
        3. Run: flooc flooc.toml (client) or floos floos.toml (server)

      See https://github.com/NTETV/floo for complete documentation.
    EOS
  end

  test do
    system "#{bin}/flooc", "--version"
    system "#{bin}/floos", "--version"
  end
end
