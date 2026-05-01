# Changelog

All notable changes to Floo will be documented in this file.

## [0.1.6] - 2026-05-01

### Added
- Added dedicated 5-platform release packaging for x86_64 Linux musl, aarch64 Linux musl, aarch64 macOS, x86_64 macOS, and x86_64 Windows.
- Added hot spare tunnel promotion so a pre-connected spare can take over when an active tunnel drops.

### Changed
- Upgraded the project to Zig 0.16.0 stable for current builds and release packaging, including Windows builds.
- Reworked reverse listener failover to rebind listeners to a healthy tunnel instead of recreating them on every reconnect.
- Consolidated Windows socket, poll, sleep, and socket-option compatibility in the shared networking layer.

### Fixed
- Fixed reverse tunnel instability triggered by multi-tunnel reconnect and listener rebinding races.
- Fixed Windows x86_64 cross-compilation issues under Zig 0.16.0.
- Fixed noisy disconnect handling for expected tunnel reset/failover paths.

## [0.1.5] - 2025-11-19

### Changed
- Upgraded the project to Zig 0.16.0 stable for current builds and release packaging.
- Updated CI/CD workflows to support Zig 0.16.0.
- Fixed Linux compilation issues regarding `sigset_t` initialization.

### Performance
- **22.2 Gbps** AES-128-GCM throughput (Reverse Mode, M1).
- AES-GCM now outperforms AEGIS ciphers on hardware with AES-NI/ARMv8 Crypto extensions.
- Outperforms Rathole by ~1.5x and FRP by ~2.1x.

## [0.1.4] - 2025-11-09

### Performance
- **30.9 Gbps** plaintext throughput (single stream, M1)
- **22.1 Gbps** AEGIS-128L encrypted throughput (single stream, M1)
- **23.3 Gbps** AEGIS-128L reverse mode (single stream, M1)
- 3.4x faster than FRP in single-stream benchmarks
- 1.3x faster than Rathole with AEGIS-128L
- Multi-stream performance: 7.7-9.6 Gbps (4 concurrent streams)

### Changed
- Updated benchmark methodology for better accuracy (single-stream testing)
- Enhanced performance testing coverage across all cipher types
- Improved documentation with comprehensive architecture explanation

### Documentation
- Added detailed architecture deep-dive
- Updated benchmark results with single-stream and multi-stream comparisons
- Added cipher performance comparison tables
- Documented data flow paths and design patterns

## [0.1.3] - 2024-11-08

### Added
- Reference counting for streams and connections to prevent use-after-free bugs
- Comprehensive reverse forwarding examples (Emby/Jellyfin)
- Multi-client load balancing example
- Corporate proxy tunneling example
- Dedicated `configs/` directory for configuration templates
- Socket buffer size configuration support (up to 8MB)

### Changed
- Simplified TOML configuration format
- Improved stream lifecycle management with proper cleanup
- Updated benchmark script to test both forward and reverse modes
- Reorganized project structure for better clarity
- Enhanced documentation with clearer examples

### Fixed
- **Critical**: Reverse forwarding crashes after first request
- **Critical**: Use-after-free vulnerability in ReverseListener
- **Critical**: Mutex deadlocks during blocking I/O operations
- Memory leaks in stream and connection cleanup
- Signal handling for SIGPIPE and EINTR
- Hardware crypto acceleration on ARM processors (restored 22+ Gbps performance)

### Performance
- AEGIS-128L: 22.6 Gbps (encrypted with hardware acceleration)
- AES-256-GCM: 18.0 Gbps (2.2x faster than FRP)
- Plaintext: 28+ Gbps single stream
- Reverse mode now performs as well as forward mode

### Security
- Fixed timing attack vulnerability in token comparison
- All PSK comparisons now use constant-time equality checks

## [0.1.2] - Previous Release

Initial stable release with basic forward and reverse tunneling support.