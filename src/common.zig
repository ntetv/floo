const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const config = @import("config.zig");
const net = @import("net_compat.zig");

pub fn nanoTimestamp() i128 {
    if (builtin.target.os.tag == .windows) {
        // std.time.nanoTimestamp() doesn't exist in this Zig nightly.
        // Use ntdll RtlQueryPerformanceCounter/Frequency (already in Zig stdlib).
        const ntdll = std.os.windows.ntdll;
        var freq: std.os.windows.LARGE_INTEGER = 1;
        var counter: std.os.windows.LARGE_INTEGER = 0;
        _ = ntdll.RtlQueryPerformanceFrequency(&freq);
        _ = ntdll.RtlQueryPerformanceCounter(&counter);
        if (freq == 0) return 0;
        return @divTrunc(@as(i128, counter) * std.time.ns_per_s, @as(i128, freq));
    }
    const ts = posix.clock_gettime(posix.CLOCK.MONOTONIC) catch return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

pub fn milliTimestamp() i64 {
    return @intCast(@divTrunc(nanoTimestamp(), std.time.ns_per_ms));
}

/// Platform-specific invalid file descriptor sentinel.
/// On POSIX: -1. On Windows: fd_t is a pointer, so we use INVALID_HANDLE_VALUE (all bits set).
pub const INVALID_FD: posix.fd_t = if (builtin.target.os.tag == .windows)
    @ptrFromInt(~@as(usize, 0))
else
    -1;

/// Convert posix.fd_t to posix.socket_t for socket API calls.
/// On Windows, HANDLE (*anyopaque) and SOCKET (*opaque{}) are distinct pointer types.
pub inline fn toSocket(fd: posix.fd_t) posix.socket_t {
    if (builtin.target.os.tag == .windows) {
        return @ptrCast(fd);
    }
    return fd;
}

inline fn socketHandle(fd: posix.fd_t) posix.socket_t {
    return toSocket(fd);
}

/// Cross-platform socket creation.
/// posix.socket() is broken for Windows in this Zig nightly (stdlib type mismatch bug).
pub fn createSocket(family: u32, sock_type: u32, protocol: u32) !posix.fd_t {
    if (builtin.target.os.tag == .windows) {
        const ws2 = std.os.windows.ws2_32;
        const filtered = sock_type & ~@as(u32, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK);
        const sock = ws2.socket(@intCast(family), @intCast(filtered), @intCast(protocol));
        if (sock == ws2.INVALID_SOCKET) return error.SystemResources;
        return @ptrCast(sock);
    }
    return posix.socket(family, sock_type, protocol);
}

/// Cross-platform bind.
/// posix.bind() throws @compileError("use std.Io instead") on Windows in this nightly.
pub fn bindSocket(fd: posix.fd_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) !void {
    if (builtin.target.os.tag == .windows) {
        const ws2 = std.os.windows.ws2_32;
        const rc = ws2.bind(toSocket(fd), @ptrCast(addr), @intCast(addrlen));
        if (rc != 0) return switch (ws2.WSAGetLastError()) {
            .EADDRINUSE => error.AddressInUse,
            .EADDRNOTAVAIL => error.AddressNotAvailable,
            .EACCES => error.AccessDenied,
            else => error.Unexpected,
        };
    } else {
        try posix.bind(fd, addr, addrlen);
    }
}

/// Cross-platform listen.
/// posix.listen() throws @compileError on Windows in this nightly.
pub fn listenSocket(fd: posix.fd_t, backlog: u31) !void {
    if (builtin.target.os.tag == .windows) {
        const ws2 = std.os.windows.ws2_32;
        const rc = ws2.listen(toSocket(fd), @intCast(backlog));
        if (rc != 0) return error.Unexpected;
    } else {
        try posix.listen(fd, backlog);
    }
}

/// Cross-platform connect.
/// posix.connect() throws @compileError on Windows in this nightly.
pub fn connectSocket(fd: posix.fd_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) !void {
    if (builtin.target.os.tag == .windows) {
        const ws2 = std.os.windows.ws2_32;
        const rc = ws2.connect(toSocket(fd), @ptrCast(addr), @intCast(addrlen));
        if (rc != 0) return switch (ws2.WSAGetLastError()) {
            .ECONNREFUSED => error.ConnectionRefused,
            .ENETUNREACH => error.NetworkUnreachable,
            .ETIMEDOUT => error.ConnectionTimedOut,
            else => error.ConnectionRefused,
        };
    } else {
        try posix.connect(fd, addr, addrlen);
    }
}

/// Cross-platform accept.
/// posix.accept() throws @compileError on Windows in this nightly.
pub fn acceptSocket(fd: posix.fd_t, addr: ?*posix.sockaddr, addr_size: ?*posix.socklen_t, flags: u32) !posix.fd_t {
    if (builtin.target.os.tag == .windows) {
        const ws2 = std.os.windows.ws2_32;
        var addrlen_i32: i32 = if (addr_size) |s| @intCast(s.*) else 0;
        const new_sock = ws2.accept(
            toSocket(fd),
            if (addr) |a| @ptrCast(a) else null,
            if (addr_size != null) &addrlen_i32 else null,
        );
        if (new_sock == ws2.INVALID_SOCKET) return error.ConnectionAborted;
        if (addr_size) |s| s.* = @intCast(addrlen_i32);
        return @ptrCast(new_sock);
    } else {
        return posix.accept(fd, addr, addr_size, flags);
    }
}

// ============================================================================
// Network Configuration Constants
// ============================================================================

/// Maximum number of pending connections in listen queue.
/// This controls how many connections can wait before accept() is called.
/// Linux default is 128, which works well for most use cases.
pub const LISTEN_BACKLOG: u32 = 128;

/// Standard buffer size for socket I/O operations (64KB).
/// Optimal for most network conditions, matches typical TCP window size.
pub const SOCKET_BUFFER_SIZE: usize = 64 * 1024;

/// Large buffer for high-throughput operations (256KB).
/// Used for frame decoding and encryption buffers.
pub const LARGE_BUFFER_SIZE: usize = 256 * 1024;

// ============================================================================
// Thread Stack Sizes
// ============================================================================

/// Default stack size for connection handler threads (256KB).
/// Provides enough space for buffers and call stack.
pub const DEFAULT_THREAD_STACK: usize = 256 * 1024;

/// Stack size for tunnel receiver threads (512KB).
/// Larger stack needed for MAX_FRAME_SIZE buffers and nested calls.
pub const TUNNEL_THREAD_STACK: usize = 512 * 1024;

// ============================================================================
// Message Buffer Sizes
// ============================================================================

/// Control message buffer size (4KB).
/// Pre-allocated buffer for encoding control messages (CONNECT, CLOSE, etc.).
/// Large enough for any control message with reasonable token lengths.
pub const CONTROL_MSG_BUFFER_SIZE: usize = 4096;

/// Initialize WinSock on Windows. Must be called before any socket operations.
/// On non-Windows platforms this is a no-op.
pub fn initWinSock() void {
    if (builtin.target.os.tag != .windows) return;
    const ws2 = std.os.windows.ws2_32;
    var wsa_data: ws2.WSADATA = undefined;
    _ = ws2.WSAStartup(0x0202, &wsa_data);
}

/// Cross-platform sleep for a given number of nanoseconds.
/// posix.nanosleep has a stdlib bug on Windows in dev.1484 (c_long vs isize).
/// On Windows, uses kernel32 Sleep() with millisecond precision (minimum 1ms).
pub fn crossSleep(nanoseconds: u64) void {
    if (builtin.target.os.tag == .windows) {
        const ms = @max(1, @as(u32, @truncate(nanoseconds / std.time.ns_per_ms)));
        _ = std.os.windows.kernel32.SleepEx(ms, 0);
    } else {
        posix.nanosleep(nanoseconds / std.time.ns_per_s, nanoseconds % std.time.ns_per_s);
    }
}

/// Lightweight trace helper that compiles away when `enabled` is false.
pub inline fn tracePrint(comptime enabled: bool, comptime fmt: []const u8, args: anytype) void {
    if (enabled) {
        std.debug.print(fmt, args);
    }
}

/// Constant-time comparison to prevent timing attacks.
///
/// This function compares two byte slices in constant time to prevent
/// attackers from using timing measurements to determine the correct
/// value byte-by-byte (timing side-channel attack).
///
/// Returns true if slices are equal, false otherwise.
///
/// Note: Length comparison is NOT constant-time, but that's unavoidable
/// as we need to know if lengths match. The actual content comparison
/// is constant-time.
///
/// Security: Use this for comparing authentication tokens, passwords,
/// PSKs, HMAC tags, or any secret values.
pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    const max_len = @max(a.len, b.len);
    var diff: u8 = 0;

    // Walk the full max length so timing does not leak the shorter prefix.
    var i: usize = 0;
    while (i < max_len) : (i += 1) {
        const lhs = if (i < a.len) a[i] else 0;
        const rhs = if (i < b.len) b[i] else 0;
        diff |= lhs ^ rhs;
    }

    return diff == 0 and a.len == b.len;
}

pub const TcpOptions = struct {
    nodelay: bool,
    keepalive: bool,
    keepalive_idle: u32,
    keepalive_interval: u32,
    keepalive_count: u32,
};

/// Build a `TcpOptions` struct from tuning settings.
pub fn tcpOptionsFromSettings(settings: *const config.TcpSettings) TcpOptions {
    return TcpOptions{
        .nodelay = settings.nodelay,
        .keepalive = settings.keepalive,
        .keepalive_idle = settings.keepalive_idle,
        .keepalive_interval = settings.keepalive_interval,
        .keepalive_count = settings.keepalive_count,
    };
}

/// Apply TCP socket options (Nagle/keepalive) with best-effort error reporting.
pub fn applyTcpOptions(fd: posix.fd_t, opts: TcpOptions) void {
    const sock = toSocket(fd);
    if (opts.nodelay) {
        const nodelay_value: c_int = 1;
        posix.setsockopt(sock, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(nodelay_value)) catch |err| {
            std.debug.print("[TCP] Failed to set TCP_NODELAY: {}\n", .{err});
        };
    }

    if (!opts.keepalive) return;

    const keepalive_value: c_int = 1;
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(keepalive_value)) catch |err| {
        std.debug.print("[TCP] Failed to set SO_KEEPALIVE: {}\n", .{err});
    };

    if (@hasDecl(posix.TCP, "KEEPIDLE")) {
        const idle_value: c_int = @intCast(opts.keepalive_idle);
        posix.setsockopt(sock, posix.IPPROTO.TCP, posix.TCP.KEEPIDLE, &std.mem.toBytes(idle_value)) catch {};
    }
    if (@hasDecl(posix.TCP, "KEEPINTVL")) {
        const intvl_value: c_int = @intCast(opts.keepalive_interval);
        posix.setsockopt(sock, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, &std.mem.toBytes(intvl_value)) catch {};
    }
    if (@hasDecl(posix.TCP, "KEEPCNT")) {
        const cnt_value: c_int = @intCast(opts.keepalive_count);
        posix.setsockopt(sock, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, &std.mem.toBytes(cnt_value)) catch {};
    }
}

/// Tune socket buffers for high throughput.
pub fn tuneSocketBuffers(fd: posix.fd_t, buffer_size: u32) void {
    const sock = toSocket(fd);
    const size: c_int = @intCast(buffer_size);
    const bytes = std.mem.toBytes(size);
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVBUF, &bytes) catch |err| {
        std.debug.print("[SOCKET] Failed to grow RCVBUF to {}: {}\n", .{ buffer_size, err });
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDBUF, &bytes) catch |err| {
        std.debug.print("[SOCKET] Failed to grow SNDBUF to {}: {}\n", .{ buffer_size, err });
    };
}

/// Send all data to file descriptor, handling partial writes.
///
/// This function ensures all bytes are sent, handling the case where
/// send() returns fewer bytes than requested (partial write).
///
/// Returns error.ConnectionClosed if the connection is closed before
/// all data is sent (send returns 0).
///
/// Extracted from client.zig and server.zig to eliminate duplication.
pub fn sendAllToFd(fd: posix.fd_t, data: []const u8) !void {
    const socket_fd = socketHandle(fd);
    var offset: usize = 0;
    while (offset < data.len) {
        const n = posix.send(socket_fd, data[offset..], 0) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

/// Write length-prefixed frame using writev() for scatter-gather I/O.
///
/// Frame format: [4-byte big-endian length][payload]
///
/// This function uses writev() for atomic write of header and payload,
/// minimizing system calls and ensuring both parts are sent together.
///
/// Handles partial writes by tracking which iovecs have been sent and
/// updating offsets accordingly.
///
/// Extracted from client.zig and server.zig to eliminate duplication.
pub fn writeFrameLocked(fd: posix.fd_t, payload: []const u8) !void {
    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], @intCast(payload.len), .big);

    // Track how much of each part has been sent
    var header_sent: usize = 0;
    var payload_sent: usize = 0;

    while (header_sent < header.len or payload_sent < payload.len) {
        // Prepare iovecs based on what still needs to be sent
        var iovecs_buf: [2]posix.iovec_const = undefined;
        var iovec_count: usize = 0;

        if (header_sent < header.len) {
            const header_remaining = header[header_sent..];
            iovecs_buf[iovec_count] = posix.iovec_const{ .base = header_remaining.ptr, .len = header_remaining.len };
            iovec_count += 1;
        }

        if (payload_sent < payload.len) {
            const payload_remaining = payload[payload_sent..];
            iovecs_buf[iovec_count] = posix.iovec_const{ .base = payload_remaining.ptr, .len = payload_remaining.len };
            iovec_count += 1;
        }

        const iovecs = iovecs_buf[0..iovec_count];
        const written: usize = if (builtin.target.os.tag == .windows) blk: {
            // WriteFile fails on overlapped sockets (Windows default).
            // Use posix.send (→ WSASend) which works on all socket types.
            const first = iovecs[0];
            break :blk posix.send(socketHandle(fd), first.base[0..first.len], 0) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
        } else posix.writev(fd, iovecs) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (written == 0) return error.ConnectionClosed;

        // Update counters based on bytes written
        var remaining = written;

        // Process header first if not fully sent
        if (header_sent < header.len) {
            const header_bytes_to_send = header.len - header_sent;
            if (remaining >= header_bytes_to_send) {
                remaining -= header_bytes_to_send;
                header_sent = header.len;
            } else {
                header_sent += remaining;
                remaining = 0;
            }
        }

        // Then process payload if we have remaining bytes
        if (remaining > 0 and payload_sent < payload.len) {
            payload_sent += @min(remaining, payload.len - payload_sent);
        }
    }
}

/// Format a net.Address into a temporary buffer for logging.
pub fn formatAddress(addr: net.Address, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{f}", .{addr}) catch "unavailable";
}

/// Resolve IPv4/IPv6/DNS host strings into a net.Address.
pub fn resolveHostPort(host: []const u8, port: u16) !net.Address {
    return net.Address.parseIp4(host, port) catch
        net.Address.parseIp6(host, port) catch
        net.Address.resolveIp(host, port);
}

/// Receive an exact number of bytes from a socket file descriptor.
pub fn recvAllFromFd(fd: posix.fd_t, buffer: []u8) !void {
    const socket_fd = socketHandle(fd);
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = posix.recv(socket_fd, buffer[offset..], 0) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

// ============================================================================
// Connection Rate Limiting
// ============================================================================

/// Simple token bucket rate limiter to prevent connection flood attacks
pub const RateLimiter = struct {
    tokens: std.atomic.Value(u32),
    max_tokens: u32,
    refill_interval_ns: i64,
    last_refill: std.atomic.Value(i64),

    /// Create a rate limiter allowing `max_per_second` operations per second
    pub fn init(max_per_second: u32) RateLimiter {
        return .{
            .tokens = std.atomic.Value(u32).init(max_per_second),
            .max_tokens = max_per_second,
            .refill_interval_ns = @intCast(@divTrunc(std.time.ns_per_s, max_per_second)),
            .last_refill = std.atomic.Value(i64).init(@intCast(nanoTimestamp())),
        };
    }

    /// Try to consume a token. Returns true if allowed, false if rate limited
    pub fn tryAcquire(self: *RateLimiter) bool {
        // In Debug mode, skip complex rate limiting to avoid compiler bugs
        if (builtin.mode == .Debug) {
            return true;
        }

        // Try to consume a token
        var current = self.tokens.load(.monotonic);
        while (current > 0) {
            if (self.tokens.cmpxchgWeak(
                current,
                current - 1,
                .monotonic,
                .monotonic,
            )) |updated| {
                current = updated;
            } else {
                return true;
            }
        }

        // Refill if needed
        const now: i64 = @intCast(nanoTimestamp());
        const last = self.last_refill.load(.monotonic);
        const elapsed = now - last;

        if (elapsed >= self.refill_interval_ns) {
            self.tokens.store(self.max_tokens, .monotonic);
            _ = self.last_refill.cmpxchgWeak(last, now, .monotonic, .monotonic);

            const refilled = self.tokens.load(.monotonic);
            if (refilled > 0) {
                _ = self.tokens.fetchSub(1, .monotonic);
                return true;
            }
        }

        return false;
    }
};
