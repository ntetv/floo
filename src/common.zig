const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const config = @import("config.zig");
const net = @import("net_compat.zig");

const win_sock = if (builtin.target.os.tag == .windows) struct {
    const Socket = usize;
    const INVALID_SOCKET: Socket = ~@as(usize, 0);
    const SOCKET_ERROR: c_int = -1;

    const WSAEINTR = 10004;
    const WSAEWOULDBLOCK = 10035;
    const WSAEADDRNOTAVAIL = 10049;
    const WSAENETDOWN = 10050;
    const WSAENETUNREACH = 10051;
    const WSAECONNABORTED = 10053;
    const WSAECONNRESET = 10054;
    const WSAECONNREFUSED = 10061;
    const WSAEACCES = 10013;
    const WSAEADDRINUSE = 10048;
    const WSAETIMEDOUT = 10060;
    const WSAESHUTDOWN = 10058;
    const POLLIN = 0x0300;
    const POLLERR = 0x0001;
    const POLLHUP = 0x0002;
    const POLLNVAL = 0x0004;

    pub const PollFd = extern struct {
        fd: Socket,
        events: i16,
        revents: i16,
    };

    extern "ws2_32" fn WSAStartup(wVersionRequested: u16, lpWSAData: *anyopaque) callconv(.winapi) c_int;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
    extern "ws2_32" fn socket(af: c_int, sock_type: c_int, protocol: c_int) callconv(.winapi) Socket;
    extern "ws2_32" fn closesocket(s: Socket) callconv(.winapi) c_int;
    extern "ws2_32" fn bind(s: Socket, name: *const anyopaque, namelen: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn listen(s: Socket, backlog: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn connect(s: Socket, name: *const anyopaque, namelen: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn accept(s: Socket, addr: ?*anyopaque, addrlen: ?*c_int) callconv(.winapi) Socket;
    extern "ws2_32" fn setsockopt(s: Socket, level: c_int, optname: c_int, optval: [*]const u8, optlen: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn send(s: Socket, buf: [*]const u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn recv(s: Socket, buf: [*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn sendto(s: Socket, buf: [*]const u8, len: c_int, flags: c_int, to: *const anyopaque, tolen: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn recvfrom(s: Socket, buf: [*]u8, len: c_int, flags: c_int, from: ?*anyopaque, fromlen: ?*c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn shutdown(s: Socket, how: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn WSAPoll(fdarray: [*]@This().PollFd, nfds: u32, timeout: c_int) callconv(.winapi) c_int;
} else struct {};

pub fn nanoTimestamp() i128 {
    if (builtin.target.os.tag == .windows) {
        // Use ntdll RtlQueryPerformanceCounter/Frequency on Windows.
        const ntdll = std.os.windows.ntdll;
        var freq: std.os.windows.LARGE_INTEGER = 1;
        var counter: std.os.windows.LARGE_INTEGER = 0;
        _ = ntdll.RtlQueryPerformanceFrequency(&freq);
        _ = ntdll.RtlQueryPerformanceCounter(&counter);
        if (freq == 0) return 0;
        return @divTrunc(@as(i128, counter) * std.time.ns_per_s, @as(i128, freq));
    }

    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts) != 0) return 0;
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
pub inline fn toSocket(fd: posix.fd_t) if (builtin.target.os.tag == .windows) win_sock.Socket else posix.socket_t {
    if (builtin.target.os.tag == .windows) {
        return @intFromPtr(fd);
    }
    return fd;
}

inline fn socketHandle(fd: posix.fd_t) if (builtin.target.os.tag == .windows) win_sock.Socket else posix.socket_t {
    return toSocket(fd);
}

pub const PollFd = if (builtin.target.os.tag == .windows) win_sock.PollFd else posix.pollfd;
pub const POLL_IN: i16 = if (builtin.target.os.tag == .windows) win_sock.POLLIN else posix.POLL.IN;
pub const POLL_ERR: i16 = if (builtin.target.os.tag == .windows) win_sock.POLLERR else posix.POLL.ERR;
pub const POLL_HUP: i16 = if (builtin.target.os.tag == .windows) win_sock.POLLHUP else posix.POLL.HUP;
pub const POLL_NVAL: i16 = if (builtin.target.os.tag == .windows) win_sock.POLLNVAL else if (@hasDecl(posix.POLL, "NVAL")) posix.POLL.NVAL else 0;

pub fn pollCompat(fds: []PollFd, timeout_ms: i32) !usize {
    if (builtin.target.os.tag == .windows) {
        const rc = win_sock.WSAPoll(fds.ptr, @intCast(fds.len), timeout_ms);
        if (rc >= 0) return @intCast(rc);
        return switch (win_sock.WSAGetLastError()) {
            win_sock.WSAEINTR => error.SignalInterrupt,
            else => error.Unexpected,
        };
    }
    return posix.poll(fds, timeout_ms);
}

/// Cross-platform fd close.
pub inline fn closeFd(fd: posix.fd_t) void {
    if (builtin.target.os.tag == .windows) {
        _ = win_sock.closesocket(toSocket(fd));
    } else {
        _ = posix.system.close(fd);
    }
}

/// Cross-platform pipe2.
pub fn pipe2Compat(flags: posix.O) ![2]posix.fd_t {
    if (builtin.target.os.tag == .windows) {
        return posix.pipe2(flags);
    }

    var fds: [2]posix.fd_t = undefined;
    if (std.c.pipe(&fds) != 0) {
        return error.SystemResources;
    }

    if (flags.CLOEXEC) {
        _ = posix.system.fcntl(fds[0], posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC));
        _ = posix.system.fcntl(fds[1], posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC));
    }
    if (flags.NONBLOCK) {
        const r0 = posix.system.fcntl(fds[0], posix.F.GETFL, @as(c_int, 0));
        const r1 = posix.system.fcntl(fds[1], posix.F.GETFL, @as(c_int, 0));
        const nonblock_flag: c_int = @bitCast(std.c.O{ .NONBLOCK = true });
        _ = posix.system.fcntl(fds[0], posix.F.SETFL, r0 | nonblock_flag);
        _ = posix.system.fcntl(fds[1], posix.F.SETFL, r1 | nonblock_flag);
    }
    return fds;
}

pub const SOCK_CLOEXEC: u32 = if (builtin.target.os.tag == .windows or !@hasDecl(posix.SOCK, "CLOEXEC")) 0 else @field(posix.SOCK, "CLOEXEC");
pub const SOCK_NONBLOCK: u32 = if (builtin.target.os.tag == .windows or !@hasDecl(posix.SOCK, "NONBLOCK")) 0 else @field(posix.SOCK, "NONBLOCK");

/// Cross-platform socket creation.
pub fn createSocket(family: u32, sock_type: u32, protocol: u32) !posix.fd_t {
    if (builtin.target.os.tag == .windows) {
        const filtered = sock_type & ~@as(u32, SOCK_CLOEXEC | SOCK_NONBLOCK);
        const sock = win_sock.socket(@intCast(family), @intCast(filtered), @intCast(protocol));
        if (sock == win_sock.INVALID_SOCKET) return error.SystemResources;
        return @ptrFromInt(sock);
    }

    const want_cloexec = (sock_type & SOCK_CLOEXEC) != 0;
    const want_nonblock = (sock_type & SOCK_NONBLOCK) != 0;
    const filtered = sock_type & ~@as(u32, SOCK_CLOEXEC | SOCK_NONBLOCK);

    const rc = posix.system.socket(family, filtered, protocol);
    switch (posix.errno(rc)) {
        .SUCCESS => {
            const fd: posix.fd_t = @intCast(rc);
            if (want_cloexec) setCloseOnExec(fd);
            if (want_nonblock and builtin.target.os.tag != .windows) {
                const current = posix.system.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
                const nonblock_flag: c_int = @bitCast(std.c.O{ .NONBLOCK = true });
                _ = posix.system.fcntl(fd, posix.F.SETFL, current | nonblock_flag);
            }
            return fd;
        },
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .PROTONOSUPPORT, .NOPROTOOPT => return error.ProtocolNotSupported,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// Cross-platform bind.
pub fn bindSocket(fd: posix.fd_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) !void {
    if (builtin.target.os.tag == .windows) {
        const rc = win_sock.bind(toSocket(fd), @ptrCast(addr), @intCast(addrlen));
        if (rc != 0) return switch (win_sock.WSAGetLastError()) {
            win_sock.WSAEADDRINUSE => error.AddressInUse,
            win_sock.WSAEADDRNOTAVAIL => error.AddressNotAvailable,
            win_sock.WSAEACCES => error.AccessDenied,
            else => error.Unexpected,
        };
    } else {
        switch (posix.errno(posix.system.bind(fd, addr, addrlen))) {
            .SUCCESS => return,
            .ACCES => return error.AccessDenied,
            .ADDRINUSE => return error.AddressInUse,
            .ADDRNOTAVAIL => return error.AddressNotAvailable,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

/// Cross-platform listen.
pub fn listenSocket(fd: posix.fd_t, backlog: u31) !void {
    if (builtin.target.os.tag == .windows) {
        const rc = win_sock.listen(toSocket(fd), @intCast(backlog));
        if (rc != 0) return error.Unexpected;
    } else {
        switch (posix.errno(posix.system.listen(fd, backlog))) {
            .SUCCESS => return,
            .ADDRINUSE => return error.AddressInUse,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

/// Cross-platform connect.
pub fn connectSocket(fd: posix.fd_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) !void {
    if (builtin.target.os.tag == .windows) {
        const rc = win_sock.connect(toSocket(fd), @ptrCast(addr), @intCast(addrlen));
        if (rc != 0) return switch (win_sock.WSAGetLastError()) {
            win_sock.WSAECONNREFUSED => error.ConnectionRefused,
            win_sock.WSAENETUNREACH => error.NetworkUnreachable,
            win_sock.WSAETIMEDOUT => error.ConnectionTimedOut,
            else => error.ConnectionRefused,
        };
    } else {
        switch (posix.errno(posix.system.connect(fd, addr, addrlen))) {
            .SUCCESS => return,
            .ADDRNOTAVAIL => return error.AddressNotAvailable,
            .CONNREFUSED => return error.ConnectionRefused,
            .HOSTUNREACH => return error.HostUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .TIMEDOUT => return error.ConnectionTimedOut,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

/// Cross-platform accept.
pub fn acceptSocket(fd: posix.fd_t, addr: ?*posix.sockaddr, addr_size: ?*posix.socklen_t, flags: u32) !posix.fd_t {
    if (builtin.target.os.tag == .windows) {
        _ = flags;
        var addrlen_i32: c_int = if (addr_size) |s| @intCast(s.*) else 0;
        const new_sock = win_sock.accept(
            toSocket(fd),
            if (addr) |a| @ptrCast(a) else null,
            if (addr_size != null) &addrlen_i32 else null,
        );
        if (new_sock == win_sock.INVALID_SOCKET) return error.ConnectionAborted;
        if (addr_size) |s| s.* = @intCast(addrlen_i32);
        return @ptrFromInt(new_sock);
    } else {
        _ = flags;
        var storage: posix.sockaddr = undefined;
        var storage_len: posix.socklen_t = @sizeOf(@TypeOf(storage));
        const rc = posix.system.accept(fd, if (addr != null) addr.? else &storage, if (addr_size != null) addr_size.? else &storage_len);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .CONNABORTED => return error.ConnectionAborted,
            .AGAIN => return error.WouldBlock,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

// ============================================================================
// Network Configuration Constants
// ============================================================================

/// Maximum number of pending connections in listen queue.
/// This controls how many connections can wait before accept() is called.
/// Set to 4096 to support high-concurrency SOCKS5/proxy scenarios.
/// Effective value = min(LISTEN_BACKLOG, net.core.somaxconn).
pub const LISTEN_BACKLOG: u32 = 4096;

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
    var wsa_data: [512]u8 = undefined;
    _ = win_sock.WSAStartup(0x0202, &wsa_data);
}

/// Cross-platform sleep for a given number of nanoseconds.
/// On Windows, use `NtDelayExecution` for stable 0.16.0 compatibility.
pub fn crossSleep(nanoseconds: u64) void {
    if (builtin.target.os.tag == .windows) {
        const ticks_100ns: i64 = @intCast(@divTrunc(nanoseconds, 100));
        const delay_ticks: i64 = @max(1, ticks_100ns);
        const delay_interval: std.os.windows.LARGE_INTEGER = -delay_ticks;
        _ = std.os.windows.ntdll.NtDelayExecution(.FALSE, &delay_interval);
    } else {
        const ts = std.c.timespec{
            .sec = @intCast(nanoseconds / std.time.ns_per_s),
            .nsec = @intCast(nanoseconds % std.time.ns_per_s),
        };
        _ = std.c.nanosleep(&ts, null);
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

pub const SetSocketOptionError = error{Unexpected};

pub fn setSocketOption(fd: posix.fd_t, level: i32, optname: u32, opt: []const u8) SetSocketOptionError!void {
    if (builtin.target.os.tag == .windows) {
        const rc = win_sock.setsockopt(toSocket(fd), level, @intCast(optname), opt.ptr, @intCast(opt.len));
        if (rc != 0) return error.Unexpected;
        return;
    }
    posix.setsockopt(toSocket(fd), level, optname, opt) catch return error.Unexpected;
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
    if (opts.nodelay) {
        const nodelay_value: c_int = 1;
        setSocketOption(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(nodelay_value)) catch |err| {
            std.debug.print("[TCP] Failed to set TCP_NODELAY: {}\n", .{err});
        };
    }

    if (!opts.keepalive) return;

    const keepalive_value: c_int = 1;
    setSocketOption(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(keepalive_value)) catch |err| {
        std.debug.print("[TCP] Failed to set SO_KEEPALIVE: {}\n", .{err});
    };

    if (@hasDecl(posix.TCP, "KEEPIDLE")) {
        const idle_value: c_int = @intCast(opts.keepalive_idle);
        setSocketOption(fd, posix.IPPROTO.TCP, posix.TCP.KEEPIDLE, &std.mem.toBytes(idle_value)) catch {};
    }
    if (@hasDecl(posix.TCP, "KEEPINTVL")) {
        const intvl_value: c_int = @intCast(opts.keepalive_interval);
        setSocketOption(fd, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, &std.mem.toBytes(intvl_value)) catch {};
    }
    if (@hasDecl(posix.TCP, "KEEPCNT")) {
        const cnt_value: c_int = @intCast(opts.keepalive_count);
        setSocketOption(fd, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, &std.mem.toBytes(cnt_value)) catch {};
    }
}

/// Send on socket fd with Zig 0.16 compatible APIs.
pub fn sendCompat(fd: posix.fd_t, data: []const u8) !usize {
    if (builtin.target.os.tag == .windows) {
        const send_len: c_int = @intCast(@min(data.len, @as(usize, std.math.maxInt(c_int))));
        const rc = win_sock.send(socketHandle(fd), data.ptr, send_len, 0);
        if (rc >= 0) return @intCast(rc);
        return switch (win_sock.WSAGetLastError()) {
            win_sock.WSAEWOULDBLOCK => error.WouldBlock,
            win_sock.WSAECONNRESET => error.ConnectionResetByPeer,
            win_sock.WSAESHUTDOWN => error.BrokenPipe,
            else => error.Unexpected,
        };
    }

    const rc = posix.system.send(socketHandle(fd), data.ptr, data.len, 0);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AGAIN => error.WouldBlock,
        .CONNRESET => error.ConnectionResetByPeer,
        .PIPE => error.BrokenPipe,
        else => |err| posix.unexpectedErrno(err),
    };
}

/// Receive from socket fd with Zig 0.16 compatible APIs.
pub fn recvCompat(fd: posix.fd_t, buffer: []u8) !usize {
    if (builtin.target.os.tag == .windows) {
        const recv_len: c_int = @intCast(@min(buffer.len, @as(usize, std.math.maxInt(c_int))));
        const rc = win_sock.recv(socketHandle(fd), buffer.ptr, recv_len, 0);
        if (rc >= 0) return @intCast(rc);
        return switch (win_sock.WSAGetLastError()) {
            win_sock.WSAEWOULDBLOCK => error.WouldBlock,
            win_sock.WSAECONNRESET => error.ConnectionResetByPeer,
            else => error.Unexpected,
        };
    }

    const rc = posix.system.recv(socketHandle(fd), buffer.ptr, buffer.len, 0);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AGAIN => error.WouldBlock,
        .CONNRESET => error.ConnectionResetByPeer,
        .BADF => error.ConnectionResetByPeer,
        else => |err| posix.unexpectedErrno(err),
    };
}

/// Best-effort close of the read/write halves of a socket.
pub fn shutdownSocket(fd: posix.fd_t, how: std.Io.net.ShutdownHow) void {
    if (builtin.target.os.tag == .windows) {
        _ = win_sock.shutdown(socketHandle(fd), @intFromEnum(how));
        return;
    }
    _ = posix.system.shutdown(socketHandle(fd), @intFromEnum(how));
}

/// Best-effort set CLOEXEC on an fd.
pub fn setCloseOnExec(fd: posix.fd_t) void {
    if (builtin.target.os.tag == .windows) return;
    _ = posix.system.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC));
}

/// Receive a UDP datagram using Zig 0.16 compatible APIs.
pub fn recvFromCompat(fd: posix.fd_t, buffer: []u8, src_addr: *posix.sockaddr, src_len: *posix.socklen_t) !usize {
    if (builtin.target.os.tag == .windows) {
        const recv_len: c_int = @intCast(@min(buffer.len, @as(usize, std.math.maxInt(c_int))));
        var src_len_i32: c_int = @intCast(src_len.*);
        const rc = win_sock.recvfrom(socketHandle(fd), buffer.ptr, recv_len, 0, @ptrCast(src_addr), &src_len_i32);
        if (rc >= 0) {
            src_len.* = @intCast(src_len_i32);
            return @intCast(rc);
        }
        return switch (win_sock.WSAGetLastError()) {
            win_sock.WSAEWOULDBLOCK => error.WouldBlock,
            else => error.Unexpected,
        };
    }
    const rc = posix.system.recvfrom(socketHandle(fd), buffer.ptr, buffer.len, 0, src_addr, src_len);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AGAIN => error.WouldBlock,
        else => |err| posix.unexpectedErrno(err),
    };
}

/// Send a UDP datagram using Zig 0.16 compatible APIs.
pub fn sendToCompat(fd: posix.fd_t, buffer: []const u8, dst_addr: *const posix.sockaddr, dst_len: posix.socklen_t) !usize {
    if (builtin.target.os.tag == .windows) {
        const send_len: c_int = @intCast(@min(buffer.len, @as(usize, std.math.maxInt(c_int))));
        const rc = win_sock.sendto(socketHandle(fd), buffer.ptr, send_len, 0, @ptrCast(dst_addr), @intCast(dst_len));
        if (rc >= 0) return @intCast(rc);
        return switch (win_sock.WSAGetLastError()) {
            win_sock.WSAEWOULDBLOCK => error.WouldBlock,
            win_sock.WSAECONNRESET => error.ConnectionResetByPeer,
            else => error.Unexpected,
        };
    }
    const rc = posix.system.sendto(socketHandle(fd), buffer.ptr, buffer.len, 0, dst_addr, dst_len);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AGAIN => error.WouldBlock,
        else => |err| posix.unexpectedErrno(err),
    };
}

/// Tune socket buffers for high throughput.
pub fn tuneSocketBuffers(fd: posix.fd_t, buffer_size: u32) void {
    const size: c_int = @intCast(buffer_size);
    const bytes = std.mem.toBytes(size);
    setSocketOption(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &bytes) catch |err| {
        std.debug.print("[SOCKET] Failed to grow RCVBUF to {}: {}\n", .{ buffer_size, err });
    };
    setSocketOption(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &bytes) catch |err| {
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
    var offset: usize = 0;
    while (offset < data.len) {
        const n = sendCompat(fd, data[offset..]) catch |err| switch (err) {
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
            // Use sendCompat which works on all socket types.
            const first = iovecs[0];
            break :blk sendCompat(fd, first.base[0..first.len]) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
        } else blk: {
            const rc = posix.system.writev(fd, iovecs.ptr, @intCast(iovecs.len));
            switch (posix.errno(rc)) {
                .SUCCESS => break :blk @intCast(rc),
                .AGAIN => continue,
                else => |err| return posix.unexpectedErrno(err),
            }
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
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = recvCompat(fd, buffer[offset..]) catch |err| switch (err) {
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
