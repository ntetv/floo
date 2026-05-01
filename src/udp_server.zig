const std = @import("std");
const posix = std.posix;
const net = @import("net_compat.zig");
const tunnel = @import("tunnel.zig");
const noise = @import("noise.zig");
const common = @import("common.zig");

/// Server-side UDP forwarder.
/// Each tunnel stream gets an independent connected UDP socket so replies from
/// the target can be associated with the originating client stream.
pub const UdpForwarder = struct {
    allocator: std.mem.Allocator,
    service_id: tunnel.ServiceId,
    target_addr: net.Address,
    tunnel_conn: *anyopaque,
    send_fn: *const fn (conn: *anyopaque, buffer: []u8, payload_len: usize) anyerror!void,
    running: std.atomic.Value(bool),
    timeout_ns: i64,
    sessions: std.AutoHashMap(tunnel.StreamId, *Session),
    sessions_mutex: std.Io.Mutex,

    pub fn create(
        allocator: std.mem.Allocator,
        service_id: tunnel.ServiceId,
        target_host: []const u8,
        target_port: u16,
        tunnel_conn: *anyopaque,
        send_fn: *const fn (conn: *anyopaque, buffer: []u8, payload_len: usize) anyerror!void,
        timeout_seconds: u64,
    ) !*UdpForwarder {
        const target_addr = try net.Address.resolveIp(target_host, target_port);
        const forwarder = try allocator.create(UdpForwarder);
        forwarder.* = .{
            .allocator = allocator,
            .service_id = service_id,
            .target_addr = target_addr,
            .tunnel_conn = tunnel_conn,
            .send_fn = send_fn,
            .running = std.atomic.Value(bool).init(true),
            .timeout_ns = @as(i64, @intCast(timeout_seconds * std.time.ns_per_s)),
            .sessions = std.AutoHashMap(tunnel.StreamId, *Session).init(allocator),
            .sessions_mutex = std.Io.Mutex.init,
        };
        return forwarder;
    }

    pub fn handleUdpData(self: *UdpForwarder, udp_msg: tunnel.UdpDataMsg) !void {
        if (udp_msg.source_addr.len == 0 or udp_msg.source_addr.len > 16) {
            return error.InvalidSourceAddress;
        }

        const now = @as(i64, @intCast(common.nanoTimestamp()));
        self.pruneExpiredSessions(now);

        const session = try self.ensureSession(udp_msg.stream_id, udp_msg.source_addr, udp_msg.source_port, now);

        _ = common.sendCompat(session.socket_fd, udp_msg.data) catch |err| {
            std.debug.print("[UDP-SERVER] send error for stream {}: {}\n", .{ udp_msg.stream_id, err });
            return err;
        };
        session.last_activity_ns.store(now, .release);
    }

    pub fn stop(self: *UdpForwarder) void {
        self.running.store(false, .release);
        var to_close = std.ArrayListUnmanaged(tunnel.StreamId).empty;
        defer to_close.deinit(self.allocator);

        self.sessions_mutex.lock(std.Options.debug_io) catch unreachable;
        var iter = self.sessions.keyIterator();
        while (iter.next()) |key_ptr| {
            if (to_close.append(self.allocator, key_ptr.*)) |_| {} else |_| break;
        }
        self.sessions_mutex.unlock(std.Options.debug_io);

        for (to_close.items) |stream_id| {
            self.removeSession(stream_id, false);
        }
    }

    pub fn destroy(self: *UdpForwarder) void {
        self.stop();
        self.sessions.deinit();
        self.allocator.destroy(self);
    }

    const Session = struct {
        stream_id: tunnel.StreamId,
        socket_fd: posix.fd_t,
        thread: std.Thread,
        running: std.atomic.Value(bool),
        forwarder: *UdpForwarder,
        last_activity_ns: std.atomic.Value(i64),
        source_addr: [16]u8,
        source_addr_len: u8,
        source_port: u16,
    };

    fn ensureSession(
        self: *UdpForwarder,
        stream_id: tunnel.StreamId,
        source_addr: []const u8,
        source_port: u16,
        now: i64,
    ) !*Session {
        self.sessions_mutex.lock(std.Options.debug_io) catch unreachable;
        if (self.sessions.get(stream_id)) |session| {
            defer self.sessions_mutex.unlock(std.Options.debug_io);
            if (session.source_addr_len != source_addr.len or
                session.source_port != source_port or
                !std.mem.eql(u8, session.source_addr[0..session.source_addr_len], source_addr))
            {
                return error.UdpForwarderBusy;
            }
            return session;
        }
        self.sessions_mutex.unlock(std.Options.debug_io);

        const fd = try common.createSocket(self.target_addr.any.family, posix.SOCK.DGRAM | common.SOCK_CLOEXEC, 0);
        errdefer common.closeFd(fd);
        try common.connectSocket(fd, &self.target_addr.any, self.target_addr.getOsSockLen());

        const session = try self.allocator.create(Session);
        session.* = .{
            .stream_id = stream_id,
            .socket_fd = fd,
            .thread = undefined,
            .running = std.atomic.Value(bool).init(true),
            .forwarder = self,
            .last_activity_ns = std.atomic.Value(i64).init(now),
            .source_addr = [_]u8{0} ** 16,
            .source_addr_len = @intCast(source_addr.len),
            .source_port = source_port,
        };
        std.mem.copyForwards(u8, session.source_addr[0..session.source_addr_len], source_addr);

        session.thread = std.Thread.spawn(.{
            .stack_size = common.DEFAULT_THREAD_STACK,
        }, sessionRecvThread, .{session}) catch |err| {
            common.closeFd(fd);
            self.allocator.destroy(session);
            return err;
        };

        self.sessions_mutex.lock(std.Options.debug_io) catch unreachable;
        self.sessions.put(stream_id, session) catch |err| {
            self.sessions_mutex.unlock(std.Options.debug_io);
            session.running.store(false, .release);
            common.shutdownSocket(session.socket_fd, .recv);
            session.thread.join();
            common.closeFd(session.socket_fd);
            self.allocator.destroy(session);
            return err;
        };
        self.sessions_mutex.unlock(std.Options.debug_io);

        return session;
    }

    fn sessionRecvThread(session: *Session) void {
        var buf: [common.SOCKET_BUFFER_SIZE]u8 align(64) = undefined;
        const forwarder = session.forwarder;

        while (session.running.load(.acquire) and forwarder.running.load(.acquire)) {
            const n = common.recvCompat(session.socket_fd, &buf) catch |err| {
                if (err == error.Interrupted) continue;
                break;
            };
            if (n <= 0) continue;

            session.last_activity_ns.store(@as(i64, @intCast(common.nanoTimestamp())), .release);

            var encode_buf: [70016]u8 = undefined;
            const udp_msg = tunnel.UdpDataMsg{
                .service_id = forwarder.service_id,
                .stream_id = session.stream_id,
                .source_addr = session.source_addr[0..session.source_addr_len],
                .source_port = session.source_port,
                .data = buf[0..n],
            };

            const encoded_len = udp_msg.encodeInto(&encode_buf) catch {
                continue;
            };

            forwarder.send_fn(forwarder.tunnel_conn, encode_buf[0 .. encoded_len + noise.TAG_LEN], encoded_len) catch |err| {
                std.debug.print("[UDP-SERVER] Failed to send to tunnel: {}\n", .{err});
            };
        }

        forwarder.removeSession(session.stream_id, true);
    }

    fn pruneExpiredSessions(self: *UdpForwarder, now: i64) void {
        if (self.timeout_ns == 0) return;

        // Workaround for Zig compiler bug in Debug mode on some platforms
        // Split into smaller parts to avoid genSetReg error
        var expired_items = std.ArrayListUnmanaged(tunnel.StreamId).empty;
        defer expired_items.deinit(self.allocator);

        {
            self.sessions_mutex.lock(std.Options.debug_io) catch unreachable;
            defer self.sessions_mutex.unlock(std.Options.debug_io);

            var iter = self.sessions.iterator();
            while (iter.next()) |entry| {
                const session_ptr = entry.value_ptr.*;
                const last_activity = session_ptr.last_activity_ns.load(.acquire);
                const time_elapsed = now - last_activity;

                if (time_elapsed > self.timeout_ns) {
                    const stream_id = entry.key_ptr.*;
                    expired_items.append(self.allocator, stream_id) catch continue;
                }
            }
        }

        // Remove expired sessions outside the lock
        for (expired_items.items) |stream_id| {
            self.removeSession(stream_id, false);
        }
    }

    fn removeSession(self: *UdpForwarder, stream_id: tunnel.StreamId, caller_is_thread: bool) void {
        self.sessions_mutex.lock(std.Options.debug_io) catch unreachable;
        const entry = self.sessions.fetchRemove(stream_id);
        self.sessions_mutex.unlock(std.Options.debug_io);

        if (entry) |removed| {
            const session = removed.value;
            session.running.store(false, .release);
            common.shutdownSocket(session.socket_fd, .recv);
            if (!caller_is_thread) {
                session.thread.join();
            }
            common.closeFd(session.socket_fd);
            self.allocator.destroy(session);
            std.debug.print("[UDP-SERVER] Session {} closed\n", .{stream_id});
        }
    }
};
