const std = @import("std");

pub const CheckStatus = enum { ok, warn, fail };
pub const EventLevel = enum { event, warn };

pub const DisconnectReason = enum(u8) {
    none,
    eof,
    reset,
    timeout,
    recv_error,
    decoder_error,
    protocol_error,
};

pub fn reportCheck(status: CheckStatus, comptime fmt: []const u8, args: anytype) void {
    const prefix = switch (status) {
        .ok => "[OK] ",
        .warn => "[WARN] ",
        .fail => "[FAIL] ",
    };
    std.debug.print("{s}", .{prefix});
    std.debug.print(fmt, args);
    std.debug.print("\n", .{});
}

pub fn emitEvent(level: EventLevel, comptime fmt: []const u8, args: anytype) void {
    const prefix = switch (level) {
        .event => "EVENT",
        .warn => "WARN",
    };
    std.debug.print("{s}  " ++ fmt ++ "\n", .{prefix} ++ args);
}

pub fn recordDisconnectReason(slot: *DisconnectReason, reason: DisconnectReason) void {
    if (slot.* == .none) {
        slot.* = reason;
    }
}

pub fn disconnectReasonLabel(reason: DisconnectReason) []const u8 {
    return switch (reason) {
        .none => "NONE",
        .eof => "EOF",
        .reset => "RESET",
        .timeout => "TIMEOUT",
        .recv_error => "RECV_ERROR",
        .decoder_error => "DECODER_ERROR",
        .protocol_error => "PROTOCOL_ERROR",
    };
}

pub fn handshakeCauseLabel(err: anyerror) []const u8 {
    return switch (err) {
        error.HandshakeFailed => "NOT_FLOO_OR_NOT_DEPLOYED",
        error.AuthenticationFailed, error.MissingPsk => "CIPHER_OR_PSK_MISMATCH",
        error.VersionMismatch => "VERSION_MISMATCH",
        else => "UNKNOWN",
    };
}

pub fn flushEncryptStats(prefix: []const u8, total: *std.atomic.Value(u64), calls: *std.atomic.Value(u64)) void {
    const total_ns = total.load(.acquire);
    const call_count = calls.load(.acquire);
    if (call_count == 0 or total_ns == 0) return;

    const avg = total_ns / call_count;
    std.debug.print("[PROFILE] {s} encryption total={} ns calls={} avg={} ns\n", .{ prefix, total_ns, call_count, avg });
    appendProfileLine(prefix, total_ns, call_count, avg);
}

pub fn flushThroughputStats(
    prefix: []const u8,
    tx: *std.atomic.Value(u64),
    rx: *std.atomic.Value(u64),
) void {
    const tx_bytes = tx.load(.acquire);
    const rx_bytes = rx.load(.acquire);
    if (tx_bytes == 0 and rx_bytes == 0) return;

    const tx_mb = asDecimalMB(tx_bytes);
    const rx_mb = asDecimalMB(rx_bytes);
    std.debug.print(
        "[PROFILE] {s} throughput tx={} bytes ({d:.2} MB) rx={} bytes ({d:.2} MB)\n",
        .{ prefix, tx_bytes, tx_mb, rx_bytes, rx_mb },
    );
}

fn asDecimalMB(bytes: u64) f64 {
    return @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0);
}

fn appendProfileLine(prefix: []const u8, total: u64, calls: u64, avg: u64) void {
    const path = "/tmp/floo_profile.log";
    var file = std.Io.Dir.createFileAbsolute(std.Options.debug_io, path, .{ .truncate = false, .read = false }) catch return;
    defer file.close(std.Options.debug_io);

    const offset = file.stat(std.Options.debug_io) catch return;
    var buf: [128]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{s}\ttotal_ns={}\tcalls={}\tavg_ns={}\n", .{ prefix, total, calls, avg }) catch return;
    file.writePositionalAll(std.Options.debug_io, line, offset.size) catch {};
}
