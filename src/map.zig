//! MAP (Magic Attribute Protocol): a Bitcom protocol's command and its
//! `SET` key/value pairs, read as 1sat-stack reads them
//! (pkg/template/bitcom `DecodeMap`).
//!
//! - The protocol's data must be at least 6 bytes; its first op's pushed
//!   bytes are the command.
//! - For `SET`, (key, value) op pairs follow, read until either op of a pair
//!   is missing or malformed. Any op counts (a non-push is an empty string).
//! - Keys and values are cleaned: each NUL byte, and each literal six-byte
//!   `\u0000`, becomes a space. A later key replaces an earlier one (`get`
//!   answers the last).
//! - Any other command decodes with no pairs.
const std = @import("std");
const script = @import("script.zig");
const bitcom = @import("bitcom.zig");

/// MAP's Bitcom address.
pub const prefix = "1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5";

pub const Pair = struct {
    key: []const u8,
    value: []const u8,
};

pub const Map = struct {
    cmd: []const u8,
    /// In script order, duplicates kept.
    pairs: []const Pair,

    /// The value of the last pair with key `key`.
    pub fn get(self: Map, key: []const u8) ?[]const u8 {
        var i = self.pairs.len;
        while (i > 0) {
            i -= 1;
            if (std.mem.eql(u8, self.pairs[i].key, key)) return self.pairs[i].value;
        }
        return null;
    }
};

/// The MAP in a protocol's data (`bitcom.Protocol.data`), or null when it is
/// too short or its command op is malformed. `a` holds the pairs and any
/// cleaned string; the rest are slices of `data`.
pub fn decode(a: std.mem.Allocator, data: []const u8) error{OutOfMemory}!?Map {
    if (data.len < 6) return null;
    var pos: usize = 0;
    const cmd = script.readOp(data, &pos) orelse return null;
    var pairs: std.ArrayList(Pair) = .empty;
    if (std.mem.eql(u8, cmd.data, "SET")) {
        while (true) {
            const key = script.readOp(data, &pos) orelse break;
            const value = script.readOp(data, &pos) orelse break;
            try pairs.append(a, .{ .key = try clean(a, key.data), .value = try clean(a, value.data) });
        }
    }
    return .{ .cmd = cmd.data, .pairs = try pairs.toOwnedSlice(a) };
}

/// The first MAP protocol in a Bitcom tape that decodes.
pub fn find(a: std.mem.Allocator, tape: bitcom.Tape) error{OutOfMemory}!?Map {
    var it = tape.protocols();
    while (it.next()) |p| {
        if (!std.mem.eql(u8, p.name, prefix)) continue;
        if (try decode(a, p.data)) |m| return m;
    }
    return null;
}

const escaped_nul = "\\u0000";

fn clean(a: std.mem.Allocator, s: []const u8) error{OutOfMemory}![]const u8 {
    if (std.mem.indexOfScalar(u8, s, 0) == null and std.mem.indexOf(u8, s, escaped_nul) == null) return s;
    const spaced = try a.dupe(u8, s);
    std.mem.replaceScalar(u8, spaced, 0, ' ');
    const out = try a.alloc(u8, std.mem.replacementSize(u8, spaced, escaped_nul, " "));
    _ = std.mem.replace(u8, spaced, escaped_nul, " ", out);
    return out;
}
