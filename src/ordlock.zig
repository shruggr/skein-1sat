//! OrdLock v2 listings (1sat-stack pkg/template/ordlock `constants_v2.go`,
//! `ordlock_v2.go` `DecodeV2`) and the branch a spend of one takes
//! (pkg/ordlock `classifySpend`).
//!
//! A listing is found by the template's invariant 436-byte prefix anywhere
//! in the locking script; from there the deployed script must follow the
//! 472-byte template byte for byte, except at its two constructor slots
//! (`OP_0` in the template), each of which holds one push (direct,
//! `OP_PUSHDATA1` or `OP_PUSHDATA2`): payOutput at template offset 436, the
//! seller's 20-byte public key hash at 468. Bytes before the prefix (an
//! inscription) and after the template (MAP) are not examined.
//!
//! payOutput is a serialized transaction output (8-byte little-endian
//! satoshis, varint script length, script): the price is its satoshis, paid
//! to its script.
const std = @import("std");
const script = @import("script.zig");

pub const template = hexBytes("76009c637576ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01c37e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad6900aa7c820128947f7701207f758767519d7b0a6f6c323a63616e63656c8876a90088ac68");

pub const pay_output_slot = 436;
pub const seller_slot = 468;
pub const prefix = template[0..pay_output_slot];

/// The offset of the purchase branch's `OP_CODESEPARATOR`.
pub const code_separator_index = 6;

pub const Listing = struct {
    /// The cancel key's public key hash.
    seller: [20]u8,
    /// payOutput's satoshis.
    price: u64,
    /// payOutput's locking script.
    pay_script: []const u8,
    /// payOutput as serialized (the bytes it was read from).
    pay_output: []const u8,
    /// Where the template starts in the locking script.
    start: usize,
};

/// The OrdLock v2 listing in `lock`, or null.
pub fn decode(lock: []const u8) ?Listing {
    const start = std.mem.indexOf(u8, lock, prefix) orelse return null;
    const deployed = lock[start..];
    var slots: [2][]const u8 = undefined;
    var ti: usize = 0;
    var di: usize = 0;
    while (ti < template.len) {
        if (ti == pay_output_slot or ti == seller_slot) {
            const push = readPush(deployed, di) orelse return null;
            slots[if (ti == pay_output_slot) 0 else 1] = push.data;
            di += push.len;
            ti += 1;
            continue;
        }
        if (di >= deployed.len or deployed[di] != template[ti]) return null;
        ti += 1;
        di += 1;
    }
    if (slots[1].len != 20) return null;
    const pay = readOutput(slots[0]) orelse return null;
    return .{
        .seller = slots[1][0..20].*,
        .price = pay.satoshis,
        .pay_script = pay.script,
        .pay_output = slots[0][0..pay.len],
        .start = start,
    };
}

/// One direct, `OP_PUSHDATA1` or `OP_PUSHDATA2` push at `off` (Go's `readPushAt`).
fn readPush(b: []const u8, off: usize) ?struct { data: []const u8, len: usize } {
    if (off >= b.len) return null;
    const op = b[off];
    const head: usize = switch (op) {
        0x01...0x4b => 1,
        script.OP_PUSHDATA1 => 2,
        script.OP_PUSHDATA2 => 3,
        else => return null,
    };
    if (off + head > b.len) return null;
    const n: usize = switch (op) {
        script.OP_PUSHDATA1 => b[off + 1],
        script.OP_PUSHDATA2 => std.mem.readInt(u16, b[off + 1 ..][0..2], .little),
        else => op,
    };
    if (n > b.len - off - head) return null;
    return .{ .data = b[off + head .. off + head + n], .len = head + n };
}

const Output = struct { satoshis: u64, script: []const u8, len: usize };

/// A serialized transaction output at the start of `b` (trailing bytes ignored).
fn readOutput(b: []const u8) ?Output {
    if (b.len < 9) return null;
    const sats = std.mem.readInt(u64, b[0..8], .little);
    var at: usize = 9;
    const n: u64 = switch (b[8]) {
        0xfd => blk: {
            if (b.len < 11) return null;
            at = 11;
            break :blk std.mem.readInt(u16, b[9..11], .little);
        },
        0xfe => blk: {
            if (b.len < 13) return null;
            at = 13;
            break :blk std.mem.readInt(u32, b[9..13], .little);
        },
        0xff => blk: {
            if (b.len < 17) return null;
            at = 17;
            break :blk std.mem.readInt(u64, b[9..17], .little);
        },
        else => b[8],
    };
    if (n > b.len - at) return null;
    const end = at + @as(usize, @intCast(n));
    return .{ .satoshis = sats, .script = b[at..end], .len = end };
}

pub const Spend = enum { purchase, cancel };

/// The branch a listing's unlocking script takes, by its last byte, the
/// branch selector: `OP_0` purchase, `OP_1` cancel; null for any other.
pub fn classify(unlocking: []const u8) ?Spend {
    if (unlocking.len == 0) return null;
    return switch (unlocking[unlocking.len - 1]) {
        script.OP_0 => .purchase,
        script.OP_1 => .cancel,
        else => null,
    };
}

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(100_000);
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}
