//! Script ops as 1sat-stack reads them (go-sdk `script.ReadOp`), and the
//! P2PKH template.
const std = @import("std");

pub const OP_0 = 0x00;
pub const OP_PUSHDATA1 = 0x4c;
pub const OP_PUSHDATA2 = 0x4d;
pub const OP_PUSHDATA4 = 0x4e;
pub const OP_1NEGATE = 0x4f;
pub const OP_RESERVED = 0x50;
pub const OP_1 = 0x51;
pub const OP_16 = 0x60;
pub const OP_IF = 0x63;
pub const OP_ENDIF = 0x68;
pub const OP_RETURN = 0x6a;
pub const OP_DUP = 0x76;
pub const OP_EQUALVERIFY = 0x88;
pub const OP_HASH160 = 0xa9;
pub const OP_CODESEPARATOR = 0xab;
pub const OP_CHECKSIG = 0xac;

pub const Op = struct {
    op: u8,
    /// The pushed bytes; empty for every op that is not a push.
    data: []const u8,
    /// The op's first byte.
    start: usize,
};

/// The op at `pos.*`, advancing it past the op; null at the end of the script
/// or when a push runs past it (go-sdk's `ReadOp` errors).
pub fn readOp(script: []const u8, pos: *usize) ?Op {
    const start = pos.*;
    if (start >= script.len) return null;
    const op = script[start];
    var at = start + 1;
    const len: usize = switch (op) {
        0x01...0x4b => op,
        OP_PUSHDATA1 => blk: {
            if (at + 1 > script.len) return null;
            at += 1;
            break :blk script[at - 1];
        },
        OP_PUSHDATA2 => blk: {
            if (at + 2 > script.len) return null;
            at += 2;
            break :blk std.mem.readInt(u16, script[at - 2 ..][0..2], .little);
        },
        OP_PUSHDATA4 => blk: {
            if (at + 4 > script.len) return null;
            at += 4;
            break :blk std.mem.readInt(u32, script[at - 4 ..][0..4], .little);
        },
        else => {
            pos.* = at;
            return .{ .op = op, .data = &.{}, .start = start };
        },
    };
    if (len > script.len - at) return null;
    pos.* = at + len;
    return .{ .op = op, .data = script[at .. at + len], .start = start };
}

/// The public key hash of a bare 25-byte P2PKH locking script, or null.
pub fn p2pkh(script: []const u8) ?[20]u8 {
    if (script.len != 25) return null;
    if (script[0] != OP_DUP or script[1] != OP_HASH160 or script[2] != 20 or
        script[23] != OP_EQUALVERIFY or script[24] != OP_CHECKSIG) return null;
    return script[3..23].*;
}

test "readOp: pushes, opcodes, truncation" {
    const s = [_]u8{ 0x02, 0xaa, 0xbb, OP_PUSHDATA1, 0x01, 0xcc, OP_0, OP_RETURN, 0x05, 0x01 };
    var pos: usize = 0;
    const a = readOp(&s, &pos).?;
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, a.data);
    const b = readOp(&s, &pos).?;
    try std.testing.expectEqual(@as(u8, OP_PUSHDATA1), b.op);
    try std.testing.expectEqualSlices(u8, &.{0xcc}, b.data);
    try std.testing.expectEqual(@as(u8, OP_0), readOp(&s, &pos).?.op);
    try std.testing.expectEqual(@as(usize, 7), readOp(&s, &pos).?.start);
    try std.testing.expect(readOp(&s, &pos) == null);
}
