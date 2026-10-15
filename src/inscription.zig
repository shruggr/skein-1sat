//! The 1Sat `ord` inscription envelope, read as 1sat-stack reads it
//! (pkg/template/inscription `Decode`; the owner as pkg/parse
//! `ParseInscription` finds it).
//!
//! - The script is walked op by op from the start. The envelope starts at the
//!   first op that is the direct push `0x03 "ord"` whose two preceding BYTES
//!   are `OP_0 OP_IF` (`00 63`): it may sit anywhere, after a lock (the
//!   prefix) or before it (the suffix). A malformed push before it ends the
//!   walk: not an inscription.
//! - Then (tag, value) op pairs. A tag is `OP_1`..`OP_16` (its number),
//!   `OP_1NEGATE` (-1), `OP_RESERVED` (0, Go's `op - 80`), a one-byte push
//!   (that byte), an empty push or `OP_0` (0), or a longer push (a named
//!   field). Tag 1 is the content type (kept only when under 256 bytes of
//!   valid UTF-8; the last one wins); tag 3 the parent (36 bytes: an
//!   outpoint; 32 bytes: a txid, output 0); tag 0 is the content and ends the
//!   fields.
//! - Either op of a pair above `OP_16`, or the end of the script, ends the
//!   envelope without content: it is still an inscription (`content` null,
//!   empty suffix), as Go returns it.
//! - After the content the next op must be `OP_ENDIF` or the end of the
//!   script; anything else and the walk resumes after that op, looking for
//!   another envelope.
//! - The owner (1SAT_P2PKH): the suffix, after one optional
//!   `OP_CODESEPARATOR`, starting with a 25-byte P2PKH lock (pkg/parse
//!   `ParseInscription`); else the prefix starting with one (pkg/parse
//!   `ParseP2PKH`, which reads the script's first 25 bytes).
const std = @import("std");
const script = @import("script.zig");

pub const Outpoint = struct {
    /// Internal byte order, as in a transaction input.
    txid: [32]u8,
    vout: u32,
};

pub const Tag = union(enum) {
    number: i32,
    name: []const u8,
};

pub const Field = struct {
    tag: Tag,
    value: []const u8,
};

pub const Inscription = struct {
    content_type: ?[]const u8 = null,
    /// Tag 0's value; null when the envelope ended without one.
    content: ?[]const u8 = null,
    parent: ?Outpoint = null,
    /// The (tag, value) pairs before the content, as script bytes: `fields()` walks them.
    pairs: []const u8,
    /// The locking script before the envelope's `OP_0 OP_IF`, and after its `OP_ENDIF`.
    prefix: []const u8,
    suffix: []const u8 = &.{},
    /// The public key hash of the P2PKH lock after the envelope.
    owner: ?[20]u8 = null,

    pub fn fields(self: Inscription) Fields {
        return .{ .pairs = self.pairs };
    }

    /// The last named field `name`'s value (Go's `Fields[name]`).
    pub fn field(self: Inscription, name: []const u8) ?[]const u8 {
        var found: ?[]const u8 = null;
        var it = self.fields();
        while (it.next()) |f| switch (f.tag) {
            .name => |n| if (std.mem.eql(u8, n, name)) {
                found = f.value;
            },
            .number => {},
        };
        return found;
    }
};

pub const Fields = struct {
    pairs: []const u8,
    pos: usize = 0,

    pub fn next(self: *Fields) ?Field {
        const tag = script.readOp(self.pairs, &self.pos) orelse return null;
        const val = script.readOp(self.pairs, &self.pos) orelse return null;
        return .{ .tag = tagOf(tag), .value = val.data };
    }
};

fn tagOf(op: script.Op) Tag {
    if (op.op > script.OP_PUSHDATA4) return .{ .number = @as(i32, op.op) - script.OP_RESERVED };
    if (op.data.len == 1) return .{ .number = op.data[0] };
    if (op.data.len > 1) return .{ .name = op.data };
    return .{ .number = 0 };
}

/// The first `ord` envelope in `lock` (see the file comment), or null.
pub fn decode(lock: []const u8) ?Inscription {
    var pos: usize = 0;
    while (pos < lock.len) {
        const start = pos;
        const first = script.readOp(lock, &pos) orelse return null;
        if (!(start >= 2 and first.op == 0x03 and std.mem.eql(u8, first.data, "ord") and
            lock[start - 2] == script.OP_0 and lock[start - 1] == script.OP_IF)) continue;

        var insc: Inscription = .{ .pairs = &.{}, .prefix = lock[0 .. start - 2] };
        const pairs_start = pos;
        while (true) {
            const pair_start = pos;
            insc.pairs = lock[pairs_start..pair_start];
            const tag = script.readOp(lock, &pos) orelse return insc;
            if (tag.op > script.OP_16) return insc;
            const val = script.readOp(lock, &pos) orelse return insc;
            if (val.op > script.OP_16) return insc;
            switch (tagOf(tag)) {
                .name => {},
                .number => |n| switch (n) {
                    0 => {
                        insc.content = val.data;
                        break;
                    },
                    1 => if (val.data.len < 256 and std.unicode.utf8ValidateSlice(val.data)) {
                        insc.content_type = val.data;
                    },
                    3 => if (val.data.len == 36) {
                        insc.parent = .{ .txid = val.data[0..32].*, .vout = std.mem.readInt(u32, val.data[32..36], .little) };
                    } else if (val.data.len == 32) {
                        insc.parent = .{ .txid = val.data[0..32].*, .vout = 0 };
                    },
                    else => {},
                },
            }
        }
        const end = pos;
        const after = script.readOp(lock, &pos);
        if (after == null or after.?.op == script.OP_ENDIF) {
            insc.suffix = lock[if (after == null) end else pos..];
            insc.owner = ownerOf(insc.prefix, insc.suffix);
            return insc;
        }
    }
    return null;
}

fn ownerOf(prefix: []const u8, suffix: []const u8) ?[20]u8 {
    const s = if (suffix.len > 0 and suffix[0] == script.OP_CODESEPARATOR) suffix[1..] else suffix;
    if (s.len >= 25) if (script.p2pkh(s[0..25])) |pkh| return pkh;
    if (prefix.len >= 25) return script.p2pkh(prefix[0..25]);
    return null;
}
