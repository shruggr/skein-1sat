//! The Bitcom tape: the data after a locking script's first `OP_RETURN`,
//! split into protocols on `|`, read as 1sat-stack reads it
//! (pkg/template/bitcom `Decode`).
//!
//! - The script is walked op by op for the first `OP_RETURN` op (pushed bytes
//!   are skipped, so an inscription's content never starts a tape). None, or
//!   a malformed push before one: no tape.
//! - Each protocol is a name (the first op's pushed bytes) and the script
//!   bytes after it up to the next `|` separator, the one-byte direct push
//!   `01 7c`, or to the end of the script.
//! - A malformed op where a name should be ends the tape there; a protocol
//!   whose name op is itself a `|` ends it too (empty data).
const std = @import("std");
const script = @import("script.zig");

pub const Protocol = struct {
    /// The protocol's identifier: a Bitcom address (MAP's
    /// `1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5`) or a name (`SIGMA`).
    name: []const u8,
    /// The script bytes after the name, up to the next `|`.
    data: []const u8,
    /// Where the separator before this protocol starts in the locking script:
    /// the `OP_RETURN` for the first protocol, the `|` push for the others.
    /// The bytes before it are what a SIGMA in this protocol signs.
    separator: usize,
};

pub const Tape = struct {
    lock: []const u8,
    /// The offset of the `OP_RETURN`.
    start: usize,

    /// The locking script before the `OP_RETURN`.
    pub fn prefix(self: Tape) []const u8 {
        return self.lock[0..self.start];
    }

    pub fn protocols(self: Tape) Protocols {
        return .{ .lock = self.lock, .pos = self.start + 1, .separator = self.start };
    }

    /// The first protocol named `name`.
    pub fn find(self: Tape, name: []const u8) ?Protocol {
        var it = self.protocols();
        while (it.next()) |p| if (std.mem.eql(u8, p.name, name)) return p;
        return null;
    }
};

pub const Protocols = struct {
    lock: []const u8,
    pos: usize,
    separator: usize,
    done: bool = false,

    pub fn next(self: *Protocols) ?Protocol {
        if (self.done or self.pos >= self.lock.len) return null;
        const pipe = findPipe(self.lock, self.pos);
        const name = script.readOp(self.lock, &self.pos) orelse {
            self.done = true;
            return null;
        };
        var p: Protocol = .{ .name = name.data, .data = &.{}, .separator = self.separator };
        if (pipe) |at| {
            if (at < self.pos) {
                self.done = true;
            } else {
                p.data = self.lock[self.pos..at];
                self.separator = at;
                self.pos = at + 2;
            }
        } else {
            p.data = self.lock[self.pos..];
            self.done = true;
        }
        return p;
    }
};

/// The Bitcom tape of `lock`, or null when it has no `OP_RETURN`.
pub fn decode(lock: []const u8) ?Tape {
    var pos: usize = 0;
    while (script.readOp(lock, &pos)) |op| {
        if (op.op == script.OP_RETURN) return .{ .lock = lock, .start = op.start };
    }
    return null;
}

fn findPipe(lock: []const u8, from: usize) ?usize {
    var pos = from;
    while (script.readOp(lock, &pos)) |op| {
        if (op.op == 0x01 and op.data[0] == '|') return op.start;
    }
    return null;
}
