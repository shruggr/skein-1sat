//! SIGMA signatures in a Bitcom tape (protocol name `SIGMA`): decoding as
//! 1sat-stack reads them (pkg/template/bitcom `DecodeSIGMA`), verifying as
//! the on-chain signer (sigma-protocol) signs, over bsvz `compat/bsm`.
//!
//! Fields, in order: algorithm, signer address, signature (65-byte compact
//! BSM), then optionally `vin`. A protocol missing any of the first three is
//! skipped. Go's two repairs are kept: an algorithm push starting with `0x03`
//! drops that byte, an address push starting with `"` drops the first and
//! last bytes.
//!
//! The fourth field is `vin` when it is a decimal integer (the signer writes
//! `String(vin)`, so `-1` and multi-digit indices occur); otherwise it is a
//! message and a fifth a nonce (decoded, not verified).
//!
//! Verification as 1sat-sdk's templates `Sigma.verifyTransaction` does
//! (docs.1satordinals.com "Signing"): the signed message is
//!
//!     sha256(sha256(outpoint of input vin) || sha256(script before the tape))
//!
//! where the outpoint is the input's txid in display order (reversed from the
//! transaction's bytes) then its index little-endian, "script before the
//! tape" is the locking script up to the separator (`OP_RETURN` or `|`)
//! preceding this SIGMA. `vin` -1 means the index of the output being signed,
//! absent means 0; when no input has that index the input hash is the
//! SHA-256 of 32 zero bytes. The
//! signature is checked with Bitcoin Signed Message over that 32-byte
//! message: the recovered key (compressed or not, as the signature says) must
//! give the signer's mainnet address. Algorithms `BSM`, `ECDSA` and
//! `SHA256-ECDSA` all verify this way; any other does not verify.
//!
//! 1sat-stack (and go-sigma) hash the txid in internal order and use
//! sha256d for the outer hash; signatures made by 1sat-sdk and the on-chain
//! vectors do not verify that way.
const std = @import("std");
const bsvz = @import("bsvz");
const script = @import("script.zig");
const bitcom = @import("bitcom.zig");

pub const name = "SIGMA";

pub const Sigma = struct {
    algorithm: []const u8,
    address: []const u8,
    signature: []const u8,
    vin: ?i64 = null,
    message: ?[]const u8 = null,
    nonce: ?[]const u8 = null,
    /// The locking script bytes this signature covers.
    signed: []const u8,
};

pub const Iterator = struct {
    protocols: bitcom.Protocols,

    pub fn next(self: *Iterator) ?Sigma {
        while (self.protocols.next()) |p| {
            if (!std.mem.eql(u8, p.name, name)) continue;
            if (decodeOne(p, self.protocols.lock)) |s| return s;
        }
        return null;
    }
};

/// The SIGMA entries of a tape, in order.
pub fn iterate(tape: bitcom.Tape) Iterator {
    return .{ .protocols = tape.protocols() };
}

fn decodeOne(p: bitcom.Protocol, lock: []const u8) ?Sigma {
    var pos: usize = 0;
    const algo = script.readOp(p.data, &pos) orelse return null;
    const addr = script.readOp(p.data, &pos) orelse return null;
    const sig = script.readOp(p.data, &pos) orelse return null;
    var s: Sigma = .{
        .algorithm = if (algo.data.len > 1 and algo.data[0] == 0x03) algo.data[1..] else algo.data,
        .address = if (addr.data.len > 1 and addr.data[0] == '"') addr.data[1 .. addr.data.len - 1] else addr.data,
        .signature = sig.data,
        .signed = lock[0..p.separator],
    };
    if (script.readOp(p.data, &pos)) |f| {
        if (parseVin(f.data)) |v| {
            s.vin = v;
        } else {
            s.message = f.data;
            if (script.readOp(p.data, &pos)) |n| s.nonce = n.data;
        }
    }
    return s;
}

fn parseVin(s: []const u8) ?i64 {
    const digits = if (s.len > 1 and s[0] == '-') s[1..] else s;
    if (digits.len == 0) return null;
    for (digits) |c| if (!std.ascii.isDigit(c)) return null;
    return std.fmt.parseInt(i64, s, 10) catch null;
}

/// The 32-byte message `s` signs, as output `vout` of `tx`.
pub fn message(s: Sigma, tx: *const bsvz.transaction.Transaction, vout: u32) [32]u8 {
    const vin = s.vin orelse 0;
    const index: i64 = if (vin == -1) vout else vin;
    var hashes: [64]u8 = undefined;
    if (index >= 0 and index < tx.inputs.len) {
        const prev = tx.inputs[@intCast(index)].previous_outpoint;
        var outpoint: [36]u8 = undefined;
        outpoint[0..32].* = prev.txid.bytes;
        std.mem.reverse(u8, outpoint[0..32]);
        std.mem.writeInt(u32, outpoint[32..36], prev.index, .little);
        hashes[0..32].* = bsvz.crypto.hash.sha256(&outpoint).bytes;
    } else {
        hashes[0..32].* = bsvz.crypto.hash.sha256(&([_]u8{0} ** 32)).bytes;
    }
    hashes[32..64].* = bsvz.crypto.hash.sha256(s.signed).bytes;
    return bsvz.crypto.hash.sha256(&hashes).bytes;
}

/// Whether `s`, found in output `vout` of `tx`, is a valid signature by its address.
pub fn verify(a: std.mem.Allocator, s: Sigma, tx: *const bsvz.transaction.Transaction, vout: u32) error{OutOfMemory}!bool {
    const known = [_][]const u8{ "BSM", "ECDSA", "SHA256-ECDSA" };
    for (known) |k| {
        if (std.mem.eql(u8, s.algorithm, k)) break;
    } else return false;
    if (s.signature.len != bsvz.crypto.compact_sig_len) return false;
    const msg = message(s, tx, vout);
    const rec = bsvz.compat.bsm.recoverPubkey(s.signature[0..bsvz.crypto.compact_sig_len].*, &msg, a) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    const pkh = if (rec.is_compressed)
        bsvz.crypto.hash.hash160(&rec.pubkey.toCompressedSec1())
    else
        bsvz.crypto.hash.hash160(&rec.pubkey.toUncompressedSec1());
    const expected = try bsvz.compat.address.encodeP2pkh(a, .mainnet, pkh);
    defer a.free(expected);
    return std.mem.eql(u8, expected, s.address);
}

/// The first SIGMA in output `vout` of `tx` that verifies (1sat-stack
/// pkg/collection `FirstValidSigma`), or null.
pub fn firstValid(a: std.mem.Allocator, tx: *const bsvz.transaction.Transaction, vout: u32) error{OutOfMemory}!?Sigma {
    if (vout >= tx.outputs.len) return null;
    const tape = bitcom.decode(tx.outputs[vout].locking_script.bytes) orelse return null;
    var it = iterate(tape);
    while (it.next()) |s| {
        if (s.address.len == 0 or s.signature.len == 0) continue;
        if (try verify(a, s, tx, vout)) return s;
    }
    return null;
}
