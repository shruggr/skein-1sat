//! The modules against 1sat-stack's vectors (pkg/template/*/testdata and the
//! cases of its _test.go files), on-chain SIGMA signatures, and hand-built
//! transactions for the ordinal rule.
const std = @import("std");
const onesat = @import("onesat");
const bsvz = @import("bsvz");

const testing = std.testing;
const inscription = onesat.inscription;
const bitcom = onesat.bitcom;
const map = onesat.map;
const sigma = onesat.sigma;
const ordlock = onesat.ordlock;
const ordinal = onesat.ordinal;
const op = onesat.script;

const Transaction = bsvz.transaction.Transaction;

test {
    _ = onesat;
}

// --- helpers --------------------------------------------------------------

/// A locking script built op by op, pushes minimally encoded (go-sdk `AppendPushData`).
const Script = struct {
    buf: std.ArrayList(u8) = .empty,
    a: std.mem.Allocator,

    fn init(a: std.mem.Allocator) Script {
        return .{ .a = a };
    }

    fn ops(self: *Script, codes: []const u8) *Script {
        self.buf.appendSlice(self.a, codes) catch @panic("OOM");
        return self;
    }

    fn push(self: *Script, data: []const u8) *Script {
        const a = self.a;
        if (data.len < op.OP_PUSHDATA1) {
            self.buf.append(a, @intCast(data.len)) catch @panic("OOM");
        } else if (data.len <= 0xff) {
            self.buf.appendSlice(a, &.{ op.OP_PUSHDATA1, @intCast(data.len) }) catch @panic("OOM");
        } else {
            var n: [2]u8 = undefined;
            std.mem.writeInt(u16, &n, @intCast(data.len), .little);
            self.buf.append(a, op.OP_PUSHDATA2) catch @panic("OOM");
            self.buf.appendSlice(a, &n) catch @panic("OOM");
        }
        self.buf.appendSlice(a, data) catch @panic("OOM");
        return self;
    }

    fn bytes(self: *Script) []const u8 {
        return self.buf.items;
    }
};

fn parseTx(a: std.mem.Allocator, comptime txid: []const u8) !Transaction {
    const hex = std.mem.trim(u8, @embedFile("testdata/" ++ txid ++ ".hex"), " \n\r\t");
    const tx = try Transaction.parseHex(a, hex);
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings(txid, displayHex(&buf, (try tx.txid(a)).bytes));
    return tx;
}

fn displayHex(buf: *[64]u8, internal: [32]u8) []const u8 {
    var rev = internal;
    std.mem.reverse(u8, &rev);
    buf.* = std.fmt.bytesToHex(rev, .lower);
    return buf;
}

fn hexAlloc(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn p2pkhLock(pkh: [20]u8) [25]u8 {
    return [_]u8{ op.OP_DUP, op.OP_HASH160, 20 } ++ pkh ++ [_]u8{ op.OP_EQUALVERIFY, op.OP_CHECKSIG };
}

// --- inscription ----------------------------------------------------------

test "inscription: not an envelope (Go TestDecode_InvalidScript)" {
    try testing.expect(inscription.decode(&.{ 0x00, 0x51, 0x52 }) == null);
    try testing.expect(inscription.decode(&.{}) == null);
}

test "inscription: Lock round trip (Go TestRoundTrip_LockDecode)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var s = Script.init(arena.allocator());
    _ = s.ops(&.{ op.OP_0, op.OP_IF }).push("ord").ops(&.{op.OP_1}).push("text/plain")
        .ops(&.{op.OP_0}).push("round trip test content").ops(&.{op.OP_ENDIF});
    const insc = inscription.decode(s.bytes()).?;
    try testing.expectEqualStrings("text/plain", insc.content_type.?);
    try testing.expectEqualStrings("round trip test content", insc.content.?);
    try testing.expectEqual(@as(usize, 0), insc.prefix.len);
    try testing.expectEqual(@as(usize, 0), insc.suffix.len);
    try testing.expect(insc.owner == null);
}

test "inscription: prefix, suffix and the owner after the envelope" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const owner = [_]u8{0x22} ** 20;
    const lock = p2pkhLock(owner);
    var s = Script.init(arena.allocator());
    _ = s.ops(&.{ op.OP_1, op.OP_0, op.OP_IF }).push("ord").ops(&.{op.OP_1}).push("a/b")
        .ops(&.{op.OP_0}).push("x").ops(&.{ op.OP_ENDIF, op.OP_CODESEPARATOR }).ops(&lock);
    const insc = inscription.decode(s.bytes()).?;
    try testing.expectEqualSlices(u8, &.{op.OP_1}, insc.prefix);
    try testing.expectEqual(@as(usize, 26), insc.suffix.len);
    try testing.expectEqualSlices(u8, &owner, &insc.owner.?);
}

test "inscription: the owner before the envelope (1SAT_P2PKH)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const owner = [_]u8{0x33} ** 20;
    var s = Script.init(arena.allocator());
    _ = s.ops(&p2pkhLock(owner)).ops(&.{ op.OP_0, op.OP_IF }).push("ord").ops(&.{op.OP_0}).push("x").ops(&.{op.OP_ENDIF});
    const insc = inscription.decode(s.bytes()).?;
    try testing.expectEqualSlices(u8, &owner, &insc.owner.?);
    try testing.expect(insc.content_type == null);
}

test "inscription: fields, parent, content type rules" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var outpoint: [36]u8 = [_]u8{0xab} ** 32 ++ [_]u8{ 7, 0, 0, 0 };
    var s = Script.init(a);
    _ = s.ops(&.{ op.OP_0, op.OP_IF }).push("ord")
        .ops(&.{op.OP_1}).push("text/plain")
        .push("app").push("first")
        .ops(&.{0x53}).push(&outpoint) // OP_3: parent
        .push(&.{1}).push(&.{ 0xff, 0xfe }) // invalid UTF-8: content type kept
        .push("app").push("second")
        .ops(&.{op.OP_0}).push("body").ops(&.{op.OP_ENDIF});
    const insc = inscription.decode(s.bytes()).?;
    try testing.expectEqualStrings("text/plain", insc.content_type.?);
    try testing.expectEqualStrings("second", insc.field("app").?);
    try testing.expect(insc.field("missing") == null);
    try testing.expectEqualSlices(u8, outpoint[0..32], &insc.parent.?.txid);
    try testing.expectEqual(@as(u32, 7), insc.parent.?.vout);
    var n: usize = 0;
    var it = insc.fields();
    while (it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 5), n);

    var s32 = Script.init(a);
    _ = s32.ops(&.{ op.OP_0, op.OP_IF }).push("ord").ops(&.{0x53}).push(outpoint[0..32]).ops(&.{op.OP_0}).push("b").ops(&.{op.OP_ENDIF});
    try testing.expectEqual(@as(u32, 0), inscription.decode(s32.bytes()).?.parent.?.vout);

    var long = Script.init(a);
    _ = long.ops(&.{ op.OP_0, op.OP_IF }).push("ord").ops(&.{op.OP_1}).push(&([_]u8{'a'} ** 256)).ops(&.{op.OP_0}).push("b").ops(&.{op.OP_ENDIF});
    try testing.expect(inscription.decode(long.bytes()).?.content_type == null);
}

test "inscription: an envelope without content is still one (Go returns it)" {
    // The envelope the Go ordlock tests prepend: OP_FALSE OP_IF "ord" OP_ENDIF.
    const s = [_]u8{ op.OP_0, op.OP_IF, 3, 'o', 'r', 'd', op.OP_ENDIF, op.OP_1 };
    const insc = inscription.decode(&s).?;
    try testing.expect(insc.content == null);
    try testing.expectEqual(@as(usize, 0), insc.suffix.len);
    // Ended by the script's end.
    try testing.expect(inscription.decode(s[0..6]).?.content == null);
}

test "inscription: the walk resumes after an unclosed envelope; a bad push ends it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var s = Script.init(arena.allocator());
    _ = s.ops(&.{ op.OP_0, op.OP_IF }).push("ord").ops(&.{op.OP_0}).push("first").ops(&.{op.OP_1})
        .ops(&.{ op.OP_0, op.OP_IF }).push("ord").ops(&.{op.OP_0}).push("second").ops(&.{op.OP_ENDIF});
    try testing.expectEqualStrings("second", inscription.decode(s.bytes()).?.content.?);
    // "ord" not preceded by OP_0 OP_IF.
    try testing.expect(inscription.decode(&.{ op.OP_1, op.OP_IF, 3, 'o', 'r', 'd', op.OP_0, 1, 'x' }) == null);
    // A truncated push before the envelope.
    try testing.expect(inscription.decode(&.{ op.OP_PUSHDATA1, 200, op.OP_0, op.OP_IF, 3, 'o', 'r', 'd', op.OP_0, 1, 'x' }) == null);
}

test "inscription: vector dfa24771 (BSV-21 deploy+mint, Go bsv21_test)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const tx = try parseTx(arena.allocator(), "dfa24771dbd093efbddf19ec424eab60113e288672c23182be75ec3f5452ba8d");
    const insc = inscription.decode(tx.outputs[0].locking_script.bytes).?;
    try testing.expectEqualStrings("application/bsv-20", insc.content_type.?);
    const json = insc.content.?;
    try testing.expect(std.mem.indexOf(u8, json, "\"deploy+mint\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"BUIDL\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"4200000000\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "df3ceacd1a4169ec7cca3037ca2714f5fcdc0bbdb88ebfd3609257faa4814809_0") != null);
}

test "inscription: vector 34adf92c (collection item: P2PKH, webp, MAP, SIGMA)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const tx = try parseTx(arena.allocator(), "34adf92c766e11a656d3ff3508df7b1a31405821bf734bc9bef9fb43fcf701f9");
    const lock = tx.outputs[0].locking_script.bytes;
    const insc = inscription.decode(lock).?;
    try testing.expectEqualStrings("image/webp", insc.content_type.?);
    try testing.expectEqual(@as(usize, 13750), insc.content.?.len);
    try testing.expectEqual(@as(usize, 25), insc.prefix.len);
    try testing.expectEqualSlices(u8, lock[3..23], &insc.owner.?);
    try testing.expect(bitcom.decode(insc.suffix) != null);
}

// --- bitcom ---------------------------------------------------------------

test "bitcom: no OP_RETURN, no tape (Go TestDecode_NoReturn)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var s = Script.init(arena.allocator());
    _ = s.ops(&.{ op.OP_DUP, op.OP_HASH160 }).push("some address").ops(&.{ op.OP_EQUALVERIFY, op.OP_CHECKSIG });
    try testing.expect(bitcom.decode(s.bytes()) == null);
    try testing.expect(bitcom.decode(&.{}) == null);
}

test "bitcom: where the OP_RETURN is (Go TestFindReturn)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = Script.init(a);
    _ = s.ops(&.{op.OP_RETURN}).push("test data");
    try testing.expectEqual(@as(usize, 0), bitcom.decode(s.bytes()).?.start);
    var s2 = Script.init(a);
    _ = s2.ops(&.{ op.OP_0, op.OP_RETURN }).push("test data2");
    const t2 = bitcom.decode(s2.bytes()).?;
    try testing.expectEqual(@as(usize, 1), t2.start);
    try testing.expectEqualSlices(u8, &.{op.OP_0}, t2.prefix());
    // An OP_RETURN byte inside a push does not start a tape.
    try testing.expect(bitcom.decode(&.{ 1, op.OP_RETURN }) == null);
}

test "bitcom: protocols split on | (Go TestDecode_WithMultipleProtocols, WithNoPipe)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = Script.init(a);
    _ = s.ops(&.{op.OP_RETURN}).push(map.prefix).push("data1").push("|").push("19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut").push("data2");
    var it = bitcom.decode(s.bytes()).?.protocols();
    const p1 = it.next().?;
    try testing.expectEqualStrings(map.prefix, p1.name);
    try testing.expectEqualSlices(u8, "\x05data1", p1.data);
    try testing.expectEqual(@as(usize, 0), p1.separator);
    const p2 = it.next().?;
    try testing.expectEqualStrings("19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut", p2.name);
    try testing.expectEqualSlices(u8, "\x05data2", p2.data);
    try testing.expectEqual(@as(usize, 1 + 35 + 6), p2.separator);
    try testing.expect(it.next() == null);

    var one = Script.init(a);
    _ = one.ops(&.{op.OP_RETURN}).push(map.prefix).push("data");
    var it1 = bitcom.decode(one.bytes()).?.protocols();
    try testing.expectEqualSlices(u8, "\x04data", it1.next().?.data);
    try testing.expect(it1.next() == null);

    // A trailing | opens no protocol; a name that is itself | ends the tape.
    var trail = Script.init(a);
    _ = trail.ops(&.{op.OP_RETURN}).push("A").push("|");
    var it2 = bitcom.decode(trail.bytes()).?.protocols();
    try testing.expectEqualStrings("A", it2.next().?.name);
    try testing.expect(it2.next() == null);
    var pipe = Script.init(a);
    _ = pipe.ops(&.{op.OP_RETURN}).push("|").push("B");
    var it3 = bitcom.decode(pipe.bytes()).?.protocols();
    try testing.expectEqualStrings("|", it3.next().?.name);
    try testing.expect(it3.next() == null);
}

test "bitcom: on-chain B | MAP | AIP posts (Go post_test_vectors)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const names = [_][]const u8{ "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut", map.prefix, "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva" };
    inline for (.{
        .{ "266c2a52d7d1f30709c847424d8195eeef8a0172f190be6244e5c8a1c2e44d94", "twetch" },
        .{ "38c914d2c47c2ff063cf9f5705e3ceaa557aca4092ed5047177d5e8f913c0b69", "retrofeed.me" },
    }) |v| {
        const tx = try parseTx(a, v[0]);
        const tape = bitcom.decode(tx.outputs[0].locking_script.bytes).?;
        var it = tape.protocols();
        for (names) |n| try testing.expectEqualStrings(n, it.next().?.name);
        try testing.expect(it.next() == null);
        const m = (try map.find(a, tape)).?;
        try testing.expectEqualStrings("SET", m.cmd);
        try testing.expectEqualStrings("post", m.get("type").?);
        try testing.expectEqualStrings(v[1], m.get("app").?);
    }
    // 5633bb96: B, then two AIP signatures (Go aip_test).
    const tx = try parseTx(a, "5633bb966d9531d22df7ae98a70966eebe4379d400d74ac948bf5b4f2867092c");
    var it = bitcom.decode(tx.outputs[0].locking_script.bytes).?.protocols();
    try testing.expectEqualStrings(names[0], it.next().?.name);
    try testing.expectEqualStrings(names[2], it.next().?.name);
    try testing.expectEqualStrings(names[2], it.next().?.name);
    try testing.expect(it.next() == null);
}

// --- map ------------------------------------------------------------------

test "map: SET pairs (Go TestDecodeMap)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expect(try map.decode(a, &.{}) == null);
    try testing.expect(try map.decode(a, &.{ 0x00, 0x01 }) == null);

    var s = Script.init(a);
    _ = s.push("SET").push("app").push("bsocial").push("type").push("post");
    const m = (try map.decode(a, s.bytes())).?;
    try testing.expectEqualStrings("SET", m.cmd);
    try testing.expectEqualStrings("bsocial", m.get("app").?);
    try testing.expectEqualStrings("post", m.get("type").?);

    var nul = Script.init(a);
    _ = nul.push("SET").push("key1").push(&.{0x00});
    try testing.expectEqualStrings(" ", (try map.decode(a, nul.bytes())).?.get("key1").?);

    var missing = Script.init(a);
    _ = missing.push("SET").push("key2");
    const mm = (try map.decode(a, missing.bytes())).?;
    try testing.expectEqual(@as(usize, 0), mm.pairs.len);
}

test "map: cleaning, duplicates, other commands (Go TestToScript)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = Script.init(a);
    _ = s.push("SET").push("k\x00ey").push("a\\u0000b\x00").push("dup").push("1").push("dup").push("2");
    const m = (try map.decode(a, s.bytes())).?;
    try testing.expectEqualStrings("a b ", m.get("k ey").?);
    try testing.expectEqualStrings("2", m.get("dup").?);

    var prefixed = Script.init(a);
    _ = prefixed.push(map.prefix).push("SET").push("app").push("bsocial");
    const p = (try map.decode(a, prefixed.bytes())).?;
    try testing.expectEqualStrings(map.prefix, p.cmd);
    try testing.expectEqual(@as(usize, 0), p.pairs.len);
}

test "map: collection item and collection fields (Go pkg/collection mapdata_test)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = Script.init(a);
    _ = s.ops(&.{op.OP_RETURN}).push(map.prefix).push("SET").push("type").push("ord").push("subType").push("collectionItem")
        .push("name").push("Item 1").push("subTypeData").push("{\"collectionId\":\"_0\",\"mintNumber\":3}");
    const m = (try map.find(a, bitcom.decode(s.bytes()).?)).?;
    try testing.expectEqualStrings("collectionItem", m.get("subType").?);
    try testing.expectEqualStrings("Item 1", m.get("name").?);
    try testing.expectEqualStrings("{\"collectionId\":\"_0\",\"mintNumber\":3}", m.get("subTypeData").?);

    var root = Script.init(a);
    _ = root.ops(&.{op.OP_RETURN}).push(map.prefix).push("SET").push("type").push("ord").push("subType").push("collection").push("name").push("Roots");
    const r = (try map.find(a, bitcom.decode(root.bytes()).?)).?;
    try testing.expectEqualStrings("collection", r.get("subType").?);
    try testing.expect(r.get("subTypeData") == null);
}

test "map: vector 34adf92c" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tx = try parseTx(a, "34adf92c766e11a656d3ff3508df7b1a31405821bf734bc9bef9fb43fcf701f9");
    const m = (try map.find(a, bitcom.decode(tx.outputs[0].locking_script.bytes).?)).?;
    try testing.expectEqualStrings("ZoideNFT", m.get("app").?);
    try testing.expectEqualStrings("ord", m.get("type").?);
    try testing.expectEqualStrings("collectionItem", m.get("subType").?);
    try testing.expect(std.mem.indexOf(u8, m.get("subTypeData").?, "\"collectionId\":\"ee8c1a403ad4d9396df261b96f53a30209c2ba419d0e9b41f4930a4602e72cde_0\"") != null);
}

// --- sigma ----------------------------------------------------------------

fn tapeOf(a: std.mem.Allocator, protos: []const []const []const u8) bitcom.Tape {
    var s = Script.init(a);
    _ = s.ops(&.{op.OP_RETURN});
    for (protos, 0..) |p, i| {
        if (i > 0) _ = s.push("|");
        for (p) |d| _ = s.push(d);
    }
    return bitcom.decode(s.bytes()).?;
}

fn collect(a: std.mem.Allocator, tape: bitcom.Tape) ![]sigma.Sigma {
    var out: std.ArrayList(sigma.Sigma) = .empty;
    var it = sigma.iterate(tape);
    while (it.next()) |s| try out.append(a, s);
    return out.items;
}

test "sigma: decoding (Go TestDecodeSIGMA)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqual(@as(usize, 0), (try collect(a, tapeOf(a, &.{ &.{ map.prefix, "some data" }, &.{ "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut", "more data" } }))).len);

    const min = try collect(a, tapeOf(a, &.{&.{ "SIGMA", "ECDSA", "1AddressBTC12345678", "signature1234567890" }}));
    try testing.expectEqual(@as(usize, 1), min.len);
    try testing.expectEqualStrings("ECDSA", min[0].algorithm);
    try testing.expectEqualStrings("1AddressBTC12345678", min[0].address);
    try testing.expectEqualStrings("signature1234567890", min[0].signature);
    try testing.expect(min[0].vin == null and min[0].message == null);

    const all = try collect(a, tapeOf(a, &.{&.{ "SIGMA", "SHA256-ECDSA", "1AddressBTC12345678", "abcdef1234567890", "Hello, world!", "random-nonce-123" }}));
    try testing.expectEqualStrings("SHA256-ECDSA", all[0].algorithm);
    try testing.expectEqualStrings("Hello, world!", all[0].message.?);
    try testing.expectEqualStrings("random-nonce-123", all[0].nonce.?);

    const multi = try collect(a, tapeOf(a, &.{ &.{ "SIGMA", "ECDSA", "1Address1", "signature1" }, &.{ "SIGMA", "SHA256-ECDSA", "1Address2", "signature2" } }));
    try testing.expectEqual(@as(usize, 2), multi.len);
    try testing.expectEqualStrings("1Address1", multi[0].address);
    try testing.expectEqualStrings("1Address2", multi[1].address);

    try testing.expectEqual(@as(usize, 0), (try collect(a, tapeOf(a, &.{&.{ "SIGMA", "ECDSA" }}))).len);

    const msg = try collect(a, tapeOf(a, &.{&.{ "SIGMA", "ECDSA", "1AddressBTC12345678", "binary-signature-data", "This is the message" }}));
    try testing.expectEqualStrings("This is the message", msg[0].message.?);
    try testing.expect(msg[0].nonce == null);

    const vins = try collect(a, tapeOf(a, &.{ &.{ "SIGMA", "BSM", "1A", "s", "0" }, &.{ "SIGMA", "BSM", "1A", "s", "-1" }, &.{ "SIGMA", "BSM", "1A", "s", "12" } }));
    try testing.expectEqual(@as(i64, 0), vins[0].vin.?);
    try testing.expectEqual(@as(i64, -1), vins[1].vin.?);
    try testing.expectEqual(@as(i64, 12), vins[2].vin.?);

    const repaired = try collect(a, tapeOf(a, &.{&.{ "SIGMA", "\x03BSM", "\"1Quoted\"", "s" }}));
    try testing.expectEqualStrings("BSM", repaired[0].algorithm);
    try testing.expectEqualStrings("1Quoted", repaired[0].address);
}

test "sigma: a real-world tape (Go TestWithRealSigmaScripts)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const lock = try hexAlloc(a, "006a055349474d41034253" ++
        "4d2231324b50354b7a6b427774736331557254727342434a7a67714b6e3855716159517141" ++
        "1fa86118c68c274c244148dc9b6d79e4bc812dcfdfebea511cb714a54a2ab2c8fe74472aaf9c87" ++
        "dac70129263467d4601ddd3aeb145b2c204c3c3bb6f41bbcbcf70130");
    const sigs = try collect(a, bitcom.decode(lock).?);
    try testing.expectEqual(@as(usize, 1), sigs.len);
    try testing.expectEqualStrings("BSM", sigs[0].algorithm);
    try testing.expectEqualStrings("12KP5KzkBwtsc1UrTrsBCJzgqKn8UqaYQq", sigs[0].address);
    try testing.expectEqual(@as(i64, 0), sigs[0].vin.?);
    try testing.expectEqualSlices(u8, &.{op.OP_0}, sigs[0].signed);
}

test "sigma: vector 34adf92c decodes and verifies (Go TestDecodeWithSigmaTestVector)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tx = try parseTx(a, "34adf92c766e11a656d3ff3508df7b1a31405821bf734bc9bef9fb43fcf701f9");
    const lock = tx.outputs[0].locking_script.bytes;
    const sigs = try collect(a, bitcom.decode(lock).?);
    try testing.expectEqual(@as(usize, 1), sigs.len);
    const s = sigs[0];
    try testing.expectEqualStrings("BSM", s.algorithm);
    try testing.expectEqualStrings("12KP5KzkBwtsc1UrTrsBCJzgqKn8UqaYQq", s.address);
    var b64: [88]u8 = undefined;
    try testing.expectEqualStrings("H6hhGMaMJ0wkQUjcm2155LyBLc/f6+pRHLcUpUoqssj+dEcqr5yH2scBKSY0Z9RgHd066xRbLCBMPDu29Bu8vPc=", std.base64.standard.Encoder.encode(&b64, s.signature));
    try testing.expectEqual(@as(i64, 0), s.vin.?);
    // The bytes before the `|` that precedes the tape.
    try testing.expectEqual(@as(usize, 14141), s.signed.len);
    try testing.expectEqualSlices(u8, &.{ 0x01, '|', 0x05 }, lock[14141..14144]);

    try testing.expect(try sigma.verify(a, s, &tx, 0));
    try testing.expect((try sigma.firstValid(a, &tx, 0)) != null);
    try testing.expect((try sigma.firstValid(a, &tx, 1)) == null);

    var other = s;
    other.vin = 1; // no input 1: the empty outpoint
    try testing.expect(!try sigma.verify(a, other, &tx, 0));
    other = s;
    other.signed = lock[0..14140];
    try testing.expect(!try sigma.verify(a, other, &tx, 0));
    other = s;
    other.address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    try testing.expect(!try sigma.verify(a, other, &tx, 0));
    other = s;
    other.algorithm = "BRC77";
    try testing.expect(!try sigma.verify(a, other, &tx, 0));
}

/// Appends a SIGMA by `key` to output `vout`, as 1sat-sdk's `Sigma.sign` does.
fn signOutput(a: std.mem.Allocator, tx: *Transaction, vout: usize, key: bsvz.crypto.PrivateKey, vin: i64) !void {
    const outputs = try a.dupe(bsvz.transaction.Output, tx.outputs);
    const lock = outputs[vout].locking_script.bytes;
    const has_tape = bitcom.decode(lock) != null;
    var s = Script.init(a);
    _ = s.ops(lock);
    if (has_tape) _ = s.push("|") else _ = s.ops(&.{op.OP_RETURN});
    const unsigned: sigma.Sigma = .{ .algorithm = "BSM", .address = "", .signature = "", .vin = vin, .signed = lock };
    const msg = sigma.message(unsigned, tx, @intCast(vout));
    const sig = try bsvz.compat.bsm.signMessage(key, &msg, a);
    const addr = try bsvz.compat.address.encodeP2pkhFromPublicKey(a, .mainnet, try key.publicKey());
    var vin_buf: [24]u8 = undefined;
    const resolved = if (vin == -1) @as(i64, @intCast(vout)) else vin;
    _ = s.push("SIGMA").push("BSM").push(addr).push(&sig).push(try std.fmt.bufPrint(&vin_buf, "{d}", .{resolved}));
    outputs[vout].locking_script = bsvz.script.Script.init(s.bytes());
    tx.outputs = outputs;
}

fn keyOf(n: u8) !bsvz.crypto.PrivateKey {
    var kb = [_]u8{0} ** 32;
    kb[31] = n;
    return bsvz.crypto.PrivateKey.fromBytes(kb);
}

test "sigma: sign and verify, user then platform signature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = Script.init(a);
    _ = s.ops(&p2pkhLock([_]u8{0x44} ** 20)).ops(&.{ op.OP_0, op.OP_IF }).push("ord").ops(&.{op.OP_1}).push("text/plain")
        .ops(&.{op.OP_0}).push("hello").ops(&.{op.OP_ENDIF}).ops(&.{op.OP_RETURN}).push(map.prefix).push("SET").push("type").push("ord");
    const inputs = [_]bsvz.transaction.Input{
        .{ .previous_outpoint = .{ .txid = .{ .bytes = [_]u8{0x01} ** 32 }, .index = 2 }, .unlocking_script = .empty(), .sequence = 0xffffffff },
        .{ .previous_outpoint = .{ .txid = .{ .bytes = [_]u8{0x02} ** 32 }, .index = 0 }, .unlocking_script = .empty(), .sequence = 0xffffffff },
    };
    const outputs = [_]bsvz.transaction.Output{
        .{ .satoshis = 1000, .locking_script = .init(&p2pkhLock([_]u8{0x55} ** 20)) },
        .{ .satoshis = 1, .locking_script = .init(s.bytes()) },
    };
    var tx: Transaction = .{ .version = 1, .inputs = &inputs, .outputs = &outputs, .lock_time = 0 };

    const user = try keyOf(1);
    const platform = try keyOf(2);
    try signOutput(a, &tx, 1, user, 0);
    try signOutput(a, &tx, 1, platform, -1);

    const sigs = try collect(a, bitcom.decode(tx.outputs[1].locking_script.bytes).?);
    try testing.expectEqual(@as(usize, 2), sigs.len);
    try testing.expectEqual(@as(i64, 1), sigs[1].vin.?); // -1 is written as the output's index
    try testing.expect(sigs[1].signed.len > sigs[0].signed.len); // the platform signs over the user's SIGMA
    try testing.expect(try sigma.verify(a, sigs[0], &tx, 1));
    try testing.expect(try sigma.verify(a, sigs[1], &tx, 1));
    try testing.expectEqualStrings(sigs[0].address, (try sigma.firstValid(a, &tx, 1)).?.address);

    // Changing the hashed inputs breaks both.
    var moved = tx;
    var ins = inputs;
    ins[0].previous_outpoint.index = 3;
    ins[1].previous_outpoint.index = 9;
    moved.inputs = &ins;
    try testing.expect(!try sigma.verify(a, sigs[0], &moved, 1));
    try testing.expect(!try sigma.verify(a, sigs[1], &moved, 1));
}

// --- ordlock --------------------------------------------------------------

// Canonical v2 listing (Go ordlock_v2_test `v2ListingHex`): seller PKH 0x11..,
// payout P2PKH 0x22.. for 1000 sats.
const v2_listing_hex = "76009c637576ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01c37e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad6922e8030000000000001976a914222222222222222222222222222222222222222288acaa7c820128947f7701207f758767519d7b0a6f6c323a63616e63656c8876a914111111111111111111111111111111111111111188ac68";

test "ordlock: the canonical v2 listing (Go TestDecodeV2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const lock = try hexAlloc(arena.allocator(), v2_listing_hex);
    try testing.expectEqual(@as(usize, 472), ordlock.template.len);
    try testing.expectEqual(@as(usize, 436), ordlock.prefix.len);
    try testing.expectEqual(@as(u8, op.OP_CODESEPARATOR), ordlock.template[ordlock.code_separator_index]);
    const l = ordlock.decode(lock).?;
    try testing.expectEqualSlices(u8, &([_]u8{0x11} ** 20), &l.seller);
    try testing.expectEqual(@as(u64, 1000), l.price);
    try testing.expectEqualSlices(u8, &p2pkhLock([_]u8{0x22} ** 20), l.pay_script);
    try testing.expectEqual(@as(usize, 8 + 1 + 25), l.pay_output.len);
    try testing.expectEqual(@as(usize, 0), l.start);
}

test "ordlock: not v2 (Go TestDecodeV2RejectsV1AndP2PKH, v1 vector 690b2131)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expect(ordlock.decode(&p2pkhLock([_]u8{0} ** 20)) == null);
    const tx = try parseTx(a, "690b213114926cd5a6f0785cb3e289afe9cde195972c1d344569c90530b8cbd1");
    try testing.expectEqual(@as(usize, 3), tx.outputs.len);
    for (tx.outputs) |o| try testing.expect(ordlock.decode(o.locking_script.bytes) == null);
}

test "ordlock: the whole template must match (Go TestV2RecognitionRequiresCompleteTemplate)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const valid = try hexAlloc(a, v2_listing_hex);
    const changed = try a.dupe(u8, valid);
    changed[changed.len - 1] = 0x00;
    for ([_][]const u8{ &.{}, ordlock.prefix, &ordlock.template, valid[0 .. valid.len - 1], changed }) |s| {
        try testing.expect(ordlock.decode(s) == null);
    }
    // A seller slot of 19 bytes.
    const short = try std.mem.concat(a, u8, &.{ valid[0 .. valid.len - 24], &[_]u8{19}, &([_]u8{0x11} ** 19), valid[valid.len - 3 ..] });
    try testing.expect(ordlock.decode(short) == null);
}

test "ordlock: surrounding data is ignored (Go TestV2RecognitionIgnoresSurroundingData)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const valid = try hexAlloc(a, v2_listing_hex);
    var trailer = Script.init(a);
    _ = trailer.ops(&.{op.OP_RETURN}).push(map.prefix).push("SET").push("app").push("test");
    const envelope = [_]u8{ op.OP_0, op.OP_IF, 3, 'o', 'r', 'd', op.OP_ENDIF };
    for ([_][]const u8{
        try std.mem.concat(a, u8, &.{ valid, &[_]u8{0x00} }),
        try std.mem.concat(a, u8, &.{ valid, trailer.bytes() }),
        try std.mem.concat(a, u8, &.{ &envelope, valid }),
    }) |s| {
        const l = ordlock.decode(s).?;
        try testing.expectEqualSlices(u8, &([_]u8{0x11} ** 20), &l.seller);
        try testing.expectEqual(@as(u64, 1000), l.price);
    }
    try testing.expectEqual(@as(usize, envelope.len), ordlock.decode(try std.mem.concat(a, u8, &.{ &envelope, valid })).?.start);
}

test "ordlock: purchase or cancel by the branch selector (Go classifySpend)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var purchase = Script.init(a);
    _ = purchase.push(&([_]u8{0xaa} ** 200)).ops(&.{op.OP_0});
    try testing.expectEqual(ordlock.Spend.purchase, ordlock.classify(purchase.bytes()).?);
    var cancel = Script.init(a);
    _ = cancel.push("ol2:cancel").push(&([_]u8{0x30} ** 71)).push(&([_]u8{0x02} ** 33)).ops(&.{op.OP_1});
    try testing.expectEqual(ordlock.Spend.cancel, ordlock.classify(cancel.bytes()).?);
    try testing.expect(ordlock.classify(&.{}) == null);
    try testing.expect(ordlock.classify(&.{ 1, 0x02 }) == null);
}

// --- ordinal --------------------------------------------------------------

/// A transaction whose inputs spend outputs of `in_sats` satoshis (null: source
/// unknown) and whose outputs hold `out_sats`.
fn ordTx(a: std.mem.Allocator, in_sats: []const ?i64, out_sats: []const i64) !Transaction {
    const inputs = try a.alloc(bsvz.transaction.Input, in_sats.len);
    for (inputs, in_sats, 0..) |*in, s, i| {
        in.* = .{ .previous_outpoint = .{ .txid = .{ .bytes = [_]u8{@intCast(i)} ** 32 }, .index = 0 }, .unlocking_script = .empty(), .sequence = 0 };
        if (s) |n| in.source_output = .{ .satoshis = n, .locking_script = .empty() };
    }
    const outputs = try a.alloc(bsvz.transaction.Output, out_sats.len);
    for (outputs, out_sats) |*o, n| o.* = .{ .satoshis = n, .locking_script = .empty() };
    return .{ .version = 1, .inputs = inputs, .outputs = outputs, .lock_time = 0 };
}

test "ordinal: output, the position rule and its null cases" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const Case = struct { in: []const ?i64, out: []const i64, vin: u32, want: ?u32 };
    const cases = [_]Case{
        // A plain transfer: 1-sat input first, 1-sat output first.
        .{ .in = &.{ 1, 1000 }, .out = &.{ 1, 900 }, .vin = 0, .want = 0 },
        // Funding before the ordinal shifts it: offset 1000.
        .{ .in = &.{ 1000, 1 }, .out = &.{ 1000, 1, 50 }, .vin = 1, .want = 1 },
        // Zero-satoshi outputs are skipped.
        .{ .in = &.{ 1, 1000 }, .out = &.{ 0, 1, 900 }, .vin = 0, .want = 1 },
        .{ .in = &.{ 1000, 1 }, .out = &.{ 500, 0, 500, 1 }, .vin = 1, .want = 3 },
        // Absorbed into a multi-sat output.
        .{ .in = &.{ 1, 1000 }, .out = &.{901}, .vin = 0, .want = null },
        .{ .in = &.{ 1000, 1 }, .out = &.{ 999, 2 }, .vin = 1, .want = null },
        // The input is not a single satoshi.
        .{ .in = &.{ 2, 1000 }, .out = &.{ 1, 1 }, .vin = 0, .want = null },
        // Past the outputs: the fee.
        .{ .in = &.{ 1000, 1 }, .out = &.{900}, .vin = 1, .want = null },
        .{ .in = &.{ 1000, 1 }, .out = &.{}, .vin = 1, .want = null },
        // The offset lands on an output boundary after several outputs.
        .{ .in = &.{ 3, 1 }, .out = &.{ 2, 1, 1 }, .vin = 1, .want = 2 },
    };
    for (cases) |c| {
        const tx = try ordTx(a, c.in, c.out);
        try testing.expectEqual(c.want, try ordinal.output(&tx, c.vin, ordinal.Hydrated{ .tx = &tx }));
    }
}

test "ordinal: output errors (out of range, missing source outputs)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tx = try ordTx(a, &.{ 1000, null, 1 }, &.{ 1000, 1 });
    const src = ordinal.Hydrated{ .tx = &tx };
    try testing.expectError(error.OutOfRange, ordinal.output(&tx, 3, src));
    // An input before the ordinal's is unknown: its offset cannot be found.
    try testing.expectError(error.MissingSourceOutput, ordinal.output(&tx, 2, src));
    // The ordinal's own source is unknown.
    try testing.expectError(error.MissingSourceOutput, ordinal.output(&tx, 1, src));
    // Inputs after it are not needed.
    const later = try ordTx(a, &.{ 1, null }, &.{ 1, 5 });
    try testing.expectEqual(@as(?u32, 0), try ordinal.output(&later, 0, ordinal.Hydrated{ .tx = &later }));
}

test "ordinal: input, the reverse rule and its null cases" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const Case = struct { in: []const ?i64, out: []const i64, vout: u32, want: ?u32 };
    const cases = [_]Case{
        .{ .in = &.{ 1, 1000 }, .out = &.{ 1, 900 }, .vout = 0, .want = 0 },
        .{ .in = &.{ 1000, 1 }, .out = &.{ 1000, 1, 50 }, .vout = 1, .want = 1 },
        // A fresh inscription: the satoshi comes from a multi-sat input.
        .{ .in = &.{1000}, .out = &.{ 1, 900 }, .vout = 0, .want = null },
        // The output is not a single satoshi.
        .{ .in = &.{ 1, 1000 }, .out = &.{ 2, 900 }, .vout = 0, .want = null },
        // Past the inputs.
        .{ .in = &.{1}, .out = &.{ 1, 1 }, .vout = 1, .want = null },
        // Zero-satoshi outputs count toward nothing.
        .{ .in = &.{ 1, 1000 }, .out = &.{ 0, 1 }, .vout = 1, .want = 0 },
    };
    for (cases) |c| {
        const tx = try ordTx(a, c.in, c.out);
        try testing.expectEqual(c.want, try ordinal.input(&tx, c.vout, ordinal.Hydrated{ .tx = &tx }));
    }
    const tx = try ordTx(a, &.{ 1000, null }, &.{ 1000, 1 });
    try testing.expectError(error.OutOfRange, ordinal.input(&tx, 2, ordinal.Hydrated{ .tx = &tx }));
    try testing.expectError(error.MissingSourceOutput, ordinal.input(&tx, 1, ordinal.Hydrated{ .tx = &tx }));
}

test "ordinal: sources from a caller (a topic call's sourceOutput)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tx = try ordTx(a, &.{ null, null }, &.{ 5, 1 });
    const Lookup = struct {
        pub fn sourceOutput(_: @This(), i: usize) ?bsvz.transaction.Output {
            return .{ .satoshis = if (i == 0) 5 else 1, .locking_script = .empty() };
        }
    };
    try testing.expectEqual(@as(?u32, 1), try ordinal.output(&tx, 1, Lookup{}));
    try testing.expectEqual(@as(?u32, 1), try ordinal.input(&tx, 1, Lookup{}));
}
