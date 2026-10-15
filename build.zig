// skein-1sat (shruggr/skein#151): the 1Sat Ordinals parsers every ordinal
// overlay needs, as one Zig module over bsvz. Zig 0.16.0.
//
// Module (`b.dependency("skein_1sat", .{ .target = t, .optimize = o }).module("onesat")`):
//
//   onesat   inscription, bitcom, map, sigma, ordlock, ordinal     src/lib.zig
//
//   zig build test    the modules against 1sat-stack's vectors, natively
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const bsvz = b.dependency("bsvz", .{ .target = target, .optimize = optimize }).module("bsvz");
    const onesat = b.addModule("onesat", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "bsvz", .module = bsvz }},
    });

    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "onesat", .module = onesat }, .{ .name = "bsvz", .module = bsvz } },
    }) });
    const run = b.addRunArtifact(tests);
    b.step("test", "The modules against 1sat-stack's vectors, natively").dependOn(&run.step);
}
