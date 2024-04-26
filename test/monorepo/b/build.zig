const std = @import("std");

pub fn build(b: *std.Build) void {
    const c_dep = b.dependency("c", .{});
    _ = b.addModule("b", .{
        .root_source_file = .{ .path = "src/main.zig" },
        .imports = &.{
            .{
                .name = "c",
                .module = c_dep.module("c"),
            },
        },
    });
}
