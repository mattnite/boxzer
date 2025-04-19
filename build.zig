const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const eggzon_dep = b.dependency("eggzon", .{
        .target = target,
        .optimize = optimize,
    });

    const boxzer_mod = b.addModule("boxzer", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    boxzer_mod.addImport("eggzon", eggzon_dep.module("eggzon"));

    const boxzer_exe = b.addExecutable(.{
        .name = "boxzer",
        .root_module = boxzer_mod,
    });
    b.installArtifact(boxzer_exe);

    const run_cmd = b.addRunArtifact(boxzer_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
