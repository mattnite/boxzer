const std = @import("std");

const Manifest = @import("Manifest.zig");
const Archive = @import("Archive.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();

    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);

    const base_url = args[1];

    var todo = std.StringArrayHashMap(void).init(allocator);
    var manifests = std.StringArrayHashMap(Manifest).init(allocator);
    var dependencies = std.StringArrayHashMap(std.StringArrayHashMapUnmanaged([]const u8)).init(allocator);

    try todo.put(try std.fs.cwd().realpathAlloc(allocator, "."), {});
    while (todo.count() > 0) {
        // pop entries from todo until it's ones we haven't visited
        const root_path = while (todo.popOrNull()) |entry| {
            if (!manifests.contains(entry.key))
                break entry.key;
        } else continue;

        var root_dir = try std.fs.openDirAbsolute(root_path, .{});
        defer root_dir.close();

        const zon_text = try root_dir.readFileAlloc(allocator, "build.zig.zon", 0x4000);
        const manifest = try Manifest.from_text(allocator, zon_text);
        try manifests.putNoClobber(root_path, manifest);
        std.log.info("created manifest: {s}", .{root_path});

        const result = try dependencies.getOrPut(root_path);
        std.debug.assert(!result.found_existing);

        result.value_ptr.* = .{};

        for (manifest.dependencies.keys(), manifest.dependencies.values()) |dep_name, dep|
            switch (dep) {
                .local => |local| {
                    const realpath = try root_dir.realpathAlloc(allocator, local.path);
                    try todo.put(realpath, {});
                    try result.value_ptr.put(allocator, dep_name, realpath);
                },
                .remote => {},
            };
    }

    const root_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    var depths = std.StringArrayHashMap(u32).init(allocator);
    for (manifests.keys()) |path|
        try depths.put(path, 0);

    // calculate the depths of all the packages
    {
        var changes_made = true;
        while (changes_made) {
            changes_made = false;
            for (depths.keys(), depths.values()) |path, depth| {
                for (dependencies.get(path).?.values()) |dep_path| {
                    const dep_depth = depths.get(dep_path).?;
                    if (dep_depth <= depth) {
                        try depths.put(dep_path, depth + 1);
                        changes_made = true;
                    }
                }
            }
        }
    }

    var archives = std.StringArrayHashMap(Archive).init(allocator);
    var hashes = std.StringArrayHashMap(Archive.MultiHashHexDigest).init(allocator);
    var urls = std.StringArrayHashMap([]const u8).init(allocator);

    var d: isize = @intCast(std.mem.max(u32, depths.values()));
    const root_manifest = manifests.get(root_path).?;
    while (d > -1) : (d -= 1) {
        for (depths.keys(), depths.values()) |path, depth| {
            if (d == depth) {
                const local_deps = dependencies.get(path).?;
                var manifest = manifests.get(path).?;
                for (local_deps.keys(), local_deps.values()) |dep_name, dep_path| {
                    try manifest.dependencies.put(dep_name, .{
                        .remote = .{
                            .url = urls.get(dep_path).?,
                            .hash = try std.fmt.allocPrint(allocator, "{s}", .{&hashes.get(dep_path).?}),
                        },
                    });
                }

                var dir = try std.fs.openDirAbsolute(path, .{ .iterate = true });
                defer dir.close();

                var archive = try Archive.read_from_fs(allocator, dir, manifest.paths);
                if (archive.files.getPtr("build.zig.zon")) |file|
                    file.text = try manifest.serialize(allocator);
                try hashes.put(path, try archive.hash(allocator, .ignore_executable_bit));
                try archives.put(path, archive);
                try urls.put(path, try std.fmt.allocPrint(allocator, "{s}/{s}-{}/{s}-{}.tar.gz", .{
                    base_url,
                    root_manifest.name,
                    root_manifest.version,
                    manifest.name,
                    manifest.version,
                }));
            }
        }
    }

    try std.fs.cwd().deleteTree("boxzer-out");
    var out_dir = try std.fs.cwd().makeOpenPath("boxzer-out", .{});
    defer out_dir.close();

    for (manifests.keys(), manifests.values()) |path, manifest| {
        const file = if (std.mem.eql(u8, path, root_path)) blk: {
            const out_path = try std.fmt.allocPrint(allocator, "{s}-{}.tar.gz", .{ manifest.name, manifest.version });
            break :blk try out_dir.createFile(out_path, .{});
        } else blk: {
            const out_path = try std.fmt.allocPrint(allocator, "{s}-{}/{s}-{}.tar.gz", .{
                root_manifest.name,
                root_manifest.version,
                manifest.name,
                manifest.version,
            });

            var dir = try out_dir.makeOpenPath(std.fs.path.dirname(out_path).?, .{});
            defer dir.close();

            break :blk try dir.createFile(std.fs.path.basename(out_path), .{});
        };
        defer file.close();

        std.log.debug("archive path: {s}", .{path});
        const name = try std.fmt.allocPrint(allocator, "{s}-{}", .{ manifest.name, manifest.version });
        const tar_gz = try archives.get(path).?.to_tar_gz(allocator, name);
        var buffered = std.io.bufferedWriter(file.writer());
        try buffered.writer().writeAll(tar_gz);
        try buffered.flush();

        std.log.info("{s}: {}", .{ path, manifest });
    }
}
