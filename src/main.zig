const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

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
        std.log.debug("created manifest: {s}", .{root_path});

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
    var stack = try circular_dependency_found(allocator, root_path, dependencies);
    defer stack.deinit();

    if (stack.items.len > 0) {
        std.log.err("Circular dependency found!", .{});
        std.log.err("  {s}", .{stack.items[0]});
        for (stack.items[1..]) |elem|
            std.log.err("  -> {s}", .{elem});

        return error.CircularDependency;
    }

    const depths = try calculate_depths(allocator, manifests.keys(), dependencies);
    for (depths.keys(), depths.values()) |path, depth| {
        std.log.info("{}: {s}", .{ depth, path });
    }

    var archives = std.StringArrayHashMap(Archive).init(allocator);
    var hashes = std.StringArrayHashMap(Archive.MultiHashHexDigest).init(allocator);
    var urls = std.StringArrayHashMap([]const u8).init(allocator);

    const root_manifest = manifests.get(root_path).?;
    // calculate urls
    for (manifests.keys(), manifests.values()) |path, manifest| {
        try urls.put(path, try std.fmt.allocPrint(allocator, "{s}/{s}-{}/{s}-{}.tar.gz", .{
            base_url,
            root_manifest.name,
            root_manifest.version,
            manifest.name,
            manifest.version,
        }));
    }

    const minimum_zig_version: []const u8 = try get_minimum_zig_version(allocator);
    var d: isize = @intCast(std.mem.max(u32, depths.values()));
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
                if (archive.files.getPtr("build.zig.zon")) |file| {
                    file.text = try manifest.serialize(allocator, .{
                        .minimum_zig_version = minimum_zig_version,
                    });
                    std.log.info("generated manifest: {s}", .{file.text});
                }
                try hashes.put(path, try archive.hash(allocator, .ignore_executable_bit));
                try archives.put(path, archive);
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
    }
}

const ZigEnv = struct {
    version: []const u8,
};

fn get_minimum_zig_version(allocator: Allocator) ![]u8 {
    const result = try std.ChildProcess.run(.{
        .allocator = allocator,
        .argv = &.{ "zig", "env" },
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    if (result.term != .Exited and result.term.Exited != 0)
        return error.FailedToGetZigVersion;

    var env = try std.json.parseFromSlice(ZigEnv, allocator, result.stdout, .{
        .ignore_unknown_fields = true,
    });
    defer env.deinit();

    return allocator.dupe(u8, env.value.version);
}

fn calculate_depths(
    allocator: Allocator,
    paths: []const []const u8,
    dependencies: std.StringArrayHashMap(std.StringArrayHashMapUnmanaged([]const u8)),
) !std.StringArrayHashMap(u32) {
    var dependents = std.StringArrayHashMap(std.StringArrayHashMapUnmanaged(void)).init(allocator);
    defer {
        //for (dependents.values()) |*d| d.deinit();
        dependents.deinit();
    }

    for (paths) |path| if (dependencies.get(path)) |deps| {
        for (deps.values()) |dep_path| {
            const result = try dependents.getOrPut(dep_path);
            if (result.found_existing == false)
                result.value_ptr.* = .{};

            try result.value_ptr.put(allocator, path, {});
        }
    };

    for (dependents.keys(), dependents.values()) |path, parents| {
        std.log.info("{s} is depended on by {}", .{ path, parents.count() });
    }

    var depths = std.StringArrayHashMap(u32).init(allocator);
    errdefer depths.deinit();

    for (paths) |path|
        try calculate_depths_recursive(path, &depths, dependents);

    return depths;
}

// walk up the dependency tree and calculate depths of each node
fn calculate_depths_recursive(
    path: []const u8,
    depths: *std.StringArrayHashMap(u32),
    dependents: std.StringArrayHashMap(std.StringArrayHashMapUnmanaged(void)),
) !void {
    // if the depth for a path is found, then we've already calculated it
    if (depths.contains(path))
        return;

    const parents = dependents.get(path) orelse {
        // we've found the root path
        try depths.put(path, 0);
        return;
    };

    var max_depth: u32 = 0;
    for (parents.keys()) |parent_path| {
        try calculate_depths_recursive(parent_path, depths, dependents);
        max_depth = @max(max_depth, depths.get(parent_path).?);
    }

    try depths.put(path, max_depth + 1);
}

fn circular_dependency_found(
    allocator: Allocator,
    root_path: []const u8,
    dependencies: std.StringArrayHashMap(std.StringArrayHashMapUnmanaged([]const u8)),
) !std.ArrayList([]const u8) {
    var stack = std.ArrayList([]const u8).init(allocator);
    errdefer stack.deinit();

    _ = try circular_dependency_found_recursive(root_path, &stack, dependencies);

    return stack;
}

fn circular_dependency_found_recursive(
    path: []const u8,
    stack: *std.ArrayList([]const u8),
    dependencies: std.StringArrayHashMap(std.StringArrayHashMapUnmanaged([]const u8)),
) !bool {
    for (stack.items) |elem| {
        if (std.mem.eql(u8, path, elem)) {
            try stack.append(path);
            return true;
        }
    }

    try stack.append(path);

    if (dependencies.get(path)) |deps|
        for (deps.values()) |dep_path| {
            if (try circular_dependency_found_recursive(dep_path, stack, dependencies))
                return true;
        };

    _ = stack.pop();
    return false;
}
