allocator: Allocator,
name: []const u8,
version: std.SemanticVersion,
dependencies: std.StringArrayHashMap(PackageInfo),
paths: std.StringArrayHashMap(void),

const Manifest = @This();
const std = @import("std");
const Allocator = std.mem.Allocator;
const zon = @import("eggzon");

const log = std.log.scoped(.manifest);

pub const PackageInfo = union(enum) {
    local: struct {
        path: []const u8,
    },
    remote: struct {
        url: []const u8,
        hash: []const u8,
    },

    pub fn format(
        info: PackageInfo,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        switch (info) {
            .local => |local| try writer.print("local: path={s}", .{local.path}),
            .remote => |remote| try writer.print("remote: url={s} hash={s}", .{ remote.url, remote.hash }),
        }
    }
};

pub fn from_text(allocator: Allocator, text: []const u8) !Manifest {
    var result = try zon.parseString(allocator, text);
    defer result.deinit();

    if (result.root != .object)
        return error.RootIsNotObject;

    const root = result.root.object;
    const name = root.get("name") orelse return error.ProjectMissingName;
    if (name != .string)
        return error.ProjectNameNotString;

    const version = root.get("version") orelse return error.ProjectMissingVersion;
    if (version != .string)
        return error.VersionIsNotString;

    const name_copy = try allocator.dupe(u8, name.string);
    const semver = try std.SemanticVersion.parse(version.string);

    var paths = std.StringArrayHashMap(void).init(allocator);
    errdefer {
        for (paths.keys()) |path| allocator.free(path);
        paths.deinit();
    }

    const zon_paths = root.get("paths") orelse return error.ProjectMissingPaths;
    if (zon_paths != .array)
        return error.ProjectPathsIsNotArray;

    for (zon_paths.array) |path| {
        if (path != .string)
            return error.ProjectPathIsNotString;
        const path_copy = try allocator.dupe(u8, path.string);
        errdefer allocator.free(path_copy);

        try paths.put(path_copy, {});
    }

    var dependencies = std.StringArrayHashMap(PackageInfo).init(allocator);
    errdefer {
        for (dependencies.keys(), dependencies.values()) |dep_key, info| {
            allocator.free(dep_key);
            switch (info) {
                .local => |local| allocator.free(local.path),
                .remote => |remote| {
                    allocator.free(remote.url);
                    allocator.free(remote.hash);
                },
            }
        }
        dependencies.deinit();
    }

    if (root.get("dependencies")) |dependencies_node| blk: {
        if (dependencies_node == .empty)
            break :blk;
        if (dependencies_node != .object)
            return error.DependenciesIsNotObject;

        for (dependencies_node.object.keys(), dependencies_node.object.values()) |dep_key, dep_value| {
            if (dep_value != .object)
                return error.DependencyIsNotObject;

            const dep = dep_value.object;
            const dep_key_copy = try allocator.dupe(u8, dep_key);
            errdefer allocator.free(dep_key_copy);

            if (dep.get("path")) |path| {
                if (path != .string)
                    return error.DependencyPathIsNotString;

                const path_copy = try allocator.dupe(u8, path.string);
                errdefer allocator.free(path_copy);

                try dependencies.put(dep_key_copy, .{
                    .local = .{ .path = path_copy },
                });
            } else {
                const url = dep.get("url") orelse return error.DependencyMissingUrl;
                const hash = dep.get("hash") orelse return error.DependencyMissingHash;

                if (url != .string)
                    return error.UrlIsNotString;

                if (hash != .string)
                    return error.HashIsNotString;

                const url_copy = try allocator.dupe(u8, url.string);
                errdefer allocator.free(url_copy);

                const hash_copy = try allocator.dupe(u8, hash.string);
                errdefer allocator.free(url_copy);

                try dependencies.put(dep_key_copy, .{
                    .remote = .{
                        .url = url_copy,
                        .hash = hash_copy,
                    },
                });
            }
        }
    }

    return Manifest{
        .allocator = allocator,
        .name = name_copy,
        .version = semver,
        .dependencies = dependencies,
        .paths = paths,
    };
}

pub fn deinit(manifest: *Manifest) void {
    manifest.allocator.free(manifest.name);

    for (manifest.dependencies.keys(), manifest.dependencies.values()) |name, info| {
        manifest.allocator.free(name);
        switch (info) {
            .local => |local| manifest.allocator.free(local.path),
            .remote => |remote| {
                manifest.allocator.free(remote.url);
                manifest.allocator.free(remote.hash);
            },
        }
    }
    manifest.dependencies.deinit();

    for (manifest.paths.keys()) |path| manifest.allocator.free(path);
    manifest.paths.deinit();
}

pub fn format(
    manifest: Manifest,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;

    try writer.writeByte('\n');
    try writer.print("\tname: {s}\n", .{manifest.name});
    try writer.print("\tversion: {}\n", .{manifest.version});
    try writer.writeAll("\tpaths:\n");
    for (manifest.paths.keys()) |path|
        try writer.print("\t\t{s}\n", .{path});

    if (manifest.dependencies.count() > 0) {
        try writer.writeAll("\tdependencies:\n");
        for (manifest.dependencies.keys(), manifest.dependencies.values()) |dep_name, dep|
            try writer.print("\t\t{s}: {}\n", .{ dep_name, dep });
    }
}

pub fn serialize(manifest: Manifest, allocator: Allocator) ![]const u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    const writer = buffer.writer();

    try writer.writeAll(".{\n");
    try writer.print(
        \\    .name = "{s}",
        \\    .version = "{}",
        \\    .paths = .{{
        \\
    , .{ manifest.name, manifest.version });
    for (manifest.paths.keys()) |path|
        try writer.print(
            \\        "{s}",
            \\
        , .{path});
    try writer.writeAll(
        \\    },
        \\
    );

    if (manifest.dependencies.count() > 0) {
        try writer.writeAll(
            \\    .dependencies = .{
            \\
        );

        for (manifest.dependencies.keys(), manifest.dependencies.values()) |dep_name, info| {
            try writer.print(
                \\        .{s} = .{{
                \\            .url = "{s}",
                \\            .hash = "{s}",
                \\        }},
                \\
            , .{
                std.zig.fmtId(dep_name),
                info.remote.url,
                info.remote.hash,
            });
        }

        try writer.writeAll(
            \\    },
            \\
        );
    }
    try writer.writeAll("}\n");

    return try buffer.toOwnedSlice();
}
