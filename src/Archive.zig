files: std.StringArrayHashMapUnmanaged(File) = .{},

const Archive = @This();
const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
pub const Hash = std.crypto.hash.sha2.Sha256;

const builtin = @import("builtin");
const tar = @import("tar.zig");

const log = std.log.scoped(.archive);

pub const File = struct {
    mode: std.fs.File.Mode,
    text: []const u8,
};

pub fn deinit(archive: *Archive, allocator: Allocator) void {
    for (archive.files.keys(), archive.files.values()) |path, file| {
        allocator.free(path);
        allocator.free(file.text);
    }

    archive.files.deinit(allocator);
}

fn padding_from_size(size: usize) usize {
    const mod = (512 + size) % 512;
    return if (mod > 0) 512 - mod else 0;
}

fn strip_components(path: []const u8, count: u32) ![]const u8 {
    var i: usize = 0;
    var c = count;
    while (c > 0) : (c -= 1) {
        if (std.mem.indexOfScalarPos(u8, path, i, '/')) |pos| {
            i = pos + 1;
        } else {
            return error.TarComponentsOutsideStrippedPrefix;
        }
    }
    return path[i..];
}

const ReadFromTarOptions = struct {
    strip_components: u32,
};

//pub fn read_from_tar(
//    allocator: Allocator,
//    reader: anytype,
//    options: ReadFromTarOptions,
//) !Archive {
//    var timer = try std.time.Timer.start();
//    defer {
//        const result = timer.read();
//        log.info("read_from_tar took {} nanoseconds", .{result});
//    }
//
//    var archive = Archive{};
//    errdefer archive.deinit(allocator);
//
//    var file_name_buffer: [255]u8 = undefined;
//    var buffer: [512 * 8]u8 = undefined;
//    var start: usize = 0;
//    var end: usize = 0;
//    header: while (true) {
//        if (buffer.len - start < 1024) {
//            const dest_end = end - start;
//            @memcpy(buffer[0..dest_end], buffer[start..end]);
//            end = dest_end;
//            start = 0;
//        }
//        const ask_header = @min(buffer.len - end, 1024 -| (end - start));
//        end += try reader.readAtLeast(buffer[end..], ask_header);
//        switch (end - start) {
//            0 => return archive,
//            1...511 => return error.UnexpectedEndOfStream,
//            else => {},
//        }
//        const header: std.tar.Header = .{ .bytes = buffer[start..][0..512] };
//        start += 512;
//        const file_size = try header.fileSize();
//        const rounded_file_size = std.mem.alignForward(u64, file_size, 512);
//        const pad_len = @as(usize, @intCast(rounded_file_size - file_size));
//        const unstripped_file_name = try header.fullFileName(&file_name_buffer);
//        switch (header.fileType()) {
//            .directory => {},
//            .normal => {
//                if (file_size == 0 and unstripped_file_name.len == 0) return archive;
//                const file_name = try strip_components(unstripped_file_name, options.strip_components);
//
//                const file_name_copy = try allocator.dupe(u8, file_name);
//                errdefer allocator.free(file_name_copy);
//
//                var file = std.ArrayList(u8).init(allocator);
//                defer file.deinit();
//
//                var file_off: usize = 0;
//                while (true) {
//                    if (buffer.len - start < 1024) {
//                        const dest_end = end - start;
//                        @memcpy(buffer[0..dest_end], buffer[start..end]);
//                        end = dest_end;
//                        start = 0;
//                    }
//                    // Ask for the rounded up file size + 512 for the next header.
//                    // TODO: https://github.com/ziglang/zig/issues/14039
//                    const ask = @as(usize, @intCast(@min(
//                        buffer.len - end,
//                        rounded_file_size + 512 - file_off -| (end - start),
//                    )));
//                    end += try reader.readAtLeast(buffer[end..], ask);
//                    if (end - start < ask) return error.UnexpectedEndOfStream;
//                    // TODO: https://github.com/ziglang/zig/issues/14039
//                    const slice = buffer[start..@as(usize, @intCast(@min(file_size - file_off + start, end)))];
//                    try file.writer().writeAll(slice);
//                    file_off += slice.len;
//                    start += slice.len;
//                    if (file_off >= file_size) {
//                        start += pad_len;
//                        // Guaranteed since we use a buffer divisible by 512.
//                        assert(start <= end);
//                        const text = try file.toOwnedSlice();
//                        errdefer allocator.free(text);
//
//                        const local_header: *const tar.Header = @ptrCast(header.bytes);
//                        _ = local_header;
//                        try archive.files.put(allocator, file_name_copy, .{
//                            .text = text,
//                            .mode = 0o644,
//                            //.mode = try local_header.get_mode(),
//                        });
//                        continue :header;
//                    }
//                }
//            },
//            .global_extended_header, .extended_header => {
//                if (start + rounded_file_size > end) return error.TarHeadersTooBig;
//                start = @as(usize, @intCast(start + rounded_file_size));
//            },
//            .hard_link => return error.TarUnsupportedFileType,
//            .symbolic_link => return error.TarUnsupportedFileType,
//            else => return error.TarUnsupportedFileType,
//        }
//    }
//
//    return archive;
//}

// TODO: thread pool it
pub fn read_from_fs(
    allocator: Allocator,
    dir: std.fs.Dir,
    paths: std.StringArrayHashMap(void),
) !Archive {
    {
        var buf: [4096]u8 = undefined;
        const dir_path = try dir.realpath(".", &buf);
        std.log.err("reading archive from: {s}", .{dir_path});
    }

    var archive = Archive{};
    errdefer archive.deinit(allocator);

    for (paths.keys()) |path| {
        var components = std.ArrayList([]const u8).init(allocator);
        defer components.deinit();

        var it = std.mem.tokenizeScalar(u8, path, '/');
        while (it.next()) |component|
            try components.append(component);

        var stack = std.ArrayList(std.fs.Dir).init(allocator);
        defer {
            for (stack.items) |*subdir| subdir.close();
            stack.deinit();
        }

        for (components.items[0 .. components.items.len - 1], 0..) |component, i| {
            const subdir = if (i == 0) dir else stack.items[stack.items.len - 1];
            var new_dir = try subdir.openDir(component, .{ .iterate = true });
            {
                errdefer new_dir.close();
                try stack.append(new_dir);
            }
        }

        const subdir = if (stack.items.len == 0) dir else stack.items[stack.items.len - 1];
        const stat = subdir.statFile(components.items[components.items.len - 1]) catch |err| {
            if (err == error.FileNotFound) {
                var buf: [4096]u8 = undefined;
                const dir_path = try subdir.realpath(".", &buf);
                std.log.err("File not found: {s}/{s}", .{ dir_path, path });
            }

            return err;
        };
        if (stat.kind == .directory) {
            var collected_dir = try subdir.openDir(components.items[components.items.len - 1], .{});
            defer collected_dir.close();
            {
                var buf: [4096]u8 = undefined;
                const dir_path = try collected_dir.realpath(".", &buf);
                std.log.debug("found directory, adding all contents: {s}", .{dir_path});
            }

            var walker = try collected_dir.walk(allocator);
            defer walker.deinit();

            while (try walker.next()) |entry| {
                if (entry.kind == .directory)
                    continue;

                if (entry.kind != .file) {
                    log.warn("skipping {}: {s}", .{ entry.kind, entry.path });
                    continue;
                }

                var path_components = std.ArrayList([]const u8).init(allocator);
                defer path_components.deinit();

                try path_components.appendSlice(components.items);
                try path_components.append(entry.path);

                const path_copy = try std.fs.path.join(allocator, path_components.items);
                errdefer allocator.free(path_copy);

                const file = try entry.dir.openFile(entry.basename, .{});
                defer file.close();

                const text = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
                errdefer allocator.free(text);

                std.log.debug("adding file: {s}", .{entry.path});
                const file_stat = try file.stat();
                try archive.files.put(allocator, path_copy, .{
                    .text = text,
                    .mode = file_stat.mode,
                });
            }
        } else {
            const file = try subdir.openFile(components.items[components.items.len - 1], .{});
            defer file.close();

            const text = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
            errdefer allocator.free(text);

            const path_copy = try std.fs.path.join(allocator, components.items);
            errdefer allocator.free(path_copy);

            const file_stat = try file.stat();
            std.log.debug("adding file directly: {s}", .{path_copy});
            try archive.files.put(allocator, path_copy, .{
                .text = text,
                .mode = file_stat.mode,
            });
        }
    }

    return archive;
}

pub fn to_tar_gz(archive: Archive, allocator: Allocator, name: []const u8) ![]u8 {
    var in_buf = std.fifo.LinearFifo(u8, .{ .Dynamic = {} }).init(allocator);
    defer in_buf.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    for (archive.files.keys(), archive.files.values()) |path, file| {
        const padding = padding_from_size(file.text.len);
        const path_with_skipped_dir = try std.fs.path.join(arena.allocator(), &.{ name, path });
        const header = try tar.Header.init(.{
            .path = path_with_skipped_dir,
            .size = file.text.len,
            .typeflag = .regular,
            .mode = @intCast(file.mode),
        });

        try in_buf.writer().writeAll(header.to_bytes());
        try in_buf.writer().writeAll(file.text);
        try in_buf.writer().writeByteNTimes(0, @as(usize, @intCast(padding)));
    }

    try in_buf.writer().writeByteNTimes(0, 1024);

    var out_buf = std.ArrayList(u8).init(allocator);
    defer out_buf.deinit();

    try std.compress.gzip.compress(in_buf.reader(), out_buf.writer(), .{});

    return out_buf.toOwnedSlice();
}

fn path_less_than(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.lessThan(u8, lhs, rhs);
}

pub const WhatToDoWithExecutableBit = enum {
    ignore_executable_bit,
    include_executable_bit,
};

fn is_executable(mode: std.fs.File.Mode, executable_bit: WhatToDoWithExecutableBit) bool {
    switch (executable_bit) {
        .ignore_executable_bit => return false,
        .include_executable_bit => {},
    }

    if (builtin.os.tag == .windows) {
        // TODO check the ACL on Windows.
        // Until this is implemented, this could be a false negative on
        // Windows, which is why we do not yet set executable_bit_only above
        // when unpacking the tarball.
        return false;
    } else {
        return (mode & std.os.S.IXUSR) != 0;
    }
}

pub const multihash_function: MultihashFunction = switch (Hash) {
    std.crypto.hash.sha2.Sha256 => .@"sha2-256",
    else => @compileError("unreachable"),
};

pub const Digest = [Hash.digest_length]u8;
pub const multihash_len = 1 + 1 + Hash.digest_length;
pub const multihash_hex_digest_len = 2 * multihash_len;
pub const MultiHashHexDigest = [multihash_hex_digest_len]u8;
const hex_charset = "0123456789abcdef";

pub const MultihashFunction = enum(u16) {
    identity = 0x00,
    sha1 = 0x11,
    @"sha2-256" = 0x12,
    @"sha2-512" = 0x13,
    @"sha3-512" = 0x14,
    @"sha3-384" = 0x15,
    @"sha3-256" = 0x16,
    @"sha3-224" = 0x17,
    @"sha2-384" = 0x20,
    @"sha2-256-trunc254-padded" = 0x1012,
    @"sha2-224" = 0x1013,
    @"sha2-512-224" = 0x1014,
    @"sha2-512-256" = 0x1015,
    @"blake2b-256" = 0xb220,
    _,
};

pub fn hex_digest(digest: Digest) MultiHashHexDigest {
    var result: MultiHashHexDigest = undefined;

    result[0] = hex_charset[@intFromEnum(multihash_function) >> 4];
    result[1] = hex_charset[@intFromEnum(multihash_function) & 15];

    result[2] = hex_charset[Hash.digest_length >> 4];
    result[3] = hex_charset[Hash.digest_length & 15];

    for (digest, 0..) |byte, i| {
        result[4 + i * 2] = hex_charset[byte >> 4];
        result[5 + i * 2] = hex_charset[byte & 15];
    }
    return result;
}

// TODO: threadpool this
pub fn hash(
    archive: Archive,
    allocator: Allocator,
    executable_bit: WhatToDoWithExecutableBit,
) !MultiHashHexDigest {
    var timer = try std.time.Timer.start();
    defer {
        const timer_result = timer.read();
        log.info("hash took {} nanoseconds", .{timer_result});
    }

    var paths = std.ArrayList([]const u8).init(allocator);
    defer paths.deinit();

    var hashes = std.ArrayList([Hash.digest_length]u8).init(allocator);
    defer hashes.deinit();

    try paths.appendSlice(archive.files.keys());
    try hashes.appendNTimes(undefined, paths.items.len);
    std.mem.sort([]const u8, paths.items, {}, path_less_than);

    for (paths.items, hashes.items) |path, *result| {
        const file = archive.files.get(path).?;
        var hasher = Hash.init(.{});
        hasher.update(path);
        hasher.update(&.{ 0, @intFromBool(is_executable(file.mode, executable_bit)) });
        hasher.update(file.text);
        hasher.final(result);
    }

    var hasher = Hash.init(.{});
    for (hashes.items) |file_hash|
        hasher.update(&file_hash);

    return hex_digest(hasher.finalResult());
}
