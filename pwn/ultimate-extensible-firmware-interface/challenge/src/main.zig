const std = @import("std");
const fmt = std.fmt;
const uefi = std.os.uefi;
const term = @import("term.zig");
const arch = @import("arch.zig");
const ArrayList = std.ArrayList;

var handle = uefi.handle;

pub fn panic(msg: []const u8, trace: ?*const std.builtin.StackTrace, first_trace_addr: ?usize) noreturn {
    _ = trace;
    _ = first_trace_addr;
    term.print("!!PANIC!!\n{s}", .{msg});
    arch.hang();
}

const Base = enum(u8) {
    Dec = 10,
    Hex = 16,
};

fn parse(T: type) T {
    var buf: [64]u8 = undefined;
    const slice = term.reader.readUntilDelimiter(&buf, '\r') catch return 0;
    term.print("\n", .{});
    return fmt.parseInt(T, slice, 0) catch 0;
}

const banner =
    \\Welcome to the advanced UEFI PRIVATE STORAGE INTERFACE.
    \\
    \\
;
const menu =
    \\==[ Menu Options ]==
    \\1. create STORAGE
    \\2. resize STORAGE
    \\3. delete STORAGE
    \\4. edit STORAGE
    \\5. self destruct
    \\
;

const MAX_SIZE: usize = 1 << 31;

fn conv(byte: u8) u8 {
    if ('0' <= byte and byte <= '9') {
        return byte - '0';
    }
    if ('A' <= byte and byte <= 'F') {
        return byte - 'A' + 10;
    }
    return 0;
}

pub fn main() void {
    term.init();
    term.print(banner, .{});

    _ = uefi.system_table.boot_services.?.setWatchdogTimer(0, 0, 0, null);

    var box = ArrayList([]u8).init(uefi.pool_allocator);

    while (true) {
        term.print(menu, .{});

        term.print("make a decision: ", .{});
        const choice = parse(u32);
        term.print("(chose: {})\n", .{choice});

        switch (choice) {
            1 => {
                term.print("STORAGE size: ", .{});
                const size = parse(usize);
                if (size >= MAX_SIZE or size == 0) {
                    term.print("bad size!\n", .{});
                    continue;
                }

                const storage = uefi.pool_allocator.alloc(u8, size) catch unreachable;
                box.append(storage) catch unreachable;
                term.print("(added to index {})\n", .{box.items.len - 1});
            },
            2 => {
                term.print("STORAGE size: ", .{});
                const size = parse(usize);
                if (size >= MAX_SIZE or size == 0) {
                    term.print("bad size!\n", .{});
                    continue;
                }

                term.print("STORAGE index: ", .{});
                const idx = parse(usize);
                if (idx >= box.items.len) {
                    term.print("bad index!\n", .{});
                    continue;
                }

                box.items[idx] = uefi.pool_allocator.realloc(box.items[idx], size) catch unreachable;
            },
            3 => {
                term.print("STORAGE index: ", .{});
                const idx = parse(usize);
                if (idx >= box.items.len) {
                    term.print("bad index!\n", .{});
                    continue;
                }

                const storage = box.orderedRemove(idx);
                uefi.pool_allocator.free(storage);
            },
            4 => {
                term.print("STORAGE index: ", .{});
                const idx = parse(usize);
                if (idx >= box.items.len) {
                    term.print("bad index!\n", .{});
                    continue;
                }

                const storage = box.items[idx];
                term.print("STORAGE offset: ", .{});
                const offset = parse(usize);
                if (offset >= storage.len) {
                    term.print("bad offset!\n", .{});
                    continue;
                }

                term.print("STORAGE data: ", .{});
                for (offset..storage.len) |i| {
                    var buf: [2]u8 = undefined;
                    _ = term.reader.read(buf[0..2]) catch unreachable;
                    const byte = (conv(buf[0]) << 4) | conv(buf[1]);
                    storage[i] = byte;
                }
                term.print("\n", .{});
                term.print("(read {} bytes to offset {x})\n", .{ storage.len - offset, offset });
            },
            5 => {
                asm volatile (
                    \\.intel_syntax noprefix
                    \\xor eax, eax
                    \\dec rax
                    \\push rax
                    \\lidt qword ptr [rsp]
                    \\int3
                );
                arch.hang();
            },
            else => {
                term.print("invalid option!\n", .{});
                continue;
            },
        }
    }
}
