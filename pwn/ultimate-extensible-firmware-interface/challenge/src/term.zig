const std = @import("std");
const arch = @import("arch.zig");

const math = std.math;
const mem = std.mem;
const uefi = std.os.uefi;
const str16 = std.unicode.utf8ToUtf16LeStringLiteral;

const Writer = std.io.Writer;
const Reader = std.io.Reader;
pub const Stdout = uefi.protocol.SimpleTextOutput;
pub const Stdin = uefi.protocol.SimpleTextInput;
pub const InputKey = uefi.protocol.SimpleTextInput.Key.Input;

pub var stdout: *Stdout = undefined;
pub var stdin: *Stdin = undefined;
pub var columns: usize = undefined;
pub var rows: usize = undefined;

// The console output protocol interprets \n as a command to move the cursor down
// without returning to column zero.
// \r is interpreted as a command to move the cursor to column zero, without affecting the row.
// In order to move down and reset the line \n\r or \r\n is required.

pub fn init() void {
    if (uefi.system_table.con_out) |con_out| {
        stdout = con_out;
        _ = stdout.queryMode(stdout.mode.mode, &columns, &rows);
    } else {
        arch.hang();
    }

    _ = stdout.reset(false);
    _ = stdout.setAttribute(0x0F);
    _ = stdout.enableCursor(true);

    if (uefi.system_table.con_in) |con_in| {
        stdin = con_in;
    } else {
        // can print an error here because stdout is
        // guaranteed to be initialized already
        @panic("failed to initialize stdin");
    }
}

pub const reader = Reader(void, error{}, readFn){ .context = {} };

fn readFn(_: void, buf: []u8) error{}!usize {
    for (0..buf.len) |i| {
        const key = waitForKey();
        buf[i] = @truncate(key.unicode_char);
    }
    print("{s}", .{buf});
    return buf.len;
}

pub fn waitForKey() InputKey {
    var idx: usize = undefined;
    var key: InputKey = undefined;
    _ = uefi.system_table.boot_services.?.waitForEvent(1, @as([*]const uefi.Event, @ptrCast(&stdin.wait_for_key)), &idx);
    _ = stdin.readKeyStroke(&key);
    return key;
}

const writer = Writer(void, error{}, writeFn){ .context = {} };

fn writeFn(_: void, string: []const u8) error{}!usize {
    write8(string);
    return string.len;
}

pub fn print(comptime format: []const u8, args: anytype) void {
    writer.print(format, args) catch unreachable;
}

pub fn write8(string: []const u8) void {
    // Converts u8 str to u16 str in fixed size blocks
    // to avoid dynamic allocation.
    // This is required because the UEFI output protocol
    // expects u16 strs.
    var buf = [_:0]u16{0} ** 17;
    var base: usize = 0;

    while (base < string.len) {
        const len = @min(16, string.len - base);
        for (0..len) |i| {
            buf[i] = @intCast(string[base + i]);
        }
        buf[len] = 0;
        _ = stdout.outputString(&buf);
        base += len;
    }
}
