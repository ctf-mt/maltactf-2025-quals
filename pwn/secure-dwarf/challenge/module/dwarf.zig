const std = @import("std");
const dwarf = std.dwarf;
const expression = dwarf.expressions;
const StackMachine = expression.StackMachine(.{});
const ExpressionContext = expression.ExpressionContext;
const ExpressionOptions = expression.ExpressionOptions;
const ArrayList = std.ArrayList;

const k = @import("kernel.zig");
const NULL = k.NULL;
const Fops = k.Fops;
const Devt = k.Devt;
const copy_to_user = k.copy_to_user;
const copy_from_user = k.copy_from_user;
const printk = k.printk;

const NAME = "dwarf";

pub fn panic(msg: []const u8, stacktrace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = stacktrace;
    _ = ret_addr;

    printk("PANIC: %s", msg.ptr);
    asm volatile ("int3" ::: "memory");
    unreachable;
}

var lock: std.atomic.Value(u64) = .{ .raw = 0 };

fn acquire_lock() void {
    while (lock.cmpxchgStrong(0, 1, std.builtin.AtomicOrder.seq_cst, std.builtin.AtomicOrder.seq_cst)) |_| {
        std.atomic.spinLoopHint();
    }
}

fn release_lock() void {
    lock.store(0, std.builtin.AtomicOrder.seq_cst);
}

const Run = extern struct {
    idx: usize,
    ret: usize,
    instructions: [0x1000]u8,
};

const MACHINE_CREATE = 0x11;
const MACHINE_RUN = 0x12;
const MACHINE_DESTROY = 0x13;
const MACHINE_QUERY = 0x14;

var stack_kmem_cache: k.KMemCache = undefined;
var array_kmem_cache: k.KMemCache = undefined;
var stack_alloc: std.mem.Allocator = undefined;
var array_alloc: std.mem.Allocator = undefined;
var ka = k.KernelAllocator{ .flags = k.Gfp.KERNEL };
var machines: ArrayList(*StackMachine) = undefined;

fn dwarf_ioctl(file: *anyopaque, cmd: u32, arg: u64) callconv(.C) i64 {
    _ = file;

    acquire_lock();
    var err: i64 = -1;

    block: {
        switch (cmd) {
            MACHINE_CREATE => {
                const machine = stack_alloc.create(StackMachine) catch {
                    printk("failed to create stack machine\n");
                    break :block;
                };
                machine.stack.ensureTotalCapacityPrecise(array_alloc, MAX_VALUES) catch {
                    printk("failed to reserve capacity\n");
                    break :block;
                };
                const idx = machines.items.len;
                machines.append(machine) catch {
                    printk("failed to append to machines list\n");
                    break :block;
                };
                err = @bitCast(idx);
            },
            MACHINE_RUN => {
                const ptr: *anyopaque = @ptrFromInt(arg);
                var packet: Run = undefined;

                if (0 != copy_from_user(@ptrCast(&packet), ptr, @sizeOf(@TypeOf(packet)))) {
                    printk("error copying from user\n");
                    break :block;
                }

                if (packet.idx >= machines.items.len) {
                    printk("invalid machine\n");
                    break :block;
                }

                const ctx = ExpressionContext{};
                const machine = machines.items[packet.idx];
                const value = machine.run(&packet.instructions, array_alloc, ctx, null) catch |e| {
                    printk("error: %s\n", @errorName(e).ptr);
                    break :block;
                };

                var ret: usize = @bitCast(@as(isize, -1));
                if (value) |v| {
                    ret = v.generic;
                }
                const dst: *anyopaque = @ptrFromInt(arg + @offsetOf(Run, "ret"));
                if (0 != copy_to_user(dst, &ret, 8)) {
                    printk("failed to copy ret\n");
                    break :block;
                }

                err = 0;
            },
            MACHINE_DESTROY => {
                const idx = arg;
                if (idx >= machines.items.len) {
                    printk("invalid machine\n");
                    break :block;
                }

                const machine = machines.items[idx];
                machine.deinit(array_alloc);
                stack_alloc.destroy(machine);
                _ = machines.orderedRemove(idx);
                err = 0;
            },
            MACHINE_QUERY => err = @bitCast(machines.items.len),
            else => err = -2,
        }
    }

    release_lock();
    return err;
}

const ops: Fops = .{
    .unlocked_ioctl = &dwarf_ioctl,
};

// modified the zig stdlib to make this public
const Value = StackMachine.Value;
const Array = std.ArrayListUnmanaged(Value);
const MAX_VALUES = 0x10;

fn init_stack(x: *anyopaque) callconv(.C) void {
    const ptr: [*]u8 = @ptrCast(x);
    @memset(ptr[0..@sizeOf(StackMachine)], 0);
}

export fn init_module() i32 {
    printk("hi from zig!!!\n");

    // SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_NO_MERGE
    const flags = (1 << 4) | (1 << 8) | (1 << 12);
    stack_kmem_cache = k.KMemCache.init("stack", @sizeOf(StackMachine), @alignOf(StackMachine), flags, &init_stack, k.Gfp.KERNEL);
    array_kmem_cache = k.KMemCache.init("array", @sizeOf(Value) * MAX_VALUES, @alignOf(Value), flags, @ptrCast(NULL), k.Gfp.KERNEL);
    stack_alloc = stack_kmem_cache.allocator();
    array_alloc = array_kmem_cache.allocator();

    machines = ArrayList(*StackMachine).init(ka.allocator());
    machines.ensureTotalCapacity(0x1000) catch {
        printk("failed to reserve machines space\n");
        return -1;
    };

    var devt = Devt{ .major = 0, .minor = 0 };
    const status = k.register_chrdev(0, NAME, &ops);
    if (status < 0) {
        printk("error\n");
        return -1;
    }
    devt.major = @intCast(status);
    const cls = k.class_create(NAME);
    _ = k.device_create(cls, NULL, @bitCast(devt), NULL, NAME);

    return 0;
}

export const license: k.Modinfo("license", "GPL") linksection(".modinfo") = .{};
