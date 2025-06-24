extern fn _printk(msg: [*:0]const u8, ...) callconv(.C) void;

const ProcHandler = fn (*const CtlTable, i32, *anyopaque, *usize, *usize) callconv(.C) i32;
const CtlTable = extern struct {
    procname: [*:0]const u8,
    data: *allowzero anyopaque,
    maxlen: i32,
    mode: i32,
    proc_handler: *const ProcHandler,
    poll: *allowzero anyopaque,
    extra1: *allowzero anyopaque,
    extra2: *allowzero anyopaque,
};

const Fops = extern struct {
    const Read = fn (*anyopaque, *u8, usize, *usize) callconv(.C) isize;
    const Write = fn (*anyopaque, *u8, usize, *usize) callconv(.C) isize;
    const Open = fn (*anyopaque, *anyopaque) callconv(.C) i32;
    const Release = fn (*anyopaque, *anyopaque) callconv(.C) i32;
    const UnlockedIoctl = fn (*anyopaque, cmd: u32, arg: u64) i64;

    module: *allowzero anyopaque = NULL,
    fop_flags: u32 = 0,
    llseek: *allowzero anyopaque = NULL,
    read: *allowzero const Read = @ptrCast(NULL),
    write: *allowzero const Write = @ptrCast(NULL),
    read_iter: *allowzero anyopaque = NULL,
    write_iter: *allowzero anyopaque = NULL,
    iopoll: *allowzero anyopaque = NULL,
    iterate_shared: *allowzero anyopaque = NULL,
    poll: *allowzero anyopaque = NULL,
    unlocked_ioctl: *allowzero const UnlockedIoctl = NULL,
    compat_ioctl: *allowzero anyopaque = NULL,
    mmap: *allowzero anyopaque = NULL,
    open: *allowzero const Open = @ptrCast(NULL),
    flush: *allowzero anyopaque = NULL,
    release: *allowzero const Release = @ptrCast(NULL),
    fsync: *allowzero anyopaque = NULL,
    fasync: *allowzero anyopaque = NULL,
    lock: *allowzero anyopaque = NULL,
    get_unmapped_area: *allowzero anyopaque = NULL,
    check_flags: *allowzero anyopaque = NULL,
    flock: *allowzero anyopaque = NULL,
    splice_write: *allowzero anyopaque = NULL,
    splice_read: *allowzero anyopaque = NULL,
    splice_eof: *allowzero anyopaque = NULL,
    setlease: *allowzero anyopaque = NULL,
    fallocate: *allowzero anyopaque = NULL,
    show_fdinfo: *allowzero anyopaque = NULL,
    // mmap_capabilities: *allowzero anyopaque = NULL, // only when CONFIG_MMU is not defined
    copy_file_range: *allowzero anyopaque = NULL,
    remap_file_range: *allowzero anyopaque = NULL,
    fadvice: *allowzero anyopaque = NULL,
    uring_cmd: *allowzero anyopaque = NULL,
    uring_cmd_iopoll: *allowzero anyopaque = NULL,
};

comptime {
    if (@sizeOf(Fops) != 0x108) {
        @compileLog(@sizeOf(Fops));
        @compileError("fops size mismatch");
    }
}

extern fn register_sysctl_sz(path: [*:0]const u8, table: *const CtlTable, sz: usize) void;
extern fn __register_chrdev(major: u32, baseminor: u32, count: u32, name: [*:0]const u8, fops: *const Fops) i32;
fn register_chrdev(major: u32, name: [*:0]const u8, fops: *const Fops) i32 {
    return __register_chrdev(major, 0, 256, name, fops);
}
extern fn class_create(name: [*:0]const u8) *anyopaque;
extern fn device_create(cls: *anyopaque, parent: *allowzero anyopaque, devt: u32, drvdata: *allowzero anyopaque, fmt: [*:0]const u8, ...) *anyopaque;
extern fn try_module_get(module: *anyopaque) bool;
extern fn module_put(module: *anyopaque) void;
extern fn _copy_to_user(dst: *anyopaque, src: *const anyopaque, len: usize) i64;

const NULL: *allowzero anyopaque = @ptrFromInt(0);

fn handler(table: *const CtlTable, write: i32, buffer: *anyopaque, lenp: *usize, ppos: *usize) callconv(.C) i32 {
    _ = table;

    if (write != 0 and lenp.* >= 8 and ppos.* == 0) {
        const cmd: usize = @as(*align(1) usize, @ptrCast(buffer)).*;
        _printk("command = %lx\n", cmd);
        return 0;
    }

    return -1;
}

fn dwarf_open(file: *anyopaque, inode: *anyopaque) callconv(.C) i32 {
    _ = file;
    _ = inode;
    return 0;
}

fn dwarf_release(file: *anyopaque, inode: *anyopaque) callconv(.C) i32 {
    _ = file;
    _ = inode;
    return 0;
}

fn dwarf_read(file: *anyopaque, buffer: *u8, len: usize, off: *usize) callconv(.C) isize {
    _ = file;
    _ = len;
    if (off.* == 0) {
        const msg: []const u8 = "Z";
        if (0 != _copy_to_user(@ptrCast(buffer), @ptrCast(msg.ptr), 1)) {
            _printk("copy to user error\n");
            return -1;
        }
        off.* += 1;
        return 1;
    } else {
        off.* = 0;
        return 0;
    }
}

var ops: Fops = .{
    .open = &dwarf_open,
    .release = &dwarf_release,
    .read = &dwarf_read,
};

const Devt = packed struct(u32) {
    minor: u20,
    major: u12,
};

export fn init_module() i32 {
    _printk("hi from zig %d!\n", @as(i32, 0));

    // const table = CtlTable{
    //     .procname = "process",
    //     .data = NULL,
    //     .maxlen = 0,
    //     .mode = 0o666,
    //     .proc_handler = &handler,
    //     .poll = NULL,
    //     .extra1 = NULL,
    //     .extra2 = NULL,
    // };
    // register_sysctl_sz("dwarf", &table, 1);

    var devt = Devt{ .minor = 0, .major = 0 };
    const status = register_chrdev(0, "dwarf", &ops);
    if (status < 0) {
        _printk("error");
        return -1;
    }
    devt.major = @intCast(status);
    const cls = class_create("dwarf");
    _ = device_create(cls, NULL, @bitCast(devt), NULL, "dwarf");

    return 0;
}

fn Modinfo(key: []const u8, val: []const u8) type {
    const len = key.len + 1 + val.len + 1;
    var default: [len]u8 = [_]u8{0} ** len;
    @memcpy(default[0..key.len], key);
    default[key.len] = '=';
    @memcpy(default[key.len + 1 .. key.len + 1 + val.len], val);
    default[key.len + 1 + val.len] = 0;

    return @Type(.{
        .@"struct" = .{
            .layout = .@"extern",
            .fields = &.{
                .{
                    .name = "data",
                    .type = [len]u8,
                    .default_value_ptr = &default,
                    .is_comptime = false,
                    .alignment = 0,
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    });
}

export const license: Modinfo("license", "GPL") linksection(".modinfo") = .{};
