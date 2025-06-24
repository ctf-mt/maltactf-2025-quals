const std = @import("std");
const mem = std.mem;

pub const NULL: *allowzero anyopaque = @ptrFromInt(0);
pub const ProcHandler = fn (*const CtlTable, i32, *anyopaque, *usize, *usize) callconv(.C) i32;
pub const CtlTable = extern struct {
    procname: [*:0]const u8,
    data: *allowzero anyopaque,
    maxlen: i32,
    mode: i32,
    proc_handler: *const ProcHandler,
    poll: *allowzero anyopaque,
    extra1: *allowzero anyopaque,
    extra2: *allowzero anyopaque,
};
pub const Fops = extern struct {
    const Read = fn (*anyopaque, *u8, usize, *usize) callconv(.C) isize;
    const Write = fn (*anyopaque, *u8, usize, *usize) callconv(.C) isize;
    const Open = fn (*anyopaque, *anyopaque) callconv(.C) i32;
    const Release = fn (*anyopaque, *anyopaque) callconv(.C) i32;
    const UnlockedIoctl = fn (*anyopaque, cmd: u32, arg: u64) callconv(.C) i64;

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
    unlocked_ioctl: *allowzero const UnlockedIoctl = @ptrCast(NULL),
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
pub const Devt = packed struct(u32) {
    minor: u20,
    major: u12,
};
pub fn Modinfo(key: []const u8, val: []const u8) type {
    const len = key.len + 1 + val.len + 1;
    var default: [len]u8 = [_]u8{0} ** len;
    @memcpy(default[0..key.len], key);
    default[key.len] = '=';
    @memcpy(default[key.len + 1 .. key.len + 1 + val.len], val);
    default[key.len + 1 + val.len] = 0;

    return @Type(.{
        .Struct = .{
            .layout = .@"extern",
            .fields = &.{
                .{
                    .name = "data",
                    .type = [len]u8,
                    .default_value = &default,
                    .is_comptime = false,
                    .alignment = 0,
                },
            },
            .decls = &.{},
            .is_tuple = false,
        },
    });
}

fn checkSize(comptime T: type, comptime size: usize) void {
    comptime {
        if (@sizeOf(T) != size) {
            @compileLog(@sizeOf(T));
            @compileError(@typeName(T) ++ " size mismatch");
        }
    }
}

comptime {
    checkSize(Fops, 0x108);
}

extern fn _printk(msg: [*:0]const u8, ...) void;
extern fn register_sysctl_sz(path: [*:0]const u8, tables: *CtlTable, sz: usize) void;
extern fn __register_chrdev(major: u32, baseminor: u32, count: u32, name: [*:0]const u8, fops: *const Fops) i32;

extern fn _copy_to_user(dst: *anyopaque, src: *const anyopaque, len: usize) i64;
extern fn _copy_from_user(dst: *anyopaque, src: *const anyopaque, len: usize) i64;

pub extern fn class_create(name: [*:0]const u8) *anyopaque;
pub extern fn device_create(cls: *anyopaque, parent: *allowzero anyopaque, devt: u32, drvdata: *allowzero anyopaque, fmt: [*:0]const u8, ...) *anyopaque;
pub extern fn try_module_get(module: *anyopaque) bool;
pub extern fn module_put(module: *anyopaque) void;

pub fn register_sysctl(name: [*:0]const u8, tables: []CtlTable) void {
    register_sysctl_sz(name, tables.ptr, tables.len);
}
pub fn register_chrdev(major: u32, name: [*:0]const u8, fops: *const Fops) i32 {
    return __register_chrdev(major, 0, 256, name, fops);
}
pub const printk = _printk;
pub fn copy_to_user(user_dst: *anyopaque, kern_src: *const anyopaque, len: usize) i64 {
    return _copy_to_user(user_dst, kern_src, len);
}
pub fn copy_from_user(kern_dst: *anyopaque, user_src: *const anyopaque, len: usize) i64 {
    return _copy_from_user(kern_dst, user_src, len);
}

pub const Gfp = packed struct(u32) {
    const Self = @This();
    const RECLAIM = Self{ .DIRECT_RECLAIM = true, .KSWAPD_RECLAIM = true };
    pub const KERNEL = RECLAIM.set(Self{ .IO = true, .FS = true });

    fn set(self: Self, other: Self) Gfp {
        const a: u32 = @bitCast(self);
        const b: u32 = @bitCast(other);
        return @bitCast(a | b);
    }

    DMA: bool = false,
    HIGHMEM: bool = false,
    DMA32: bool = false,
    MOVABLE: bool = false,
    RECLAIMABLE: bool = false,
    HIGH: bool = false,
    IO: bool = false,
    FS: bool = false,
    ZERO: bool = false,
    UNUSED: bool = false,
    DIRECT_RECLAIM: bool = false,
    KSWAPD_RECLAIM: bool = false,
    WRITE: bool = false,
    NOWARN: bool = false,
    RETRY_MAYFAIL: bool = false,
    NOFAIL: bool = false,
    NORETRY: bool = false,
    MEMALLOC: bool = false,
    COMP: bool = false,
    NOMEMALLOC: bool = false,
    HARDWALL: bool = false,
    THISNODE: bool = false,
    ACCOUNT: bool = false,
    ZEROTAGS: bool = false,
    SKIP_ZERO: bool = false,
    SKIP_KASAN: bool = false,
    NOLOCKDEP: bool = false,
    NO_OBJ_EXT: bool = false,
    __pad1: bool = false,
    __pad2: bool = false,
    __pad3: bool = false,
    __pad4: bool = false,
};

pub const KMALLOC_SHIFT_HIGH: usize = 12;
pub const KMALLOC_CACHE_MAX_SIZE: usize = 1 << KMALLOC_SHIFT_HIGH;

extern fn __kmalloc_large_noprof(size: usize, flags: u32) *allowzero anyopaque;
extern fn __kmalloc_noprof(size: usize, flags: u32) *allowzero anyopaque;
extern fn krealloc_noprof(p: *anyopaque, size: usize, flags: u32) *allowzero anyopaque;

pub fn kmalloc(size: usize, flags: Gfp) *allowzero anyopaque {
    const raw_flags: u32 = @bitCast(flags);
    if (@inComptime() and std.meta.activeTag(@typeInfo(size)) == .comptime_int) {
        if (size > KMALLOC_CACHE_MAX_SIZE) {
            return __kmalloc_large_noprof(size, raw_flags);
        }
    }
    return __kmalloc_noprof(size, raw_flags);
}

pub extern fn kfree(obj: *anyopaque) void;

pub const KernelAllocator = struct {
    const Self = @This();
    const Vtable = mem.Allocator.VTable{ .alloc = alloc, .free = free, .resize = resize };

    flags: Gfp,

    pub fn allocator(self: *Self) mem.Allocator {
        return mem.Allocator{
            .ptr = @ptrCast(self),
            .vtable = &Vtable,
        };
    }

    fn alloc(ctx: *anyopaque, size: usize, alignment: u8, ret_addr: usize) ?[*]u8 {
        _ = alignment;
        _ = ret_addr;

        const ka: *KernelAllocator = @ptrCast(@alignCast(ctx));
        const ptr = kmalloc(size, ka.flags);
        if (ptr == NULL) {
            return null;
        } else {
            return @ptrCast(ptr);
        }
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: u8, ret_addr: usize) void {
        _ = ctx;
        _ = alignment;
        _ = ret_addr;
        kfree(@ptrCast(memory.ptr));
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: u8, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        return false;
    }
};

const KMemCacheArgs = extern struct {
    alignment: u32 = 0,
    useroffset: u32 = 0,
    usersize: u32 = 0,
    freeptr_offset: u32 = 0,
    use_freeptr_offset: bool = false,
    ctor: *allowzero const fn (*anyopaque) callconv(.C) void,
};

comptime {
    checkSize(KMemCacheArgs, 0x20);
}

extern fn __kmem_cache_create_args(name: [*:0]const u8, size: u32, args: *const KMemCacheArgs, flags: u32) *allowzero anyopaque;
extern fn kmem_cache_alloc_lru_noprof(s: *allowzero anyopaque, lru: *allowzero anyopaque, flags: u32) *allowzero anyopaque;
extern fn kmem_cache_free(s: *allowzero anyopaque, x: *allowzero anyopaque) void;

pub const KMemCache = struct {
    const Self = @This();
    const VTable = mem.Allocator.VTable{ .alloc = alloc, .free = free, .resize = resize };

    s: *allowzero anyopaque,
    size: u32,
    alignment: u32,
    flags: Gfp,

    pub fn init(name: [*:0]const u8, size: u32, alignment: u32, kmem_flags: u32, ctor: *allowzero const fn (*anyopaque) callconv(.C) void, flags: Gfp) Self {
        const args: KMemCacheArgs = .{ .alignment = alignment, .ctor = ctor };
        const s = __kmem_cache_create_args(name, size, &args, kmem_flags);
        return .{
            .s = s,
            .size = size,
            .alignment = @ctz(alignment),
            .flags = flags,
        };
    }

    pub fn allocator(self: *Self) mem.Allocator {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &VTable,
        };
    }

    fn alloc(ctx: *anyopaque, size: usize, alignment: u8, ret_addr: usize) ?[*]u8 {
        _ = ret_addr;

        const ka: *Self = @alignCast(@ptrCast(ctx));
        if (size != ka.size) return null;
        if (alignment > ka.alignment) return null;

        const ptr = kmem_cache_alloc_lru_noprof(ka.s, @ptrFromInt(0), @bitCast(ka.flags));
        if (ptr == NULL) {
            return null;
        } else {
            return @ptrCast(ptr);
        }
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: u8, ret_addr: usize) void {
        _ = ret_addr;

        const ka: *Self = @alignCast(@ptrCast(ctx));
        if (alignment > ka.alignment) return;

        kmem_cache_free(ka.s, @ptrCast(memory.ptr));
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: u8, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        return false;
    }
};

const LogError = error{};
fn log_write(ctx: void, bytes: []const u8) LogError!usize {
    _ = ctx;
    var buffer: [4096:0]u8 = undefined;

    var leftover = bytes.len;
    var ptr = bytes.ptr;
    while (leftover != 0) {
        const nbytes = @min(buffer.len, leftover);
        @memcpy(buffer[0..nbytes], ptr[0..nbytes]);
        buffer[nbytes] = 0;
        printk("%s", &buffer);

        leftover -= nbytes;
        ptr += nbytes;
    }

    return bytes.len;
}
const Log = std.io.Writer(void, LogError, log_write);
pub const log = Log{ .context = {} };
pub fn print(comptime format: []const u8, args: anytype) void {
    var logbuf: [0x1000]u8 = undefined;
    const slice = std.fmt.bufPrint(&logbuf, format, args) catch @panic("failed to format");
    log.print("{s}", .{slice}) catch {};
}
