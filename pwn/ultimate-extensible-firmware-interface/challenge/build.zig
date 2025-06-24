const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.resolveTargetQuery(std.Target.Query{
        .cpu_arch = std.Target.Cpu.Arch.x86_64,
        .os_tag = std.Target.Os.Tag.uefi,
    });

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = std.builtin.OptimizeMode.ReleaseFast;

    const exe = b.addExecutable(.{
        .name = "uefi",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = false,
    });

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    const create_dirs = b.addSystemCommand(&.{ "mkdir", "-p", "contents/EFI/BOOT" });
    create_dirs.step.dependOn(b.getInstallStep());

    const copy_bootloader = b.addSystemCommand(&.{"cp"});
    copy_bootloader.addArtifactArg(exe);
    copy_bootloader.addArgs(&.{"contents/EFI/BOOT/BOOTX64.EFI"});
    copy_bootloader.step.dependOn(&create_dirs.step);

    const copy_pdb = b.addSystemCommand(&.{"cp"});
    copy_pdb.addFileArg(exe.getEmittedPdb());
    copy_pdb.addArgs(&.{"contents"});
    copy_pdb.step.dependOn(&create_dirs.step);

    const pkg = b.step("pkg", "");
    pkg.dependOn(&copy_bootloader.step);
    pkg.dependOn(&copy_pdb.step);

    const launch = b.addSystemCommand(&.{"./run.sh"});
    launch.step.dependOn(pkg);

    const run = b.step("run", "");
    run.dependOn(&launch.step);
}
