const std = @import("std");

const Target = enum {
    x86_64,
    arm,
    aarch64,
    riscv32,
    riscv64,
    mips,
    mipsel,
    mips64,
    mips64el,
    sparc,
    sparc64,
    m68k,
    ppc,
    // ppc64,
    s390x,
    tricore,
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("unizorn", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/root.zig"),
    });

    if (b.systemIntegrationOption("unicorn", .{})) {
        mod.linkSystemLibrary("unicorn", .{});
        mod.linkSystemLibrary("c", .{});
    } else {
        const unicorn_targets = b.option([]Target, "unicorn_targets", "List of supported unicorn targets") orelse &[_]Target{
            .x86_64,
            .arm,
            .aarch64,
            .riscv32,
            .riscv64,
            .mips,
            .mipsel,
            .mips64,
            .mips64el,
            .sparc,
            .sparc64,
            .m68k,
            .ppc,
            // ppc64,
            .s390x,
            .tricore,
        };
        const unicorn = try buildUnicorn(b, target, optimize, unicorn_targets);
        mod.linkLibrary(unicorn);
    }

    const unizorn_test = b.addTest(.{
        .name = "unizorn",
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });
    unizorn_test.root_module.addImport("unizorn", mod);

    const unizorn_test_run = b.addRunArtifact(unizorn_test);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&unizorn_test_run.step);
}

fn buildUnicorn(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    unicorn_targets: []const Target,
) !*std.Build.Step.Compile {
    // windows neet little patch to use win32 api on mingw
    const dep_name = if (target.result.os.tag == .windows) "unicorn-fork" else "unicorn";
    const unicorn = b.lazyDependency(dep_name, .{}) orelse return error.FetchNeeded;

    const unicorn_common = b.addStaticLibrary(.{
        .name = "unicorn-common",
        .target = target,
        .optimize = optimize,
    });
    unicorn_common.linkLibC();

    unicorn_common.addIncludePath(unicorn.path("glib_compat"));
    unicorn_common.addIncludePath(unicorn.path("qemu"));
    unicorn_common.addIncludePath(unicorn.path("qemu/include"));
    unicorn_common.addIncludePath(unicorn.path("qemu/include/qemu"));
    unicorn_common.addIncludePath(unicorn.path("include"));
    unicorn_common.addIncludePath(unicorn.path("qemu/tcg"));
    const flags =
        &.{
        // "-D_WIN32",
        // "-DUNICORN_TRACER",
    };

    unicorn_common.addCSourceFiles(.{
        .root = unicorn.path(""),
        .files = &.{
            "list.c",

            "glib_compat/glib_compat.c",
            "glib_compat/gtestutils.c",
            "glib_compat/garray.c",
            "glib_compat/gtree.c",
            "glib_compat/grand.c",
            "glib_compat/glist.c",
            "glib_compat/gmem.c",
            "glib_compat/gpattern.c",
            "glib_compat/gslice.c",

            "qemu/util/bitmap.c",
            "qemu/util/bitops.c",
            "qemu/util/crc32c.c",
            "qemu/util/cutils.c",
            "qemu/util/getauxval.c",
            "qemu/util/guest-random.c",
            "qemu/util/host-utils.c",
            "qemu/util/osdep.c",
            "qemu/util/qdist.c",
            "qemu/util/qemu-timer.c",
            "qemu/util/qemu-timer-common.c",
            "qemu/util/range.c",
            "qemu/util/qht.c",
            "qemu/util/pagesize.c",
            "qemu/util/cacheinfo.c",

            "qemu/crypto/aes.c",
        },
        .flags = flags,
    });
    unicorn_common.linkLibC();

    const config_host = b.addConfigHeader(.{
        .style = .blank,
        .include_path = "config-host.h",
    }, .{
        .CONFIG_QEMU_CONFDIR = "/usr/local/etc/qemu",
        .CONFIG_QEMU_LOCALSTATEDIR = "/usr/local/var",
        .CONFIG_QEMU_HELPERDIR = "/usr/local/libexec",
        .CONFIG_QEMU_LOCALEDIR = "/locale",
        .QEMU_VERSION = "5.0.1",
        .QEMU_VERSION_MAJOR = 5,
        .QEMU_VERSION_MINOR = 0,
        .QEMU_VERSION_MICRO = 1,
        .CONFIG_TCG = 1,
        .CONFIG_AVX2_OPT = 1,
        .CONFIG_CPUID_H = 1,
        .CONFIG_ATOMIC64 = 1,
        .CONFIG_ATTRIBUTE_ALIAS = 1,
        .CONFIG_SYSMACROS = 1,
        .CONFIG_STATIC_ASSERT = 1,
        .CONFIG_INT128 = 1,
        .HAVE_UTMPX = 1,
        .CONFIG_GETRANDOM = 1,
        .CONFIG_THREAD_SETNAME_BYTHREAD = 1,
        .CONFIG_PTHREAD_SETNAME_NP_W_TID = 1,
        .HOST_DSOSUF = ".so",
    });

    switch (target.result.cpu.arch) {
        .x86 => {
            config_host.addValues(.{
                .HOST_X86 = 1,
            });
        },
        .x86_64 => {
            config_host.addValues(.{
                .HOST_X86_64 = 1,
            });
        },
        .aarch64 => {
            config_host.addValues(.{
                .HOST_AARCH64 = 1,
            });
        },
        else => @panic("TODO"),
    }

    switch (target.result.os.tag) {
        .linux => {
            config_host.addValues(.{
                .CONFIG_POSIX = 1,
                .CONFIG_POSIX_MADVISE = 1,
                .CONFIG_POSIX_MEMALIGN = 1,

                .CONFIG_LINUX = 1,
                .CONFIG_LINUX_MAGIC_H = 1,

                .CONFIG_BYTESWAP_H = 1,
                .CONFIG_GETAUXVAL = 1,
                .CONFIG_MADVISE = 1,
                .CONFIG_SYNC_FILE_RANGE = 1,
                .CONFIG_DUP3 = 1,
                .CONFIG_PRCTL_PR_SET_TIMERSLACK = 1,
                .CONFIG_EPOLL = 1,
                .CONFIG_CLOCK_ADJTIME = 1,
                .CONFIG_SYNCFS = 1,
                .CONFIG_SEM_TIMEDWAIT = 1,
                .HAVE_STRCHRNUL = 1,
                .HAVE_STRUCT_STAT_ST_ATIM = 1,
                .CONFIG_SIGNALFD = 1,
                .CONFIG_MALLOC_TRIM = 1,
                .CONFIG_OPEN_BY_HANDLE = 1,
                .CONFIG_PRAGMA_DIAGNOSTIC_AVAILABLE = 1,
                .CONFIG_HAS_ENVIRON = 1,
            });
        },
        .windows => {
            config_host.addValues(.{
                // .CONFIG_POSIX = 1,
                .CONFIG_WIN32 = 1,
            });
        },
        .macos, .freebsd, .openbsd => {
            config_host.addValues(.{
                .CONFIG_POSIX = 1,
                .CONFIG_POSIX_MEMALIGN = 1,
                .CONFIG_MADVISE = 1,
            });
        },
        else => @panic("TODO"),
    }
    // TODO:
    // .CONFIG_CMPXCHG128 = 1,

    unicorn_common.addConfigHeader(config_host);

    var targets = std.ArrayList(*std.Build.Step.Compile).init(b.allocator);
    for (unicorn_targets) |t| {
        try targets.append(try createTarget(b, target, optimize, unicorn, config_host, t, flags));
    }

    const lib = b.addStaticLibrary(.{
        .name = "unicorn",
        .target = target,
        .optimize = .ReleaseFast,
    });

    const lib_flags = &.{
        "-DUNICORN_HAS_X86",
        "-DUNICORN_HAS_ARM",
        "-DUNICORN_HAS_AARCH64",
        "-DUNICORN_HAS_RISCV",
        "-DUNICORN_HAS_MIPS",
        "-DUNICORN_HAS_MIPSEL",
        "-DUNICORN_HAS_MIPS64",
        "-DUNICORN_HAS_MIPS64EL",
        "-DUNICORN_HAS_SPARC",
        "-DUNICORN_HAS_M64K",
        // "-DUNICORN_HAS_PPC",
        "-DUNICORN_HAS_S390",
        "-DUNICORN_HAS_TRICORE",
        // "-D_WIN32",
    };

    lib.addCSourceFiles(.{
        .root = unicorn.path(""),
        .files = &.{
            "uc.c",
            "qemu/softmmu/vl.c",
            "qemu/hw/core/cpu.c",
        },
        .flags = lib_flags,
    });

    switch (target.result.os.tag) {
        .linux, .macos, .freebsd, .openbsd => {
            lib.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/util/oslib-posix.c",
                    "qemu/util/qemu-thread-posix.c",
                },
                .flags = lib_flags,
            });
        },
        .windows => {
            lib.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/util/oslib-win32.c",
                    "qemu/util/qemu-thread-win32.c",
                },
                .flags = lib_flags,
            });
            // lib.addAssemblyFile(unicorn.path("qemu/util/setjmp-wrapper-win32.asm"));
        },
        else => |t| @panic(b.fmt("Add support for {}", .{t})),
    }

    lib.addIncludePath(unicorn.path("glib_compat"));
    lib.addIncludePath(unicorn.path("include"));
    lib.addIncludePath(unicorn.path("qemu/include"));
    lib.addIncludePath(unicorn.path("qemu"));
    lib.addConfigHeader(config_host);
    lib.linkLibrary(unicorn_common);
    for (targets.items) |t| {
        lib.linkLibrary(t);
    }

    lib.installHeadersDirectory(unicorn.path("include"), "", .{});

    b.installArtifact(lib);

    return lib;
}

fn createTarget(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    unicorn: *std.Build.Dependency,
    config_host: *std.Build.Step.ConfigHeader,
    unicorn_target: Target,
    flags: []const []const u8,
) !*std.Build.Step.Compile {
    _ = optimize;
    const softmmu = b.addStaticLibrary(.{
        .name = b.fmt("{s}-softmmu", .{@tagName(unicorn_target)}),
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    softmmu.linkLibC();

    const config_target = b.addConfigHeader(.{
        .style = .blank,
        .include_path = "config-target.h",
    }, .{});

    softmmu.addConfigHeader(config_host);
    softmmu.addConfigHeader(config_target);

    switch (target.result.cpu.arch) {
        .x86_64, .x86 => {
            softmmu.addIncludePath(unicorn.path("qemu/tcg/i386"));
        },
        .aarch64 => {
            softmmu.addIncludePath(unicorn.path("qemu/tcg/aarch64"));
        },
        else => unreachable,
    }

    softmmu.addIncludePath(unicorn.path("glib_compat"));
    softmmu.addIncludePath(unicorn.path("qemu"));
    softmmu.addIncludePath(unicorn.path("qemu/include"));
    softmmu.addIncludePath(unicorn.path("include"));
    softmmu.addIncludePath(unicorn.path("qemu/tcg"));

    var softmmu_flags = std.ArrayList([]const u8).init(b.allocator);
    try softmmu_flags.appendSlice(flags);
    try softmmu_flags.appendSlice(&.{
        "-DNEED_CPU_H",
        "-DCONFIG_STATIC_ASSERT=1",
        // "-DUNICORN_TRACER",
        "-include",
        unicorn.builder.pathFromRoot(b.fmt("qemu/{s}.h", .{@tagName(unicorn_target)})),
    });

    softmmu.addCSourceFiles(.{
        .root = unicorn.path(""),
        .files = &.{
            "qemu/exec.c",
            "qemu/exec-vary.c",

            "qemu/softmmu/cpus.c",
            "qemu/softmmu/ioport.c",
            "qemu/softmmu/memory.c",
            "qemu/softmmu/memory_mapping.c",

            "qemu/fpu/softfloat.c",

            "qemu/tcg/optimize.c",
            "qemu/tcg/tcg.c",
            "qemu/tcg/tcg-op.c",
            "qemu/tcg/tcg-op-gvec.c",
            "qemu/tcg/tcg-op-vec.c",

            "qemu/accel/tcg/cpu-exec.c",
            "qemu/accel/tcg/cpu-exec-common.c",
            "qemu/accel/tcg/cputlb.c",
            "qemu/accel/tcg/tcg-all.c",
            "qemu/accel/tcg/tcg-runtime.c",
            "qemu/accel/tcg/tcg-runtime-gvec.c",
            "qemu/accel/tcg/translate-all.c",
            "qemu/accel/tcg/translator.c",
        },
        .flags = softmmu_flags.items,
    });

    switch (unicorn_target) {
        .x86_64 => {
            config_target.addValues(.{
                .TARGET_I386 = 1,
                .TARGET_X86_64 = 1,
                .TARGET_NAME = "x86_64",
                .CONFIG_SOFTMMU = 1,
            });
            softmmu.addIncludePath(unicorn.path("qemu/target/i386"));
            softmmu.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/hw/i386/x86.c",
                    "qemu/target/i386/arch_memory_mapping.c",
                    "qemu/target/i386/bpt_helper.c",
                    "qemu/target/i386/cc_helper.c",
                    "qemu/target/i386/cpu.c",
                    "qemu/target/i386/excp_helper.c",
                    "qemu/target/i386/fpu_helper.c",
                    "qemu/target/i386/helper.c",
                    "qemu/target/i386/int_helper.c",
                    "qemu/target/i386/machine.c",
                    "qemu/target/i386/mem_helper.c",
                    "qemu/target/i386/misc_helper.c",
                    "qemu/target/i386/mpx_helper.c",
                    "qemu/target/i386/seg_helper.c",
                    "qemu/target/i386/smm_helper.c",
                    "qemu/target/i386/svm_helper.c",
                    "qemu/target/i386/translate.c",
                    "qemu/target/i386/xsave_helper.c",
                    "qemu/target/i386/unicorn.c",
                },
                .flags = softmmu_flags.items,
            });
        },
        .arm => {
            config_target.addValues(.{
                .TARGET_ARM = 1,
                .TARGET_NAME = "arm",
                .CONFIG_SOFTMMU = 1,
                .TARGET_SYSTBL_ABI = .@"common,oabi",
                .TARGET_SUPPORTS_MTTCG = 1,
            });
            softmmu.addIncludePath(unicorn.path("qemu/target/arm"));
            softmmu.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/target/arm/cpu.c",
                    "qemu/target/arm/crypto_helper.c",
                    "qemu/target/arm/debug_helper.c",
                    "qemu/target/arm/helper.c",
                    "qemu/target/arm/iwmmxt_helper.c",
                    "qemu/target/arm/m_helper.c",
                    "qemu/target/arm/neon_helper.c",
                    "qemu/target/arm/op_helper.c",
                    "qemu/target/arm/psci.c",
                    "qemu/target/arm/tlb_helper.c",
                    "qemu/target/arm/translate.c",
                    "qemu/target/arm/vec_helper.c",
                    "qemu/target/arm/vfp_helper.c",
                    "qemu/target/arm/unicorn_arm.c",
                },
                .flags = softmmu_flags.items,
            });
        },
        .aarch64 => {
            config_target.addValues(.{
                .TARGET_ARM = 1,
                .TARGET_AARCH64 = 1,
                .TARGET_NAME = "aarch64",
                .CONFIG_SOFTMMU = 1,
            });
            softmmu.addIncludePath(unicorn.path("qemu/target/arm"));
            softmmu.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/target/arm/cpu64.c",
                    "qemu/target/arm/cpu.c",
                    "qemu/target/arm/crypto_helper.c",
                    "qemu/target/arm/debug_helper.c",
                    "qemu/target/arm/helper-a64.c",
                    "qemu/target/arm/helper.c",
                    "qemu/target/arm/iwmmxt_helper.c",
                    "qemu/target/arm/m_helper.c",
                    "qemu/target/arm/neon_helper.c",
                    "qemu/target/arm/op_helper.c",
                    "qemu/target/arm/pauth_helper.c",
                    "qemu/target/arm/psci.c",
                    "qemu/target/arm/sve_helper.c",
                    "qemu/target/arm/tlb_helper.c",
                    "qemu/target/arm/translate-a64.c",
                    "qemu/target/arm/translate.c",
                    "qemu/target/arm/translate-sve.c",
                    "qemu/target/arm/vec_helper.c",
                    "qemu/target/arm/vfp_helper.c",
                    "qemu/target/arm/unicorn_aarch64.c",
                },
                .flags = softmmu_flags.items,
            });
        },
        .riscv32, .riscv64 => |r| {
            config_target.addValues(.{
                .TARGET_RISCV = 1,
                .TARGET_NAME = @tagName(r),
                .CONFIG_SOFTMMU = 1,
                // .TARGET_SYSTBL_ABI = .@"common,oabi",
                .TARGET_SUPPORTS_MTTCG = 1,
            });
            switch (r) {
                .riscv32 => {
                    config_target.addValues(.{
                        .TARGET_RISCV32 = 1,
                    });
                },
                .riscv64 => {
                    config_target.addValues(.{
                        .TARGET_RISCV64 = 1,
                    });
                },
                else => unreachable,
            }
            softmmu.addIncludePath(unicorn.path("qemu/target/riscv"));
            softmmu.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/target/riscv/cpu.c",
                    "qemu/target/riscv/cpu_helper.c",
                    "qemu/target/riscv/csr.c",
                    "qemu/target/riscv/fpu_helper.c",
                    "qemu/target/riscv/op_helper.c",
                    "qemu/target/riscv/pmp.c",
                    "qemu/target/riscv/translate.c",
                    "qemu/target/riscv/unicorn.c",
                },
                .flags = softmmu_flags.items,
            });
        },
        .mips, .mipsel, .mips64, .mips64el => |r| {
            config_target.addValues(.{
                .TARGET_MIPS = 1,
                .TARGET_NAME = @tagName(r),
                .CONFIG_SOFTMMU = 1,
            });
            switch (r) {
                .mips => {
                    config_target.addValues(.{
                        .TARGET_ABI_MIPSO32 = 1,
                        .TARGET_WORDS_BIGENDIAN = 1,
                    });
                },
                .mipsel => {
                    config_target.addValues(.{
                        .TARGET_ABI_MIPSO32 = 1,
                    });
                },
                .mips64 => {
                    config_target.addValues(.{
                        .TARGET_MIPS64 = 1,
                        .TARGET_ABI_MIPSN64 = 1,
                        .TARGET_WORDS_BIGENDIAN = 1,
                    });
                },
                .mips64el => {
                    config_target.addValues(.{
                        .TARGET_MIPS64 = 1,
                        .TARGET_ABI_MIPSN64 = 1,
                    });
                },

                else => unreachable,
            }
            softmmu.addIncludePath(unicorn.path("qemu/target/mips"));
            softmmu.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/target/mips/cp0_helper.c",
                    "qemu/target/mips/cp0_timer.c",
                    "qemu/target/mips/cpu.c",
                    "qemu/target/mips/dsp_helper.c",
                    "qemu/target/mips/fpu_helper.c",
                    "qemu/target/mips/helper.c",
                    "qemu/target/mips/lmi_helper.c",
                    "qemu/target/mips/msa_helper.c",
                    "qemu/target/mips/op_helper.c",
                    "qemu/target/mips/translate.c",
                    "qemu/target/mips/unicorn.c",
                },
                .flags = softmmu_flags.items,
            });
        },
        .sparc, .sparc64 => |r| {
            config_target.addValues(.{
                .TARGET_SPARC = 1,
                .TARGET_NAME = @tagName(r),
                .CONFIG_SOFTMMU = 1,
                .TARGET_WORDS_BIGENDIAN = 1,
            });
            switch (r) {
                .sparc => {},
                .sparc64 => {
                    config_target.addValues(.{
                        .TARGET_SPARC64 = 1,
                    });
                },
                else => unreachable,
            }
            softmmu.addIncludePath(unicorn.path("qemu/target/sparc"));
            softmmu.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/target/sparc/cc_helper.c",
                    "qemu/target/sparc/cpu.c",
                    "qemu/target/sparc/fop_helper.c",
                    "qemu/target/sparc/helper.c",
                    switch (r) {
                        .sparc => "qemu/target/sparc/int32_helper.c",
                        .sparc64 => "qemu/target/sparc/int64_helper.c",
                        else => unreachable,
                    },
                    "qemu/target/sparc/ldst_helper.c",
                    "qemu/target/sparc/mmu_helper.c",
                    "qemu/target/sparc/translate.c",
                    "qemu/target/sparc/win_helper.c",
                    switch (r) {
                        .sparc => "qemu/target/sparc/unicorn.c",
                        .sparc64 => "qemu/target/sparc/unicorn64.c",
                        else => unreachable,
                    },
                },
                .flags = softmmu_flags.items,
            });
            if (r == .sparc64) {
                softmmu.addCSourceFiles(.{
                    .root = unicorn.path(""),
                    .files = &.{
                        "qemu/target/sparc/vis_helper.c",
                    },
                    .flags = softmmu_flags.items,
                });
            }
        },
        .m68k => |r| {
            config_target.addValues(.{
                .TARGET_M68K = 1,
                .TARGET_NAME = @tagName(r),
                .CONFIG_SOFTMMU = 1,
                .TARGET_WORDS_BIGENDIAN = 1,
            });
            softmmu.addIncludePath(unicorn.path("qemu/target/m68k"));
            softmmu.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/target/m68k/cpu.c",
                    "qemu/target/m68k/fpu_helper.c",
                    "qemu/target/m68k/helper.c",
                    "qemu/target/m68k/op_helper.c",
                    "qemu/target/m68k/softfloat.c",
                    "qemu/target/m68k/translate.c",
                    "qemu/target/m68k/unicorn.c",
                },
                .flags = softmmu_flags.items,
            });
        },
        .ppc => |r| {
            config_target.addValues(.{
                .TARGET_PPC = 1,
                .TARGET_NAME = @tagName(r),
                .CONFIG_SOFTMMU = 1,
                .TARGET_WORDS_BIGENDIAN = 1,
            });
            softmmu.addIncludePath(unicorn.path("qemu/target/ppc"));
            softmmu.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/hw/ppc/ppc.c",
                    "qemu/hw/ppc/ppc_booke.c",

                    "qemu/libdecnumber/decContext.c",
                    "qemu/libdecnumber/decNumber.c",
                    "qemu/libdecnumber/dpd/decimal128.c",
                    "qemu/libdecnumber/dpd/decimal32.c",
                    "qemu/libdecnumber/dpd/decimal64.c",

                    "qemu/target/ppc/cpu.c",
                    "qemu/target/ppc/cpu-models.c",
                    "qemu/target/ppc/dfp_helper.c",
                    "qemu/target/ppc/excp_helper.c",
                    "qemu/target/ppc/fpu_helper.c",
                    "qemu/target/ppc/int_helper.c",
                    "qemu/target/ppc/machine.c",
                    "qemu/target/ppc/mem_helper.c",
                    "qemu/target/ppc/misc_helper.c",
                    "qemu/target/ppc/mmu-hash32.c",
                    "qemu/target/ppc/mmu_helper.c",
                    "qemu/target/ppc/timebase_helper.c",
                    "qemu/target/ppc/translate.c",
                    "qemu/target/ppc/unicorn.c",
                },
                .flags = softmmu_flags.items,
            });
        },
        // .ppc64 => |r| {
        //     config_target.addValues(.{
        //         .TARGET_PPC = 1,
        //         .TARGET_NAME = @tagName(r),
        //         .CONFIG_SOFTMMU = 1,
        //         .TARGET_WORDS_BIGENDIAN = 1,
        //         .TARGET_PPC64 = 1,
        //     });
        //     softmmu.addIncludePath(unicorn.path("qemu/target/ppc"));
        //     softmmu.addCSourceFiles(.{
        //         .root = unicorn.path(""),
        //         .files = &.{
        //             "qemu/hw/ppc/ppc.c",
        //             "qemu/hw/ppc/ppc_booke.c",

        //             "qemu/libdecnumber/decContext.c",
        //             "qemu/libdecnumber/decNumber.c",
        //             "qemu/libdecnumber/dpd/decimal128.c",
        //             "qemu/libdecnumber/dpd/decimal32.c",
        //             "qemu/libdecnumber/dpd/decimal64.c",

        //             "qemu/target/ppc/compat.c",
        //             "qemu/target/ppc/cpu.c",
        //             "qemu/target/ppc/cpu-models.c",
        //             "qemu/target/ppc/dfp_helper.c",
        //             "qemu/target/ppc/excp_helper.c",
        //             "qemu/target/ppc/fpu_helper.c",
        //             "qemu/target/ppc/int_helper.c",
        //             "qemu/target/ppc/machine.c",
        //             "qemu/target/ppc/mem_helper.c",
        //             "qemu/target/ppc/misc_helper.c",
        //             "qemu/target/ppc/mmu-book3s-v3.c",
        //             "qemu/target/ppc/mmu-hash32.c",
        //             "qemu/target/ppc/mmu-hash64.c",
        //             "qemu/target/ppc/mmu_helper.c",
        //             "qemu/target/ppc/mmu-radix64.c",
        //             "qemu/target/ppc/timebase_helper.c",
        //             "qemu/target/ppc/translate.c",
        //             "qemu/target/ppc/unicorn.c",
        //         },
        //         .flags = softmmu_flags.items,
        //     });
        // },
        .s390x => |r| {
            config_target.addValues(.{
                .TARGET_S390x = 1,
                .TARGET_NAME = @tagName(r),
                .CONFIG_SOFTMMU = 1,
                .TARGET_SYSTBL_ABI = "common,64",
                .TARGET_WORDS_BIGENDIAN = 1,
                .TARGET_SUPPORTS_MTTCG = 1,
            });
            softmmu.addIncludePath(unicorn.path("qemu/target/s390x"));
            softmmu.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/hw/s390x/s390-skeys.c",

                    "qemu/target/s390x/cc_helper.c",
                    "qemu/target/s390x/cpu.c",
                    "qemu/target/s390x/cpu_features.c",
                    "qemu/target/s390x/cpu_models.c",
                    "qemu/target/s390x/crypto_helper.c",
                    "qemu/target/s390x/excp_helper.c",
                    "qemu/target/s390x/fpu_helper.c",
                    "qemu/target/s390x/helper.c",
                    "qemu/target/s390x/interrupt.c",
                    "qemu/target/s390x/int_helper.c",
                    "qemu/target/s390x/ioinst.c",
                    "qemu/target/s390x/mem_helper.c",
                    "qemu/target/s390x/misc_helper.c",
                    "qemu/target/s390x/mmu_helper.c",
                    "qemu/target/s390x/sigp.c",
                    "qemu/target/s390x/tcg-stub.c",
                    "qemu/target/s390x/translate.c",
                    "qemu/target/s390x/vec_fpu_helper.c",
                    "qemu/target/s390x/vec_helper.c",
                    "qemu/target/s390x/vec_int_helper.c",
                    "qemu/target/s390x/vec_string_helper.c",
                    "qemu/target/s390x/unicorn.c",
                },
                .flags = softmmu_flags.items,
            });
        },
        .tricore => |r| {
            config_target.addValues(.{
                .TARGET_TRICORE = 1,
                .TARGET_NAME = @tagName(r),
                .CONFIG_SOFTMMU = 1,
            });
            softmmu.addIncludePath(unicorn.path("qemu/target/tricore"));
            softmmu.addCSourceFiles(.{
                .root = unicorn.path(""),
                .files = &.{
                    "qemu/target/tricore/cpu.c",
                    "qemu/target/tricore/fpu_helper.c",
                    "qemu/target/tricore/helper.c",
                    "qemu/target/tricore/op_helper.c",
                    "qemu/target/tricore/translate.c",
                    "qemu/target/tricore/unicorn.c",
                },
                .flags = softmmu_flags.items,
            });
        },
    }

    return softmmu;
}
