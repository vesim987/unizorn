const std = @import("std");
pub const c = @cImport({
    @cInclude("unicorn/unicorn.h");
});

pub const Error = error{
    NoMem,
    Arch,
    Handle,
    Mode,
    Version,
    ReadUnmapped,
    WriteUnmapped,
    FetchUnmapped,
    Hook,
    InsnInvalid,
    Map,
    WriteProt,
    ReadProt,
    FetchProt,
    Arg,
    ReadUnaligned,
    WriteUnaligned,
    FetchUnaligned,
    HookExists,
    Resource,
    Exception,
};

fn zig_error_from_uc_err(err: c.uc_err) Error!void {
    switch (err) {
        c.UC_ERR_OK => {},
        c.UC_ERR_NOMEM => return Error.NoMem,
        c.UC_ERR_ARCH => return Error.Arch,
        c.UC_ERR_HANDLE => return Error.Handle,
        c.UC_ERR_MODE => return Error.Mode,
        c.UC_ERR_VERSION => return Error.Version,
        c.UC_ERR_READ_UNMAPPED => return Error.ReadUnmapped,
        c.UC_ERR_WRITE_UNMAPPED => return Error.WriteUnmapped,
        c.UC_ERR_FETCH_UNMAPPED => return Error.FetchUnmapped,
        c.UC_ERR_HOOK => return Error.Hook,
        c.UC_ERR_INSN_INVALID => return Error.InsnInvalid,
        c.UC_ERR_MAP => return Error.Map,
        c.UC_ERR_WRITE_PROT => return Error.ReadProt,
        c.UC_ERR_READ_PROT => return Error.WriteProt,
        c.UC_ERR_FETCH_PROT => return Error.FetchProt,
        c.UC_ERR_ARG => return Error.Arg,
        c.UC_ERR_READ_UNALIGNED => return Error.ReadUnaligned,
        c.UC_ERR_WRITE_UNALIGNED => return Error.WriteUnaligned,
        c.UC_ERR_FETCH_UNALIGNED => return Error.FetchUnaligned,
        c.UC_ERR_HOOK_EXIST => return Error.HookExists,
        c.UC_ERR_RESOURCE => return Error.Resource,
        c.UC_ERR_EXCEPTION => return Error.Exception,
        else => std.debug.panic("Invalid unicorn error: {}", .{err}),
    }
}

pub const Arch = enum(c.uc_arch) {
    X86 = c.UC_ARCH_X86,
    Arm = c.UC_ARCH_ARM,
    Arm64 = c.UC_ARCH_ARM64,
    Mips = c.UC_ARCH_MIPS,
    Ppc = c.UC_ARCH_PPC,
    Sparc = c.UC_ARCH_SPARC,
    M68k = c.UC_ARCH_M68K,
    Riscv = c.UC_ARCH_RISCV,
    S390x = c.UC_ARCH_S390X,
    Tricore = c.UC_ARCH_TRICORE,
    _,
};

pub const Mode = enum(c_uint) {
    pub const LittleEndian = from_uc_mode(c.UC_MODE_LITTLE_ENDIAN);
    pub const BigEndian = from_uc_mode(c.UC_MODE_BIG_ENDIAN);
    pub const Arm = from_uc_mode(c.UC_MODE_ARM);
    pub const Thumb = from_uc_mode(c.UC_MODE_THUMB);
    pub const MClass = from_uc_mode(c.UC_MODE_MCLASS);
    pub const V8 = from_uc_mode(c.UC_MODE_V8);
    pub const ArmBe8 = from_uc_mode(c.UC_MODE_ARMBE8);
    pub const Arm926 = from_uc_mode(c.UC_MODE_ARM926);
    pub const Arm846 = from_uc_mode(c.UC_MODE_ARM946);
    pub const Arm1176 = from_uc_mode(c.UC_MODE_ARM1176);
    pub const Micro = from_uc_mode(c.UC_MODE_MICRO);
    pub const Misp3 = from_uc_mode(c.UC_MODE_MIPS3);
    pub const Mips32R6 = from_uc_mode(c.UC_MODE_MIPS32R6);
    pub const Mips32 = from_uc_mode(c.UC_MODE_MIPS32);
    pub const Mips64 = from_uc_mode(c.UC_MODE_MIPS64);
    pub const Mode16 = from_uc_mode(c.UC_MODE_16);
    pub const Mode32 = from_uc_mode(c.UC_MODE_32);
    pub const Mode64 = from_uc_mode(c.UC_MODE_64);
    pub const Ppc32 = from_uc_mode(c.UC_MODE_PPC32);
    pub const Ppc64 = from_uc_mode(c.UC_MODE_PPC64);
    pub const Qpx = from_uc_mode(c.UC_MODE_QPX);
    pub const Sparc32 = from_uc_mode(c.UC_MODE_SPARC32);
    pub const Sparc64 = from_uc_mode(c.UC_MODE_SPARC64);
    pub const V9 = from_uc_mode(c.UC_MODE_V9);
    pub const Riscv32 = from_uc_mode(c.UC_MODE_RISCV32);
    pub const Riscv64 = from_uc_mode(c.UC_MODE_RISCV64);

    pub fn o(self: Mode, other: Mode) Mode {
        return @enumFromInt(@intFromEnum(self) | @intFromEnum(other));
    }

    fn from_uc_mode(reg: c_int) Mode {
        return @enumFromInt(reg);
    }

    _,
};

pub const Cpu = enum(c_int) {
    pub const X86 = struct {
        pub const QEMU64 = from_uc_cpu(c.CPU_X86_QEMU64);
        pub const PHENOM = from_uc_cpu(c.CPU_X86_PHENOM);
        pub const CORE2DUO = from_uc_cpu(c.CPU_X86_CORE2DUO);
        pub const KVM64 = from_uc_cpu(c.CPU_X86_KVM64);
        pub const QEMU32 = from_uc_cpu(c.CPU_X86_QEMU32);
        pub const KVM32 = from_uc_cpu(c.CPU_X86_KVM32);
        pub const COREDUO = from_uc_cpu(c.CPU_X86_COREDUO);
        pub const @"486" = from_uc_cpu(c.CPU_X86_486);
        pub const PENTIUM = from_uc_cpu(c.CPU_X86_PENTIUM);
        pub const PENTIUM2 = from_uc_cpu(c.CPU_X86_PENTIUM2);
        pub const PENTIUM3 = from_uc_cpu(c.CPU_X86_PENTIUM3);
        pub const ATHLON = from_uc_cpu(c.CPU_X86_ATHLON);
        pub const N270 = from_uc_cpu(c.CPU_X86_N270);
        pub const CONROE = from_uc_cpu(c.CPU_X86_CONROE);
        pub const PENRYN = from_uc_cpu(c.CPU_X86_PENRYN);
        pub const NEHALEM = from_uc_cpu(c.CPU_X86_NEHALEM);
        pub const WESTMERE = from_uc_cpu(c.CPU_X86_WESTMERE);
        pub const SANDYBRIDGE = from_uc_cpu(c.CPU_X86_SANDYBRIDGE);
        pub const IVYBRIDGE = from_uc_cpu(c.CPU_X86_IVYBRIDGE);
        pub const HASWELL = from_uc_cpu(c.CPU_X86_HASWELL);
        pub const BROADWELL = from_uc_cpu(c.CPU_X86_BROADWELL);
        pub const SKYLAKE_CLIENT = from_uc_cpu(c.CPU_X86_SKYLAKE_CLIENT);
        pub const SKYLAKE_SERVER = from_uc_cpu(c.CPU_X86_SKYLAKE_SERVER);
        pub const CASCADELAKE_SERVER = from_uc_cpu(c.CPU_X86_CASCADELAKE_SERVER);
        pub const COOPERLAKE = from_uc_cpu(c.CPU_X86_COOPERLAKE);
        pub const ICELAKE_CLIENT = from_uc_cpu(c.CPU_X86_ICELAKE_CLIENT);
        pub const ICELAKE_SERVER = from_uc_cpu(c.CPU_X86_ICELAKE_SERVER);
        pub const DENVERTON = from_uc_cpu(c.CPU_X86_DENVERTON);
        pub const SNOWRIDGE = from_uc_cpu(c.CPU_X86_SNOWRIDGE);
        pub const KNIGHTSMILL = from_uc_cpu(c.CPU_X86_KNIGHTSMILL);
        pub const OPTERON_G1 = from_uc_cpu(c.CPU_X86_OPTERON_G1);
        pub const OPTERON_G2 = from_uc_cpu(c.CPU_X86_OPTERON_G2);
        pub const OPTERON_G3 = from_uc_cpu(c.CPU_X86_OPTERON_G3);
        pub const OPTERON_G4 = from_uc_cpu(c.CPU_X86_OPTERON_G4);
        pub const OPTERON_G5 = from_uc_cpu(c.CPU_X86_OPTERON_G5);
        pub const EPYC = from_uc_cpu(c.CPU_X86_EPYC);
        pub const DHYANA = from_uc_cpu(c.CPU_X86_DHYANA);
        pub const EPYC_ROME = from_uc_cpu(c.CPU_X86_EPYC_ROME);
        pub const ENDING = from_uc_cpu(c.CPU_X86_ENDING);
    };

    pub const Arm = struct {
        pub const @"926" = from_uc_cpu(c.UC_CPU_ARM_926);
        pub const @"946" = from_uc_cpu(c.UC_CPU_ARM_946);
        pub const @"1026" = from_uc_cpu(c.UC_CPU_ARM_1026);
        pub const @"1136_R2" = from_uc_cpu(c.UC_CPU_ARM_1136_R2);
        pub const @"1136" = from_uc_cpu(c.UC_CPU_ARM_1136);
        pub const @"1176" = from_uc_cpu(c.UC_CPU_ARM_1176);
        pub const @"11MPCORE" = from_uc_cpu(c.UC_CPU_ARM_11MPCORE);
        pub const CortexM0 = from_uc_cpu(c.UC_CPU_ARM_CORTEX_M0);
        pub const CortexM3 = from_uc_cpu(c.UC_CPU_ARM_CORTEX_M3);
        pub const CortexM4 = from_uc_cpu(c.UC_CPU_ARM_CORTEX_M4);
        pub const CortexM7 = from_uc_cpu(c.UC_CPU_ARM_CORTEX_M7);
        pub const CortexM33 = from_uc_cpu(c.UC_CPU_ARM_CORTEX_M33);
        pub const CortexR5 = from_uc_cpu(c.UC_CPU_ARM_CORTEX_R5);
        pub const CortexR5F = from_uc_cpu(c.UC_CPU_ARM_CORTEX_R5F);
        pub const CortexA7 = from_uc_cpu(c.UC_CPU_ARM_CORTEX_A7);
        pub const CortexA8 = from_uc_cpu(c.UC_CPU_ARM_CORTEX_A8);
        pub const CortexA9 = from_uc_cpu(c.UC_CPU_ARM_CORTEX_A9);
        pub const CortexA15 = from_uc_cpu(c.UC_CPU_ARM_CORTEX_A15);
        pub const TI925T = from_uc_cpu(c.UC_CPU_ARM_TI925T);
        pub const SA1100 = from_uc_cpu(c.UC_CPU_ARM_SA1100);
        pub const SA1110 = from_uc_cpu(c.UC_CPU_ARM_SA1110);
        pub const PXA250 = from_uc_cpu(c.UC_CPU_ARM_PXA250);
        pub const PXA255 = from_uc_cpu(c.UC_CPU_ARM_PXA255);
        pub const PXA260 = from_uc_cpu(c.UC_CPU_ARM_PXA260);
        pub const PXA261 = from_uc_cpu(c.UC_CPU_ARM_PXA261);
        pub const PXA262 = from_uc_cpu(c.UC_CPU_ARM_PXA262);
        pub const PXA270 = from_uc_cpu(c.UC_CPU_ARM_PXA270);
        pub const PXA270A0 = from_uc_cpu(c.UC_CPU_ARM_PXA270A0);
        pub const PXA270A1 = from_uc_cpu(c.UC_CPU_ARM_PXA270A1);
        pub const PXA270B0 = from_uc_cpu(c.UC_CPU_ARM_PXA270B0);
        pub const PXA270B1 = from_uc_cpu(c.UC_CPU_ARM_PXA270B1);
        pub const PXA270C0 = from_uc_cpu(c.UC_CPU_ARM_PXA270C0);
        pub const PXA270C5 = from_uc_cpu(c.UC_CPU_ARM_PXA270C5);
        pub const MAX = from_uc_cpu(c.UC_CPU_ARM_MAX);

        pub const Ending = from_uc_cpu(c.UC_CPU_ARM_ENDING);
    };

    pub const Arm64 = struct {
        pub const A57 = from_uc_cpu(c.CPU_ARM64_A57);
        pub const A53 = from_uc_cpu(c.CPU_ARM64_A53);
        pub const A72 = from_uc_cpu(c.CPU_ARM64_A72);
        pub const MAX = from_uc_cpu(c.CPU_ARM64_MAX);
        pub const ENDING = from_uc_cpu(c.CPU_ARM64_ENDING);
    };

    pub const Mips32 = struct {
        pub const @"4KC" = from_uc_cpu(c.CPU_MIPS32_4KC);
        pub const @"4KM" = from_uc_cpu(c.CPU_MIPS32_4KM);
        pub const @"4KECR1" = from_uc_cpu(c.CPU_MIPS32_4KECR1);
        pub const @"4KEMR1" = from_uc_cpu(c.CPU_MIPS32_4KEMR1);
        pub const @"4KEC" = from_uc_cpu(c.CPU_MIPS32_4KEC);
        pub const @"4KEM" = from_uc_cpu(c.CPU_MIPS32_4KEM);
        pub const @"24KC" = from_uc_cpu(c.CPU_MIPS32_24KC);
        pub const @"24KEC" = from_uc_cpu(c.CPU_MIPS32_24KEC);
        pub const @"24KF" = from_uc_cpu(c.CPU_MIPS32_24KF);
        pub const @"34KF" = from_uc_cpu(c.CPU_MIPS32_34KF);
        pub const @"74KF" = from_uc_cpu(c.CPU_MIPS32_74KF);
        pub const M14K = from_uc_cpu(c.CPU_MIPS32_M14K);
        pub const M14KC = from_uc_cpu(c.CPU_MIPS32_M14KC);
        pub const P5600 = from_uc_cpu(c.CPU_MIPS32_P5600);
        pub const MIPS32R6_GENERIC = from_uc_cpu(c.CPU_MIPS32_MIPS32R6_GENERIC);
        pub const I7200 = from_uc_cpu(c.CPU_MIPS32_I7200);
        pub const ENDING = from_uc_cpu(c.CPU_MIPS32_ENDING);
    };

    pub const Mips64 = struct {
        pub const R4000 = from_uc_cpu(c.CPU_MIPS64_R4000);
        pub const VR5432 = from_uc_cpu(c.CPU_MIPS64_VR5432);
        pub const @"5KC" = from_uc_cpu(c.CPU_MIPS64_5KC);
        pub const @"5KF" = from_uc_cpu(c.CPU_MIPS64_5KF);
        pub const @"20KC" = from_uc_cpu(c.CPU_MIPS64_20KC);
        pub const MIPS64R2_GENERIC = from_uc_cpu(c.CPU_MIPS64_MIPS64R2_GENERIC);
        pub const @"5KEC" = from_uc_cpu(c.CPU_MIPS64_5KEC);
        pub const @"5KEF" = from_uc_cpu(c.CPU_MIPS64_5KEF);
        pub const I6400 = from_uc_cpu(c.CPU_MIPS64_I6400);
        pub const I6500 = from_uc_cpu(c.CPU_MIPS64_I6500);
        pub const LOONGSON_2E = from_uc_cpu(c.CPU_MIPS64_LOONGSON_2E);
        pub const LOONGSON_2F = from_uc_cpu(c.CPU_MIPS64_LOONGSON_2F);
        pub const MIPS64DSPR2 = from_uc_cpu(c.CPU_MIPS64_MIPS64DSPR2);
        pub const ENDING = from_uc_cpu(c.CPU_MIPS64_ENDING);
    };

    pub const Ppc32 = struct {
        pub const @"401" = from_uc_cpu(c.CPU_PPC32_401);
        pub const @"401A1" = from_uc_cpu(c.CPU_PPC32_401A1);
        pub const @"401B2" = from_uc_cpu(c.CPU_PPC32_401B2);
        pub const @"401C2" = from_uc_cpu(c.CPU_PPC32_401C2);
        pub const @"401D2" = from_uc_cpu(c.CPU_PPC32_401D2);
        pub const @"401E2" = from_uc_cpu(c.CPU_PPC32_401E2);
        pub const @"401F2" = from_uc_cpu(c.CPU_PPC32_401F2);
        pub const @"401G2" = from_uc_cpu(c.CPU_PPC32_401G2);
        pub const IOP480 = from_uc_cpu(c.CPU_PPC32_IOP480);
        pub const COBRA = from_uc_cpu(c.CPU_PPC32_COBRA);
        pub const @"403GA" = from_uc_cpu(c.CPU_PPC32_403GA);
        pub const @"403GB" = from_uc_cpu(c.CPU_PPC32_403GB);
        pub const @"403GC" = from_uc_cpu(c.CPU_PPC32_403GC);
        pub const @"403GCX" = from_uc_cpu(c.CPU_PPC32_403GCX);
        pub const @"405D2" = from_uc_cpu(c.CPU_PPC32_405D2);
        pub const @"405D4" = from_uc_cpu(c.CPU_PPC32_405D4);
        pub const @"405CRA" = from_uc_cpu(c.CPU_PPC32_405CRA);
        pub const @"405CRB" = from_uc_cpu(c.CPU_PPC32_405CRB);
        pub const @"405CRC" = from_uc_cpu(c.CPU_PPC32_405CRC);
        pub const @"405EP" = from_uc_cpu(c.CPU_PPC32_405EP);
        pub const @"405EZ" = from_uc_cpu(c.CPU_PPC32_405EZ);
        pub const @"405GPA" = from_uc_cpu(c.CPU_PPC32_405GPA);
        pub const @"405GPB" = from_uc_cpu(c.CPU_PPC32_405GPB);
        pub const @"405GPC" = from_uc_cpu(c.CPU_PPC32_405GPC);
        pub const @"405GPD" = from_uc_cpu(c.CPU_PPC32_405GPD);
        pub const @"405GPR" = from_uc_cpu(c.CPU_PPC32_405GPR);
        pub const @"405LP" = from_uc_cpu(c.CPU_PPC32_405LP);
        pub const NPE405H = from_uc_cpu(c.CPU_PPC32_NPE405H);
        pub const NPE405H2 = from_uc_cpu(c.CPU_PPC32_NPE405H2);
        pub const NPE405L = from_uc_cpu(c.CPU_PPC32_NPE405L);
        pub const NPE4GS3 = from_uc_cpu(c.CPU_PPC32_NPE4GS3);
        pub const STB03 = from_uc_cpu(c.CPU_PPC32_STB03);
        pub const STB04 = from_uc_cpu(c.CPU_PPC32_STB04);
        pub const STB25 = from_uc_cpu(c.CPU_PPC32_STB25);
        pub const X2VP4 = from_uc_cpu(c.CPU_PPC32_X2VP4);
        pub const X2VP20 = from_uc_cpu(c.CPU_PPC32_X2VP20);
        pub const @"440_XILINX" = from_uc_cpu(c.CPU_PPC32_440_XILINX);
        pub const @"440_XILINX_W_DFPU" = from_uc_cpu(c.CPU_PPC32_440_XILINX_W_DFPU);
        pub const @"440EPA" = from_uc_cpu(c.CPU_PPC32_440EPA);
        pub const @"440EPB" = from_uc_cpu(c.CPU_PPC32_440EPB);
        pub const @"440EPX" = from_uc_cpu(c.CPU_PPC32_440EPX);
        pub const @"460EXB" = from_uc_cpu(c.CPU_PPC32_460EXB);
        pub const G2 = from_uc_cpu(c.CPU_PPC32_G2);
        pub const G2H4 = from_uc_cpu(c.CPU_PPC32_G2H4);
        pub const G2GP = from_uc_cpu(c.CPU_PPC32_G2GP);
        pub const G2LS = from_uc_cpu(c.CPU_PPC32_G2LS);
        pub const G2HIP3 = from_uc_cpu(c.CPU_PPC32_G2HIP3);
        pub const G2HIP4 = from_uc_cpu(c.CPU_PPC32_G2HIP4);
        pub const MPC603 = from_uc_cpu(c.CPU_PPC32_MPC603);
        pub const G2LE = from_uc_cpu(c.CPU_PPC32_G2LE);
        pub const G2LEGP = from_uc_cpu(c.CPU_PPC32_G2LEGP);
        pub const G2LELS = from_uc_cpu(c.CPU_PPC32_G2LELS);
        pub const G2LEGP1 = from_uc_cpu(c.CPU_PPC32_G2LEGP1);
        pub const G2LEGP3 = from_uc_cpu(c.CPU_PPC32_G2LEGP3);
        pub const MPC5200_V10 = from_uc_cpu(c.CPU_PPC32_MPC5200_V10);
        pub const MPC5200_V11 = from_uc_cpu(c.CPU_PPC32_MPC5200_V11);
        pub const MPC5200_V12 = from_uc_cpu(c.CPU_PPC32_MPC5200_V12);
        pub const MPC5200B_V20 = from_uc_cpu(c.CPU_PPC32_MPC5200B_V20);
        pub const MPC5200B_V21 = from_uc_cpu(c.CPU_PPC32_MPC5200B_V21);
        pub const E200Z5 = from_uc_cpu(c.CPU_PPC32_E200Z5);
        pub const E200Z6 = from_uc_cpu(c.CPU_PPC32_E200Z6);
        pub const E300C1 = from_uc_cpu(c.CPU_PPC32_E300C1);
        pub const E300C2 = from_uc_cpu(c.CPU_PPC32_E300C2);
        pub const E300C3 = from_uc_cpu(c.CPU_PPC32_E300C3);
        pub const E300C4 = from_uc_cpu(c.CPU_PPC32_E300C4);
        pub const MPC8343 = from_uc_cpu(c.CPU_PPC32_MPC8343);
        pub const MPC8343A = from_uc_cpu(c.CPU_PPC32_MPC8343A);
        pub const MPC8343E = from_uc_cpu(c.CPU_PPC32_MPC8343E);
        pub const MPC8343EA = from_uc_cpu(c.CPU_PPC32_MPC8343EA);
        pub const MPC8347T = from_uc_cpu(c.CPU_PPC32_MPC8347T);
        pub const MPC8347P = from_uc_cpu(c.CPU_PPC32_MPC8347P);
        pub const MPC8347AT = from_uc_cpu(c.CPU_PPC32_MPC8347AT);
        pub const MPC8347AP = from_uc_cpu(c.CPU_PPC32_MPC8347AP);
        pub const MPC8347ET = from_uc_cpu(c.CPU_PPC32_MPC8347ET);
        pub const MPC8347EP = from_uc_cpu(c.CPU_PPC32_MPC8347EP);
        pub const MPC8347EAT = from_uc_cpu(c.CPU_PPC32_MPC8347EAT);
        pub const MPC8347EAP = from_uc_cpu(c.CPU_PPC32_MPC8347EAP);
        pub const MPC8349 = from_uc_cpu(c.CPU_PPC32_MPC8349);
        pub const MPC8349A = from_uc_cpu(c.CPU_PPC32_MPC8349A);
        pub const MPC8349E = from_uc_cpu(c.CPU_PPC32_MPC8349E);
        pub const MPC8349EA = from_uc_cpu(c.CPU_PPC32_MPC8349EA);
        pub const MPC8377 = from_uc_cpu(c.CPU_PPC32_MPC8377);
        pub const MPC8377E = from_uc_cpu(c.CPU_PPC32_MPC8377E);
        pub const MPC8378 = from_uc_cpu(c.CPU_PPC32_MPC8378);
        pub const MPC8378E = from_uc_cpu(c.CPU_PPC32_MPC8378E);
        pub const MPC8379 = from_uc_cpu(c.CPU_PPC32_MPC8379);
        pub const MPC8379E = from_uc_cpu(c.CPU_PPC32_MPC8379E);
        pub const E500_V10 = from_uc_cpu(c.CPU_PPC32_E500_V10);
        pub const E500_V20 = from_uc_cpu(c.CPU_PPC32_E500_V20);
        pub const E500V2_V10 = from_uc_cpu(c.CPU_PPC32_E500V2_V10);
        pub const E500V2_V20 = from_uc_cpu(c.CPU_PPC32_E500V2_V20);
        pub const E500V2_V21 = from_uc_cpu(c.CPU_PPC32_E500V2_V21);
        pub const E500V2_V22 = from_uc_cpu(c.CPU_PPC32_E500V2_V22);
        pub const E500V2_V30 = from_uc_cpu(c.CPU_PPC32_E500V2_V30);
        pub const E500MC = from_uc_cpu(c.CPU_PPC32_E500MC);
        pub const MPC8533_V10 = from_uc_cpu(c.CPU_PPC32_MPC8533_V10);
        pub const MPC8533_V11 = from_uc_cpu(c.CPU_PPC32_MPC8533_V11);
        pub const MPC8533E_V10 = from_uc_cpu(c.CPU_PPC32_MPC8533E_V10);
        pub const MPC8533E_V11 = from_uc_cpu(c.CPU_PPC32_MPC8533E_V11);
        pub const MPC8540_V10 = from_uc_cpu(c.CPU_PPC32_MPC8540_V10);
        pub const MPC8540_V20 = from_uc_cpu(c.CPU_PPC32_MPC8540_V20);
        pub const MPC8540_V21 = from_uc_cpu(c.CPU_PPC32_MPC8540_V21);
        pub const MPC8541_V10 = from_uc_cpu(c.CPU_PPC32_MPC8541_V10);
        pub const MPC8541_V11 = from_uc_cpu(c.CPU_PPC32_MPC8541_V11);
        pub const MPC8541E_V10 = from_uc_cpu(c.CPU_PPC32_MPC8541E_V10);
        pub const MPC8541E_V11 = from_uc_cpu(c.CPU_PPC32_MPC8541E_V11);
        pub const MPC8543_V10 = from_uc_cpu(c.CPU_PPC32_MPC8543_V10);
        pub const MPC8543_V11 = from_uc_cpu(c.CPU_PPC32_MPC8543_V11);
        pub const MPC8543_V20 = from_uc_cpu(c.CPU_PPC32_MPC8543_V20);
        pub const MPC8543_V21 = from_uc_cpu(c.CPU_PPC32_MPC8543_V21);
        pub const MPC8543E_V10 = from_uc_cpu(c.CPU_PPC32_MPC8543E_V10);
        pub const MPC8543E_V11 = from_uc_cpu(c.CPU_PPC32_MPC8543E_V11);
        pub const MPC8543E_V20 = from_uc_cpu(c.CPU_PPC32_MPC8543E_V20);
        pub const MPC8543E_V21 = from_uc_cpu(c.CPU_PPC32_MPC8543E_V21);
        pub const MPC8544_V10 = from_uc_cpu(c.CPU_PPC32_MPC8544_V10);
        pub const MPC8544_V11 = from_uc_cpu(c.CPU_PPC32_MPC8544_V11);
        pub const MPC8544E_V10 = from_uc_cpu(c.CPU_PPC32_MPC8544E_V10);
        pub const MPC8544E_V11 = from_uc_cpu(c.CPU_PPC32_MPC8544E_V11);
        pub const MPC8545_V20 = from_uc_cpu(c.CPU_PPC32_MPC8545_V20);
        pub const MPC8545_V21 = from_uc_cpu(c.CPU_PPC32_MPC8545_V21);
        pub const MPC8545E_V20 = from_uc_cpu(c.CPU_PPC32_MPC8545E_V20);
        pub const MPC8545E_V21 = from_uc_cpu(c.CPU_PPC32_MPC8545E_V21);
        pub const MPC8547E_V20 = from_uc_cpu(c.CPU_PPC32_MPC8547E_V20);
        pub const MPC8547E_V21 = from_uc_cpu(c.CPU_PPC32_MPC8547E_V21);
        pub const MPC8548_V10 = from_uc_cpu(c.CPU_PPC32_MPC8548_V10);
        pub const MPC8548_V11 = from_uc_cpu(c.CPU_PPC32_MPC8548_V11);
        pub const MPC8548_V20 = from_uc_cpu(c.CPU_PPC32_MPC8548_V20);
        pub const MPC8548_V21 = from_uc_cpu(c.CPU_PPC32_MPC8548_V21);
        pub const MPC8548E_V10 = from_uc_cpu(c.CPU_PPC32_MPC8548E_V10);
        pub const MPC8548E_V11 = from_uc_cpu(c.CPU_PPC32_MPC8548E_V11);
        pub const MPC8548E_V20 = from_uc_cpu(c.CPU_PPC32_MPC8548E_V20);
        pub const MPC8548E_V21 = from_uc_cpu(c.CPU_PPC32_MPC8548E_V21);
        pub const MPC8555_V10 = from_uc_cpu(c.CPU_PPC32_MPC8555_V10);
        pub const MPC8555_V11 = from_uc_cpu(c.CPU_PPC32_MPC8555_V11);
        pub const MPC8555E_V10 = from_uc_cpu(c.CPU_PPC32_MPC8555E_V10);
        pub const MPC8555E_V11 = from_uc_cpu(c.CPU_PPC32_MPC8555E_V11);
        pub const MPC8560_V10 = from_uc_cpu(c.CPU_PPC32_MPC8560_V10);
        pub const MPC8560_V20 = from_uc_cpu(c.CPU_PPC32_MPC8560_V20);
        pub const MPC8560_V21 = from_uc_cpu(c.CPU_PPC32_MPC8560_V21);
        pub const MPC8567 = from_uc_cpu(c.CPU_PPC32_MPC8567);
        pub const MPC8567E = from_uc_cpu(c.CPU_PPC32_MPC8567E);
        pub const MPC8568 = from_uc_cpu(c.CPU_PPC32_MPC8568);
        pub const MPC8568E = from_uc_cpu(c.CPU_PPC32_MPC8568E);
        pub const MPC8572 = from_uc_cpu(c.CPU_PPC32_MPC8572);
        pub const MPC8572E = from_uc_cpu(c.CPU_PPC32_MPC8572E);
        pub const E600 = from_uc_cpu(c.CPU_PPC32_E600);
        pub const MPC8610 = from_uc_cpu(c.CPU_PPC32_MPC8610);
        pub const MPC8641 = from_uc_cpu(c.CPU_PPC32_MPC8641);
        pub const MPC8641D = from_uc_cpu(c.CPU_PPC32_MPC8641D);
        pub const @"601_V0" = from_uc_cpu(c.CPU_PPC32_601_V0);
        pub const @"601_V1" = from_uc_cpu(c.CPU_PPC32_601_V1);
        pub const @"601_V2" = from_uc_cpu(c.CPU_PPC32_601_V2);
        pub const @"602" = from_uc_cpu(c.CPU_PPC32_602);
        pub const @"603" = from_uc_cpu(c.CPU_PPC32_603);
        pub const @"603E_V1_1" = from_uc_cpu(c.CPU_PPC32_603E_V1_1);
        pub const @"603E_V1_2" = from_uc_cpu(c.CPU_PPC32_603E_V1_2);
        pub const @"603E_V1_3" = from_uc_cpu(c.CPU_PPC32_603E_V1_3);
        pub const @"603E_V1_4" = from_uc_cpu(c.CPU_PPC32_603E_V1_4);
        pub const @"603E_V2_2" = from_uc_cpu(c.CPU_PPC32_603E_V2_2);
        pub const @"603E_V3" = from_uc_cpu(c.CPU_PPC32_603E_V3);
        pub const @"603E_V4" = from_uc_cpu(c.CPU_PPC32_603E_V4);
        pub const @"603E_V4_1" = from_uc_cpu(c.CPU_PPC32_603E_V4_1);
        pub const @"603E7" = from_uc_cpu(c.CPU_PPC32_603E7);
        pub const @"603E7T" = from_uc_cpu(c.CPU_PPC32_603E7T);
        pub const @"603E7V" = from_uc_cpu(c.CPU_PPC32_603E7V);
        pub const @"603E7V1" = from_uc_cpu(c.CPU_PPC32_603E7V1);
        pub const @"603E7V2" = from_uc_cpu(c.CPU_PPC32_603E7V2);
        pub const @"603P" = from_uc_cpu(c.CPU_PPC32_603P);
        pub const @"604" = from_uc_cpu(c.CPU_PPC32_604);
        pub const @"604E_V1_0" = from_uc_cpu(c.CPU_PPC32_604E_V1_0);
        pub const @"604E_V2_2" = from_uc_cpu(c.CPU_PPC32_604E_V2_2);
        pub const @"604E_V2_4" = from_uc_cpu(c.CPU_PPC32_604E_V2_4);
        pub const @"604R" = from_uc_cpu(c.CPU_PPC32_604R);
        pub const @"740_V1_0" = from_uc_cpu(c.CPU_PPC32_740_V1_0);
        pub const @"750_V1_0" = from_uc_cpu(c.CPU_PPC32_750_V1_0);
        pub const @"740_V2_0" = from_uc_cpu(c.CPU_PPC32_740_V2_0);
        pub const @"750_V2_0" = from_uc_cpu(c.CPU_PPC32_750_V2_0);
        pub const @"740_V2_1" = from_uc_cpu(c.CPU_PPC32_740_V2_1);
        pub const @"750_V2_1" = from_uc_cpu(c.CPU_PPC32_750_V2_1);
        pub const @"740_V2_2" = from_uc_cpu(c.CPU_PPC32_740_V2_2);
        pub const @"750_V2_2" = from_uc_cpu(c.CPU_PPC32_750_V2_2);
        pub const @"740_V3_0" = from_uc_cpu(c.CPU_PPC32_740_V3_0);
        pub const @"750_V3_0" = from_uc_cpu(c.CPU_PPC32_750_V3_0);
        pub const @"740_V3_1" = from_uc_cpu(c.CPU_PPC32_740_V3_1);
        pub const @"750_V3_1" = from_uc_cpu(c.CPU_PPC32_750_V3_1);
        pub const @"740E" = from_uc_cpu(c.CPU_PPC32_740E);
        pub const @"750E" = from_uc_cpu(c.CPU_PPC32_750E);
        pub const @"740P" = from_uc_cpu(c.CPU_PPC32_740P);
        pub const @"750P" = from_uc_cpu(c.CPU_PPC32_750P);
        pub const @"750CL_V1_0" = from_uc_cpu(c.CPU_PPC32_750CL_V1_0);
        pub const @"750CL_V2_0" = from_uc_cpu(c.CPU_PPC32_750CL_V2_0);
        pub const @"750CX_V1_0" = from_uc_cpu(c.CPU_PPC32_750CX_V1_0);
        pub const @"750CX_V2_0" = from_uc_cpu(c.CPU_PPC32_750CX_V2_0);
        pub const @"750CX_V2_1" = from_uc_cpu(c.CPU_PPC32_750CX_V2_1);
        pub const @"750CX_V2_2" = from_uc_cpu(c.CPU_PPC32_750CX_V2_2);
        pub const @"750CXE_V2_1" = from_uc_cpu(c.CPU_PPC32_750CXE_V2_1);
        pub const @"750CXE_V2_2" = from_uc_cpu(c.CPU_PPC32_750CXE_V2_2);
        pub const @"750CXE_V2_3" = from_uc_cpu(c.CPU_PPC32_750CXE_V2_3);
        pub const @"750CXE_V2_4" = from_uc_cpu(c.CPU_PPC32_750CXE_V2_4);
        pub const @"750CXE_V2_4B" = from_uc_cpu(c.CPU_PPC32_750CXE_V2_4B);
        pub const @"750CXE_V3_0" = from_uc_cpu(c.CPU_PPC32_750CXE_V3_0);
        pub const @"750CXE_V3_1" = from_uc_cpu(c.CPU_PPC32_750CXE_V3_1);
        pub const @"750CXE_V3_1B" = from_uc_cpu(c.CPU_PPC32_750CXE_V3_1B);
        pub const @"750CXR" = from_uc_cpu(c.CPU_PPC32_750CXR);
        pub const @"750FL" = from_uc_cpu(c.CPU_PPC32_750FL);
        pub const @"750FX_V1_0" = from_uc_cpu(c.CPU_PPC32_750FX_V1_0);
        pub const @"750FX_V2_0" = from_uc_cpu(c.CPU_PPC32_750FX_V2_0);
        pub const @"750FX_V2_1" = from_uc_cpu(c.CPU_PPC32_750FX_V2_1);
        pub const @"750FX_V2_2" = from_uc_cpu(c.CPU_PPC32_750FX_V2_2);
        pub const @"750FX_V2_3" = from_uc_cpu(c.CPU_PPC32_750FX_V2_3);
        pub const @"750GL" = from_uc_cpu(c.CPU_PPC32_750GL);
        pub const @"750GX_V1_0" = from_uc_cpu(c.CPU_PPC32_750GX_V1_0);
        pub const @"750GX_V1_1" = from_uc_cpu(c.CPU_PPC32_750GX_V1_1);
        pub const @"750GX_V1_2" = from_uc_cpu(c.CPU_PPC32_750GX_V1_2);
        pub const @"750L_V2_0" = from_uc_cpu(c.CPU_PPC32_750L_V2_0);
        pub const @"750L_V2_1" = from_uc_cpu(c.CPU_PPC32_750L_V2_1);
        pub const @"750L_V2_2" = from_uc_cpu(c.CPU_PPC32_750L_V2_2);
        pub const @"750L_V3_0" = from_uc_cpu(c.CPU_PPC32_750L_V3_0);
        pub const @"750L_V3_2" = from_uc_cpu(c.CPU_PPC32_750L_V3_2);
        pub const @"745_V1_0" = from_uc_cpu(c.CPU_PPC32_745_V1_0);
        pub const @"755_V1_0" = from_uc_cpu(c.CPU_PPC32_755_V1_0);
        pub const @"745_V1_1" = from_uc_cpu(c.CPU_PPC32_745_V1_1);
        pub const @"755_V1_1" = from_uc_cpu(c.CPU_PPC32_755_V1_1);
        pub const @"745_V2_0" = from_uc_cpu(c.CPU_PPC32_745_V2_0);
        pub const @"755_V2_0" = from_uc_cpu(c.CPU_PPC32_755_V2_0);
        pub const @"745_V2_1" = from_uc_cpu(c.CPU_PPC32_745_V2_1);
        pub const @"755_V2_1" = from_uc_cpu(c.CPU_PPC32_755_V2_1);
        pub const @"745_V2_2" = from_uc_cpu(c.CPU_PPC32_745_V2_2);
        pub const @"755_V2_2" = from_uc_cpu(c.CPU_PPC32_755_V2_2);
        pub const @"745_V2_3" = from_uc_cpu(c.CPU_PPC32_745_V2_3);
        pub const @"755_V2_3" = from_uc_cpu(c.CPU_PPC32_755_V2_3);
        pub const @"745_V2_4" = from_uc_cpu(c.CPU_PPC32_745_V2_4);
        pub const @"755_V2_4" = from_uc_cpu(c.CPU_PPC32_755_V2_4);
        pub const @"745_V2_5" = from_uc_cpu(c.CPU_PPC32_745_V2_5);
        pub const @"755_V2_5" = from_uc_cpu(c.CPU_PPC32_755_V2_5);
        pub const @"745_V2_6" = from_uc_cpu(c.CPU_PPC32_745_V2_6);
        pub const @"755_V2_6" = from_uc_cpu(c.CPU_PPC32_755_V2_6);
        pub const @"745_V2_7" = from_uc_cpu(c.CPU_PPC32_745_V2_7);
        pub const @"755_V2_7" = from_uc_cpu(c.CPU_PPC32_755_V2_7);
        pub const @"745_V2_8" = from_uc_cpu(c.CPU_PPC32_745_V2_8);
        pub const @"755_V2_8" = from_uc_cpu(c.CPU_PPC32_755_V2_8);
        pub const @"7400_V1_0" = from_uc_cpu(c.CPU_PPC32_7400_V1_0);
        pub const @"7400_V1_1" = from_uc_cpu(c.CPU_PPC32_7400_V1_1);
        pub const @"7400_V2_0" = from_uc_cpu(c.CPU_PPC32_7400_V2_0);
        pub const @"7400_V2_1" = from_uc_cpu(c.CPU_PPC32_7400_V2_1);
        pub const @"7400_V2_2" = from_uc_cpu(c.CPU_PPC32_7400_V2_2);
        pub const @"7400_V2_6" = from_uc_cpu(c.CPU_PPC32_7400_V2_6);
        pub const @"7400_V2_7" = from_uc_cpu(c.CPU_PPC32_7400_V2_7);
        pub const @"7400_V2_8" = from_uc_cpu(c.CPU_PPC32_7400_V2_8);
        pub const @"7400_V2_9" = from_uc_cpu(c.CPU_PPC32_7400_V2_9);
        pub const @"7410_V1_0" = from_uc_cpu(c.CPU_PPC32_7410_V1_0);
        pub const @"7410_V1_1" = from_uc_cpu(c.CPU_PPC32_7410_V1_1);
        pub const @"7410_V1_2" = from_uc_cpu(c.CPU_PPC32_7410_V1_2);
        pub const @"7410_V1_3" = from_uc_cpu(c.CPU_PPC32_7410_V1_3);
        pub const @"7410_V1_4" = from_uc_cpu(c.CPU_PPC32_7410_V1_4);
        pub const @"7448_V1_0" = from_uc_cpu(c.CPU_PPC32_7448_V1_0);
        pub const @"7448_V1_1" = from_uc_cpu(c.CPU_PPC32_7448_V1_1);
        pub const @"7448_V2_0" = from_uc_cpu(c.CPU_PPC32_7448_V2_0);
        pub const @"7448_V2_1" = from_uc_cpu(c.CPU_PPC32_7448_V2_1);
        pub const @"7450_V1_0" = from_uc_cpu(c.CPU_PPC32_7450_V1_0);
        pub const @"7450_V1_1" = from_uc_cpu(c.CPU_PPC32_7450_V1_1);
        pub const @"7450_V1_2" = from_uc_cpu(c.CPU_PPC32_7450_V1_2);
        pub const @"7450_V2_0" = from_uc_cpu(c.CPU_PPC32_7450_V2_0);
        pub const @"7450_V2_1" = from_uc_cpu(c.CPU_PPC32_7450_V2_1);
        pub const @"7441_V2_1" = from_uc_cpu(c.CPU_PPC32_7441_V2_1);
        pub const @"7441_V2_3" = from_uc_cpu(c.CPU_PPC32_7441_V2_3);
        pub const @"7451_V2_3" = from_uc_cpu(c.CPU_PPC32_7451_V2_3);
        pub const @"7441_V2_10" = from_uc_cpu(c.CPU_PPC32_7441_V2_10);
        pub const @"7451_V2_10" = from_uc_cpu(c.CPU_PPC32_7451_V2_10);
        pub const @"7445_V1_0" = from_uc_cpu(c.CPU_PPC32_7445_V1_0);
        pub const @"7455_V1_0" = from_uc_cpu(c.CPU_PPC32_7455_V1_0);
        pub const @"7445_V2_1" = from_uc_cpu(c.CPU_PPC32_7445_V2_1);
        pub const @"7455_V2_1" = from_uc_cpu(c.CPU_PPC32_7455_V2_1);
        pub const @"7445_V3_2" = from_uc_cpu(c.CPU_PPC32_7445_V3_2);
        pub const @"7455_V3_2" = from_uc_cpu(c.CPU_PPC32_7455_V3_2);
        pub const @"7445_V3_3" = from_uc_cpu(c.CPU_PPC32_7445_V3_3);
        pub const @"7455_V3_3" = from_uc_cpu(c.CPU_PPC32_7455_V3_3);
        pub const @"7445_V3_4" = from_uc_cpu(c.CPU_PPC32_7445_V3_4);
        pub const @"7455_V3_4" = from_uc_cpu(c.CPU_PPC32_7455_V3_4);
        pub const @"7447_V1_0" = from_uc_cpu(c.CPU_PPC32_7447_V1_0);
        pub const @"7457_V1_0" = from_uc_cpu(c.CPU_PPC32_7457_V1_0);
        pub const @"7447_V1_1" = from_uc_cpu(c.CPU_PPC32_7447_V1_1);
        pub const @"7457_V1_1" = from_uc_cpu(c.CPU_PPC32_7457_V1_1);
        pub const @"7457_V1_2" = from_uc_cpu(c.CPU_PPC32_7457_V1_2);
        pub const @"7447A_V1_0" = from_uc_cpu(c.CPU_PPC32_7447A_V1_0);
        pub const @"7457A_V1_0" = from_uc_cpu(c.CPU_PPC32_7457A_V1_0);
        pub const @"7447A_V1_1" = from_uc_cpu(c.CPU_PPC32_7447A_V1_1);
        pub const @"7457A_V1_1" = from_uc_cpu(c.CPU_PPC32_7457A_V1_1);
        pub const @"7447A_V1_2" = from_uc_cpu(c.CPU_PPC32_7447A_V1_2);
        pub const @"7457A_V1_2" = from_uc_cpu(c.CPU_PPC32_7457A_V1_2);
        pub const ENDING = from_uc_cpu(c.CPU_PPC32_ENDING);
    };

    pub const Ppc64 = struct {
        pub const E5500 = from_uc_cpu(c.CPU_PPC64_E5500);
        pub const E6500 = from_uc_cpu(c.CPU_PPC64_E6500);
        pub const @"970_V2_2" = from_uc_cpu(c.CPU_PPC64_970_V2_2);
        pub const @"970FX_V1_0" = from_uc_cpu(c.CPU_PPC64_970FX_V1_0);
        pub const @"970FX_V2_0" = from_uc_cpu(c.CPU_PPC64_970FX_V2_0);
        pub const @"970FX_V2_1" = from_uc_cpu(c.CPU_PPC64_970FX_V2_1);
        pub const @"970FX_V3_0" = from_uc_cpu(c.CPU_PPC64_970FX_V3_0);
        pub const @"970FX_V3_1" = from_uc_cpu(c.CPU_PPC64_970FX_V3_1);
        pub const @"970MP_V1_0" = from_uc_cpu(c.CPU_PPC64_970MP_V1_0);
        pub const @"970MP_V1_1" = from_uc_cpu(c.CPU_PPC64_970MP_V1_1);
        pub const POWER5_V2_1 = from_uc_cpu(c.CPU_PPC64_POWER5_V2_1);
        pub const POWER7_V2_3 = from_uc_cpu(c.CPU_PPC64_POWER7_V2_3);
        pub const POWER7_V2_1 = from_uc_cpu(c.CPU_PPC64_POWER7_V2_1);
        pub const POWER8E_V2_1 = from_uc_cpu(c.CPU_PPC64_POWER8E_V2_1);
        pub const POWER8_V2_0 = from_uc_cpu(c.CPU_PPC64_POWER8_V2_0);
        pub const POWER8NVL_V1_0 = from_uc_cpu(c.CPU_PPC64_POWER8NVL_V1_0);
        pub const POWER9_V1_0 = from_uc_cpu(c.CPU_PPC64_POWER9_V1_0);
        pub const POWER9_V2_0 = from_uc_cpu(c.CPU_PPC64_POWER9_V2_0);
        pub const POWER10_V1_0 = from_uc_cpu(c.CPU_PPC64_POWER10_V1_0);
        pub const ENDING = from_uc_cpu(c.CPU_PPC64_ENDING);
    };

    pub const Sparc32 = struct {
        pub const FUJITSU_MB86904 = from_uc_cpu(c.CPU_SPARC32_FUJITSU_MB86904);
        pub const FUJITSU_MB86907 = from_uc_cpu(c.CPU_SPARC32_FUJITSU_MB86907);
        pub const TI_MICROSPARC_I = from_uc_cpu(c.CPU_SPARC32_TI_MICROSPARC_I);
        pub const TI_MICROSPARC_II = from_uc_cpu(c.CPU_SPARC32_TI_MICROSPARC_II);
        pub const TI_MICROSPARC_IIEP = from_uc_cpu(c.CPU_SPARC32_TI_MICROSPARC_IIEP);
        pub const TI_SUPERSPARC_40 = from_uc_cpu(c.CPU_SPARC32_TI_SUPERSPARC_40);
        pub const TI_SUPERSPARC_50 = from_uc_cpu(c.CPU_SPARC32_TI_SUPERSPARC_50);
        pub const TI_SUPERSPARC_51 = from_uc_cpu(c.CPU_SPARC32_TI_SUPERSPARC_51);
        pub const TI_SUPERSPARC_60 = from_uc_cpu(c.CPU_SPARC32_TI_SUPERSPARC_60);
        pub const TI_SUPERSPARC_61 = from_uc_cpu(c.CPU_SPARC32_TI_SUPERSPARC_61);
        pub const TI_SUPERSPARC_II = from_uc_cpu(c.CPU_SPARC32_TI_SUPERSPARC_II);
        pub const LEON2 = from_uc_cpu(c.CPU_SPARC32_LEON2);
        pub const LEON3 = from_uc_cpu(c.CPU_SPARC32_LEON3);
        pub const ENDING = from_uc_cpu(c.CPU_SPARC32_ENDING);
    };

    pub const Sparc64 = struct {
        pub const FUJITSU = from_uc_cpu(c.CPU_SPARC64_FUJITSU);
        pub const FUJITSU_III = from_uc_cpu(c.CPU_SPARC64_FUJITSU_III);
        pub const FUJITSU_IV = from_uc_cpu(c.CPU_SPARC64_FUJITSU_IV);
        pub const FUJITSU_V = from_uc_cpu(c.CPU_SPARC64_FUJITSU_V);
        pub const TI_ULTRASPARC_I = from_uc_cpu(c.CPU_SPARC64_TI_ULTRASPARC_I);
        pub const TI_ULTRASPARC_II = from_uc_cpu(c.CPU_SPARC64_TI_ULTRASPARC_II);
        pub const TI_ULTRASPARC_III = from_uc_cpu(c.CPU_SPARC64_TI_ULTRASPARC_III);
        pub const TI_ULTRASPARC_IIE = from_uc_cpu(c.CPU_SPARC64_TI_ULTRASPARC_IIE);
        pub const SUN_ULTRASPARC_III = from_uc_cpu(c.CPU_SPARC64_SUN_ULTRASPARC_III);
        pub const SUN_ULTRASPARC_III_CU = from_uc_cpu(c.CPU_SPARC64_SUN_ULTRASPARC_III_CU);
        pub const SUN_ULTRASPARC_IIII = from_uc_cpu(c.CPU_SPARC64_SUN_ULTRASPARC_IIII);
        pub const SUN_ULTRASPARC_IV = from_uc_cpu(c.CPU_SPARC64_SUN_ULTRASPARC_IV);
        pub const SUN_ULTRASPARC_IV_PLUS = from_uc_cpu(c.CPU_SPARC64_SUN_ULTRASPARC_IV_PLUS);
        pub const SUN_ULTRASPARC_IIII_PLUS = from_uc_cpu(c.CPU_SPARC64_SUN_ULTRASPARC_IIII_PLUS);
        pub const SUN_ULTRASPARC_T1 = from_uc_cpu(c.CPU_SPARC64_SUN_ULTRASPARC_T1);
        pub const SUN_ULTRASPARC_T2 = from_uc_cpu(c.CPU_SPARC64_SUN_ULTRASPARC_T2);
        pub const NEC_ULTRASPARC_I = from_uc_cpu(c.CPU_SPARC64_NEC_ULTRASPARC_I);
        pub const ENDING = from_uc_cpu(c.CPU_SPARC64_ENDING);
    };

    pub const M68k = struct {
        pub const M5206 = from_uc_cpu(c.CPU_M68K_M5206);
        pub const M68000 = from_uc_cpu(c.CPU_M68K_M68000);
        pub const M68020 = from_uc_cpu(c.CPU_M68K_M68020);
        pub const M68030 = from_uc_cpu(c.CPU_M68K_M68030);
        pub const M68040 = from_uc_cpu(c.CPU_M68K_M68040);
        pub const M68060 = from_uc_cpu(c.CPU_M68K_M68060);
        pub const M5208 = from_uc_cpu(c.CPU_M68K_M5208);
        pub const CFV4E = from_uc_cpu(c.CPU_M68K_CFV4E);
        pub const ANY = from_uc_cpu(c.CPU_M68K_ANY);
        pub const ENDING = from_uc_cpu(c.CPU_M68K_ENDING);
    };

    pub const Riscv32 = struct {
        pub const ANY = from_uc_cpu(c.CPU_RISCV32_ANY);
        pub const BASE32 = from_uc_cpu(c.CPU_RISCV32_BASE32);
        pub const SIFIVE_E31 = from_uc_cpu(c.CPU_RISCV32_SIFIVE_E31);
        pub const SIFIVE_U34 = from_uc_cpu(c.CPU_RISCV32_SIFIVE_U34);
        pub const ENDING = from_uc_cpu(c.CPU_RISCV32_ENDING);
    };

    pub const Riscv64 = struct {
        pub const ANY = from_uc_cpu(c.CPU_RISCV64_ANY);
        pub const BASE64 = from_uc_cpu(c.CPU_RISCV64_BASE64);
        pub const SIFIVE_E51 = from_uc_cpu(c.CPU_RISCV64_SIFIVE_E51);
        pub const SIFIVE_U54 = from_uc_cpu(c.CPU_RISCV64_SIFIVE_U54);
        pub const ENDING = from_uc_cpu(c.CPU_RISCV64_ENDING);
    };

    pub const S390x = struct {
        pub const Z900 = from_uc_cpu(c.CPU_S390X_Z900);
        pub const Z900_2 = from_uc_cpu(c.CPU_S390X_Z900_2);
        pub const Z900_3 = from_uc_cpu(c.CPU_S390X_Z900_3);
        pub const Z800 = from_uc_cpu(c.CPU_S390X_Z800);
        pub const Z990 = from_uc_cpu(c.CPU_S390X_Z990);
        pub const Z990_2 = from_uc_cpu(c.CPU_S390X_Z990_2);
        pub const Z990_3 = from_uc_cpu(c.CPU_S390X_Z990_3);
        pub const Z890 = from_uc_cpu(c.CPU_S390X_Z890);
        pub const Z990_4 = from_uc_cpu(c.CPU_S390X_Z990_4);
        pub const Z890_2 = from_uc_cpu(c.CPU_S390X_Z890_2);
        pub const Z990_5 = from_uc_cpu(c.CPU_S390X_Z990_5);
        pub const Z890_3 = from_uc_cpu(c.CPU_S390X_Z890_3);
        pub const Z9EC = from_uc_cpu(c.CPU_S390X_Z9EC);
        pub const Z9EC_2 = from_uc_cpu(c.CPU_S390X_Z9EC_2);
        pub const Z9BC = from_uc_cpu(c.CPU_S390X_Z9BC);
        pub const Z9EC_3 = from_uc_cpu(c.CPU_S390X_Z9EC_3);
        pub const Z9BC_2 = from_uc_cpu(c.CPU_S390X_Z9BC_2);
        pub const Z10EC = from_uc_cpu(c.CPU_S390X_Z10EC);
        pub const Z10EC_2 = from_uc_cpu(c.CPU_S390X_Z10EC_2);
        pub const Z10BC = from_uc_cpu(c.CPU_S390X_Z10BC);
        pub const Z10EC_3 = from_uc_cpu(c.CPU_S390X_Z10EC_3);
        pub const Z10BC_2 = from_uc_cpu(c.CPU_S390X_Z10BC_2);
        pub const Z196 = from_uc_cpu(c.CPU_S390X_Z196);
        pub const Z196_2 = from_uc_cpu(c.CPU_S390X_Z196_2);
        pub const Z114 = from_uc_cpu(c.CPU_S390X_Z114);
        pub const ZEC12 = from_uc_cpu(c.CPU_S390X_ZEC12);
        pub const ZEC12_2 = from_uc_cpu(c.CPU_S390X_ZEC12_2);
        pub const ZBC12 = from_uc_cpu(c.CPU_S390X_ZBC12);
        pub const Z13 = from_uc_cpu(c.CPU_S390X_Z13);
        pub const Z13_2 = from_uc_cpu(c.CPU_S390X_Z13_2);
        pub const Z13S = from_uc_cpu(c.CPU_S390X_Z13S);
        pub const Z14 = from_uc_cpu(c.CPU_S390X_Z14);
        pub const Z14_2 = from_uc_cpu(c.CPU_S390X_Z14_2);
        pub const Z14ZR1 = from_uc_cpu(c.CPU_S390X_Z14ZR1);
        pub const GEN15A = from_uc_cpu(c.CPU_S390X_GEN15A);
        pub const GEN15B = from_uc_cpu(c.CPU_S390X_GEN15B);
        pub const QEMU = from_uc_cpu(c.CPU_S390X_QEMU);
        pub const MAX = from_uc_cpu(c.CPU_S390X_MAX);
        pub const ENDING = from_uc_cpu(c.CPU_S390X_ENDING);
    };

    pub const Tricore = struct {
        pub const TC1796 = from_uc_cpu(c.CPU_TRICORE_TC1796);
        pub const TC1797 = from_uc_cpu(c.CPU_TRICORE_TC1797);
        pub const TC27X = from_uc_cpu(c.CPU_TRICORE_TC27X);
        pub const ENDING = from_uc_cpu(c.CPU_TRICORE_ENDING);
    };

    fn from_uc_cpu(reg: c_int) Cpu {
        return @enumFromInt(reg);
    }

    pub fn to_string(self: Cpu, arch: Arch) []const u8 {
        switch (arch) {
            inline .Arm => |a| {
                const Cpus = @field(Cpu, @tagName(a));
                inline for (comptime std.meta.declarations(Cpus)) |decl| {
                    if (self == @field(Cpus, decl.name))
                        return decl.name;
                }
            },
            else => @panic("TODO"),
        }
        return "Unknown";
    }

    _,
};

pub const Reg = enum(c_int) {
    pub const X86 = struct {
        pub const INVALID = from_uc_reg(c.X86_REG_INVALID);
        pub const AH = from_uc_reg(c.X86_REG_AH);
        pub const AL = from_uc_reg(c.X86_REG_AL);
        pub const AX = from_uc_reg(c.X86_REG_AX);
        pub const BH = from_uc_reg(c.X86_REG_BH);
        pub const BL = from_uc_reg(c.X86_REG_BL);
        pub const BP = from_uc_reg(c.X86_REG_BP);
        pub const BPL = from_uc_reg(c.X86_REG_BPL);
        pub const BX = from_uc_reg(c.X86_REG_BX);
        pub const CH = from_uc_reg(c.X86_REG_CH);
        pub const CL = from_uc_reg(c.X86_REG_CL);
        pub const CS = from_uc_reg(c.X86_REG_CS);
        pub const CX = from_uc_reg(c.X86_REG_CX);
        pub const DH = from_uc_reg(c.X86_REG_DH);
        pub const DI = from_uc_reg(c.X86_REG_DI);
        pub const DIL = from_uc_reg(c.X86_REG_DIL);
        pub const DL = from_uc_reg(c.X86_REG_DL);
        pub const DS = from_uc_reg(c.X86_REG_DS);
        pub const DX = from_uc_reg(c.X86_REG_DX);
        pub const EAX = from_uc_reg(c.X86_REG_EAX);
        pub const EBP = from_uc_reg(c.X86_REG_EBP);
        pub const EBX = from_uc_reg(c.X86_REG_EBX);
        pub const ECX = from_uc_reg(c.X86_REG_ECX);
        pub const EDI = from_uc_reg(c.X86_REG_EDI);
        pub const EDX = from_uc_reg(c.X86_REG_EDX);
        pub const EFLAGS = from_uc_reg(c.X86_REG_EFLAGS);
        pub const EIP = from_uc_reg(c.X86_REG_EIP);
        pub const ES = from_uc_reg(c.X86_REG_ES);
        pub const ESI = from_uc_reg(c.X86_REG_ESI);
        pub const ESP = from_uc_reg(c.X86_REG_ESP);
        pub const FPSW = from_uc_reg(c.X86_REG_FPSW);
        pub const FS = from_uc_reg(c.X86_REG_FS);
        pub const GS = from_uc_reg(c.X86_REG_GS);
        pub const IP = from_uc_reg(c.X86_REG_IP);
        pub const RAX = from_uc_reg(c.X86_REG_RAX);
        pub const RBP = from_uc_reg(c.X86_REG_RBP);
        pub const RBX = from_uc_reg(c.X86_REG_RBX);
        pub const RCX = from_uc_reg(c.X86_REG_RCX);
        pub const RDI = from_uc_reg(c.X86_REG_RDI);
        pub const RDX = from_uc_reg(c.X86_REG_RDX);
        pub const RIP = from_uc_reg(c.X86_REG_RIP);
        pub const RSI = from_uc_reg(c.X86_REG_RSI);
        pub const RSP = from_uc_reg(c.X86_REG_RSP);
        pub const SI = from_uc_reg(c.X86_REG_SI);
        pub const SIL = from_uc_reg(c.X86_REG_SIL);
        pub const SP = from_uc_reg(c.X86_REG_SP);
        pub const SPL = from_uc_reg(c.X86_REG_SPL);
        pub const SS = from_uc_reg(c.X86_REG_SS);
        pub const CR0 = from_uc_reg(c.X86_REG_CR0);
        pub const CR1 = from_uc_reg(c.X86_REG_CR1);
        pub const CR2 = from_uc_reg(c.X86_REG_CR2);
        pub const CR3 = from_uc_reg(c.X86_REG_CR3);
        pub const CR4 = from_uc_reg(c.X86_REG_CR4);
        pub const CR8 = from_uc_reg(c.X86_REG_CR8);
        pub const DR0 = from_uc_reg(c.X86_REG_DR0);
        pub const DR1 = from_uc_reg(c.X86_REG_DR1);
        pub const DR2 = from_uc_reg(c.X86_REG_DR2);
        pub const DR3 = from_uc_reg(c.X86_REG_DR3);
        pub const DR4 = from_uc_reg(c.X86_REG_DR4);
        pub const DR5 = from_uc_reg(c.X86_REG_DR5);
        pub const DR6 = from_uc_reg(c.X86_REG_DR6);
        pub const DR7 = from_uc_reg(c.X86_REG_DR7);
        pub const FP0 = from_uc_reg(c.X86_REG_FP0);
        pub const FP1 = from_uc_reg(c.X86_REG_FP1);
        pub const FP2 = from_uc_reg(c.X86_REG_FP2);
        pub const FP3 = from_uc_reg(c.X86_REG_FP3);
        pub const FP4 = from_uc_reg(c.X86_REG_FP4);
        pub const FP5 = from_uc_reg(c.X86_REG_FP5);
        pub const FP6 = from_uc_reg(c.X86_REG_FP6);
        pub const FP7 = from_uc_reg(c.X86_REG_FP7);
        pub const K0 = from_uc_reg(c.X86_REG_K0);
        pub const K1 = from_uc_reg(c.X86_REG_K1);
        pub const K2 = from_uc_reg(c.X86_REG_K2);
        pub const K3 = from_uc_reg(c.X86_REG_K3);
        pub const K4 = from_uc_reg(c.X86_REG_K4);
        pub const K5 = from_uc_reg(c.X86_REG_K5);
        pub const K6 = from_uc_reg(c.X86_REG_K6);
        pub const K7 = from_uc_reg(c.X86_REG_K7);
        pub const MM0 = from_uc_reg(c.X86_REG_MM0);
        pub const MM1 = from_uc_reg(c.X86_REG_MM1);
        pub const MM2 = from_uc_reg(c.X86_REG_MM2);
        pub const MM3 = from_uc_reg(c.X86_REG_MM3);
        pub const MM4 = from_uc_reg(c.X86_REG_MM4);
        pub const MM5 = from_uc_reg(c.X86_REG_MM5);
        pub const MM6 = from_uc_reg(c.X86_REG_MM6);
        pub const MM7 = from_uc_reg(c.X86_REG_MM7);
        pub const R8 = from_uc_reg(c.X86_REG_R8);
        pub const R9 = from_uc_reg(c.X86_REG_R9);
        pub const R10 = from_uc_reg(c.X86_REG_R10);
        pub const R11 = from_uc_reg(c.X86_REG_R11);
        pub const R12 = from_uc_reg(c.X86_REG_R12);
        pub const R13 = from_uc_reg(c.X86_REG_R13);
        pub const R14 = from_uc_reg(c.X86_REG_R14);
        pub const R15 = from_uc_reg(c.X86_REG_R15);
        pub const ST0 = from_uc_reg(c.X86_REG_ST0);
        pub const ST1 = from_uc_reg(c.X86_REG_ST1);
        pub const ST2 = from_uc_reg(c.X86_REG_ST2);
        pub const ST3 = from_uc_reg(c.X86_REG_ST3);
        pub const ST4 = from_uc_reg(c.X86_REG_ST4);
        pub const ST5 = from_uc_reg(c.X86_REG_ST5);
        pub const ST6 = from_uc_reg(c.X86_REG_ST6);
        pub const ST7 = from_uc_reg(c.X86_REG_ST7);
        pub const XMM0 = from_uc_reg(c.X86_REG_XMM0);
        pub const XMM1 = from_uc_reg(c.X86_REG_XMM1);
        pub const XMM2 = from_uc_reg(c.X86_REG_XMM2);
        pub const XMM3 = from_uc_reg(c.X86_REG_XMM3);
        pub const XMM4 = from_uc_reg(c.X86_REG_XMM4);
        pub const XMM5 = from_uc_reg(c.X86_REG_XMM5);
        pub const XMM6 = from_uc_reg(c.X86_REG_XMM6);
        pub const XMM7 = from_uc_reg(c.X86_REG_XMM7);
        pub const XMM8 = from_uc_reg(c.X86_REG_XMM8);
        pub const XMM9 = from_uc_reg(c.X86_REG_XMM9);
        pub const XMM10 = from_uc_reg(c.X86_REG_XMM10);
        pub const XMM11 = from_uc_reg(c.X86_REG_XMM11);
        pub const XMM12 = from_uc_reg(c.X86_REG_XMM12);
        pub const XMM13 = from_uc_reg(c.X86_REG_XMM13);
        pub const XMM14 = from_uc_reg(c.X86_REG_XMM14);
        pub const XMM15 = from_uc_reg(c.X86_REG_XMM15);
        pub const XMM16 = from_uc_reg(c.X86_REG_XMM16);
        pub const XMM17 = from_uc_reg(c.X86_REG_XMM17);
        pub const XMM18 = from_uc_reg(c.X86_REG_XMM18);
        pub const XMM19 = from_uc_reg(c.X86_REG_XMM19);
        pub const XMM20 = from_uc_reg(c.X86_REG_XMM20);
        pub const XMM21 = from_uc_reg(c.X86_REG_XMM21);
        pub const XMM22 = from_uc_reg(c.X86_REG_XMM22);
        pub const XMM23 = from_uc_reg(c.X86_REG_XMM23);
        pub const XMM24 = from_uc_reg(c.X86_REG_XMM24);
        pub const XMM25 = from_uc_reg(c.X86_REG_XMM25);
        pub const XMM26 = from_uc_reg(c.X86_REG_XMM26);
        pub const XMM27 = from_uc_reg(c.X86_REG_XMM27);
        pub const XMM28 = from_uc_reg(c.X86_REG_XMM28);
        pub const XMM29 = from_uc_reg(c.X86_REG_XMM29);
        pub const XMM30 = from_uc_reg(c.X86_REG_XMM30);
        pub const XMM31 = from_uc_reg(c.X86_REG_XMM31);
        pub const YMM0 = from_uc_reg(c.X86_REG_YMM0);
        pub const YMM1 = from_uc_reg(c.X86_REG_YMM1);
        pub const YMM2 = from_uc_reg(c.X86_REG_YMM2);
        pub const YMM3 = from_uc_reg(c.X86_REG_YMM3);
        pub const YMM4 = from_uc_reg(c.X86_REG_YMM4);
        pub const YMM5 = from_uc_reg(c.X86_REG_YMM5);
        pub const YMM6 = from_uc_reg(c.X86_REG_YMM6);
        pub const YMM7 = from_uc_reg(c.X86_REG_YMM7);
        pub const YMM8 = from_uc_reg(c.X86_REG_YMM8);
        pub const YMM9 = from_uc_reg(c.X86_REG_YMM9);
        pub const YMM10 = from_uc_reg(c.X86_REG_YMM10);
        pub const YMM11 = from_uc_reg(c.X86_REG_YMM11);
        pub const YMM12 = from_uc_reg(c.X86_REG_YMM12);
        pub const YMM13 = from_uc_reg(c.X86_REG_YMM13);
        pub const YMM14 = from_uc_reg(c.X86_REG_YMM14);
        pub const YMM15 = from_uc_reg(c.X86_REG_YMM15);
        pub const YMM16 = from_uc_reg(c.X86_REG_YMM16);
        pub const YMM17 = from_uc_reg(c.X86_REG_YMM17);
        pub const YMM18 = from_uc_reg(c.X86_REG_YMM18);
        pub const YMM19 = from_uc_reg(c.X86_REG_YMM19);
        pub const YMM20 = from_uc_reg(c.X86_REG_YMM20);
        pub const YMM21 = from_uc_reg(c.X86_REG_YMM21);
        pub const YMM22 = from_uc_reg(c.X86_REG_YMM22);
        pub const YMM23 = from_uc_reg(c.X86_REG_YMM23);
        pub const YMM24 = from_uc_reg(c.X86_REG_YMM24);
        pub const YMM25 = from_uc_reg(c.X86_REG_YMM25);
        pub const YMM26 = from_uc_reg(c.X86_REG_YMM26);
        pub const YMM27 = from_uc_reg(c.X86_REG_YMM27);
        pub const YMM28 = from_uc_reg(c.X86_REG_YMM28);
        pub const YMM29 = from_uc_reg(c.X86_REG_YMM29);
        pub const YMM30 = from_uc_reg(c.X86_REG_YMM30);
        pub const YMM31 = from_uc_reg(c.X86_REG_YMM31);
        pub const ZMM0 = from_uc_reg(c.X86_REG_ZMM0);
        pub const ZMM1 = from_uc_reg(c.X86_REG_ZMM1);
        pub const ZMM2 = from_uc_reg(c.X86_REG_ZMM2);
        pub const ZMM3 = from_uc_reg(c.X86_REG_ZMM3);
        pub const ZMM4 = from_uc_reg(c.X86_REG_ZMM4);
        pub const ZMM5 = from_uc_reg(c.X86_REG_ZMM5);
        pub const ZMM6 = from_uc_reg(c.X86_REG_ZMM6);
        pub const ZMM7 = from_uc_reg(c.X86_REG_ZMM7);
        pub const ZMM8 = from_uc_reg(c.X86_REG_ZMM8);
        pub const ZMM9 = from_uc_reg(c.X86_REG_ZMM9);
        pub const ZMM10 = from_uc_reg(c.X86_REG_ZMM10);
        pub const ZMM11 = from_uc_reg(c.X86_REG_ZMM11);
        pub const ZMM12 = from_uc_reg(c.X86_REG_ZMM12);
        pub const ZMM13 = from_uc_reg(c.X86_REG_ZMM13);
        pub const ZMM14 = from_uc_reg(c.X86_REG_ZMM14);
        pub const ZMM15 = from_uc_reg(c.X86_REG_ZMM15);
        pub const ZMM16 = from_uc_reg(c.X86_REG_ZMM16);
        pub const ZMM17 = from_uc_reg(c.X86_REG_ZMM17);
        pub const ZMM18 = from_uc_reg(c.X86_REG_ZMM18);
        pub const ZMM19 = from_uc_reg(c.X86_REG_ZMM19);
        pub const ZMM20 = from_uc_reg(c.X86_REG_ZMM20);
        pub const ZMM21 = from_uc_reg(c.X86_REG_ZMM21);
        pub const ZMM22 = from_uc_reg(c.X86_REG_ZMM22);
        pub const ZMM23 = from_uc_reg(c.X86_REG_ZMM23);
        pub const ZMM24 = from_uc_reg(c.X86_REG_ZMM24);
        pub const ZMM25 = from_uc_reg(c.X86_REG_ZMM25);
        pub const ZMM26 = from_uc_reg(c.X86_REG_ZMM26);
        pub const ZMM27 = from_uc_reg(c.X86_REG_ZMM27);
        pub const ZMM28 = from_uc_reg(c.X86_REG_ZMM28);
        pub const ZMM29 = from_uc_reg(c.X86_REG_ZMM29);
        pub const ZMM30 = from_uc_reg(c.X86_REG_ZMM30);
        pub const ZMM31 = from_uc_reg(c.X86_REG_ZMM31);
        pub const R8B = from_uc_reg(c.X86_REG_R8B);
        pub const R9B = from_uc_reg(c.X86_REG_R9B);
        pub const R10B = from_uc_reg(c.X86_REG_R10B);
        pub const R11B = from_uc_reg(c.X86_REG_R11B);
        pub const R12B = from_uc_reg(c.X86_REG_R12B);
        pub const R13B = from_uc_reg(c.X86_REG_R13B);
        pub const R14B = from_uc_reg(c.X86_REG_R14B);
        pub const R15B = from_uc_reg(c.X86_REG_R15B);
        pub const R8D = from_uc_reg(c.X86_REG_R8D);
        pub const R9D = from_uc_reg(c.X86_REG_R9D);
        pub const R10D = from_uc_reg(c.X86_REG_R10D);
        pub const R11D = from_uc_reg(c.X86_REG_R11D);
        pub const R12D = from_uc_reg(c.X86_REG_R12D);
        pub const R13D = from_uc_reg(c.X86_REG_R13D);
        pub const R14D = from_uc_reg(c.X86_REG_R14D);
        pub const R15D = from_uc_reg(c.X86_REG_R15D);
        pub const R8W = from_uc_reg(c.X86_REG_R8W);
        pub const R9W = from_uc_reg(c.X86_REG_R9W);
        pub const R10W = from_uc_reg(c.X86_REG_R10W);
        pub const R11W = from_uc_reg(c.X86_REG_R11W);
        pub const R12W = from_uc_reg(c.X86_REG_R12W);
        pub const R13W = from_uc_reg(c.X86_REG_R13W);
        pub const R14W = from_uc_reg(c.X86_REG_R14W);
        pub const R15W = from_uc_reg(c.X86_REG_R15W);
        pub const IDTR = from_uc_reg(c.X86_REG_IDTR);
        pub const GDTR = from_uc_reg(c.X86_REG_GDTR);
        pub const LDTR = from_uc_reg(c.X86_REG_LDTR);
        pub const TR = from_uc_reg(c.X86_REG_TR);
        pub const FPCW = from_uc_reg(c.X86_REG_FPCW);
        pub const FPTAG = from_uc_reg(c.X86_REG_FPTAG);
        pub const MSR = from_uc_reg(c.X86_REG_MSR);
        pub const MXCSR = from_uc_reg(c.X86_REG_MXCSR);
        pub const FS_BASE = from_uc_reg(c.X86_REG_FS_BASE);
        pub const GS_BASE = from_uc_reg(c.X86_REG_GS_BASE);
        pub const FLAGS = from_uc_reg(c.X86_REG_FLAGS);
        pub const RFLAGS = from_uc_reg(c.X86_REG_RFLAGS);
        pub const FIP = from_uc_reg(c.X86_REG_FIP);
        pub const FCS = from_uc_reg(c.X86_REG_FCS);
        pub const FDP = from_uc_reg(c.X86_REG_FDP);
        pub const FDS = from_uc_reg(c.X86_REG_FDS);
        pub const FOP = from_uc_reg(c.X86_REG_FOP);
        pub const ENDING = from_uc_reg(c.X86_REG_ENDING);
    };

    pub const Arm = struct {
        pub const INVALID = from_uc_reg(c.UC_ARM_REG_INVALID);
        pub const APSR = from_uc_reg(c.UC_ARM_REG_APSR);
        pub const APSR_NZCV = from_uc_reg(c.UC_ARM_REG_APSR_NZCV);
        pub const CPSR = from_uc_reg(c.UC_ARM_REG_CPSR);
        pub const FPEXC = from_uc_reg(c.UC_ARM_REG_FPEXC);
        pub const FPINST = from_uc_reg(c.UC_ARM_REG_FPINST);
        pub const FPSCR = from_uc_reg(c.UC_ARM_REG_FPSCR);
        pub const FPSCR_NZCV = from_uc_reg(c.UC_ARM_REG_FPSCR_NZCV);
        pub const FPSID = from_uc_reg(c.UC_ARM_REG_FPSID);
        pub const ITSTATE = from_uc_reg(c.UC_ARM_REG_ITSTATE);
        pub const LR = from_uc_reg(c.UC_ARM_REG_LR);
        pub const PC = from_uc_reg(c.UC_ARM_REG_PC);
        pub const SP = from_uc_reg(c.UC_ARM_REG_SP);
        pub const SPSR = from_uc_reg(c.UC_ARM_REG_SPSR);
        pub const D0 = from_uc_reg(c.UC_ARM_REG_D0);
        pub const D1 = from_uc_reg(c.UC_ARM_REG_D1);
        pub const D2 = from_uc_reg(c.UC_ARM_REG_D2);
        pub const D3 = from_uc_reg(c.UC_ARM_REG_D3);
        pub const D4 = from_uc_reg(c.UC_ARM_REG_D4);
        pub const D5 = from_uc_reg(c.UC_ARM_REG_D5);
        pub const D6 = from_uc_reg(c.UC_ARM_REG_D6);
        pub const D7 = from_uc_reg(c.UC_ARM_REG_D7);
        pub const D8 = from_uc_reg(c.UC_ARM_REG_D8);
        pub const D9 = from_uc_reg(c.UC_ARM_REG_D9);
        pub const D10 = from_uc_reg(c.UC_ARM_REG_D10);
        pub const D11 = from_uc_reg(c.UC_ARM_REG_D11);
        pub const D12 = from_uc_reg(c.UC_ARM_REG_D12);
        pub const D13 = from_uc_reg(c.UC_ARM_REG_D13);
        pub const D14 = from_uc_reg(c.UC_ARM_REG_D14);
        pub const D15 = from_uc_reg(c.UC_ARM_REG_D15);
        pub const D16 = from_uc_reg(c.UC_ARM_REG_D16);
        pub const D17 = from_uc_reg(c.UC_ARM_REG_D17);
        pub const D18 = from_uc_reg(c.UC_ARM_REG_D18);
        pub const D19 = from_uc_reg(c.UC_ARM_REG_D19);
        pub const D20 = from_uc_reg(c.UC_ARM_REG_D20);
        pub const D21 = from_uc_reg(c.UC_ARM_REG_D21);
        pub const D22 = from_uc_reg(c.UC_ARM_REG_D22);
        pub const D23 = from_uc_reg(c.UC_ARM_REG_D23);
        pub const D24 = from_uc_reg(c.UC_ARM_REG_D24);
        pub const D25 = from_uc_reg(c.UC_ARM_REG_D25);
        pub const D26 = from_uc_reg(c.UC_ARM_REG_D26);
        pub const D27 = from_uc_reg(c.UC_ARM_REG_D27);
        pub const D28 = from_uc_reg(c.UC_ARM_REG_D28);
        pub const D29 = from_uc_reg(c.UC_ARM_REG_D29);
        pub const D30 = from_uc_reg(c.UC_ARM_REG_D30);
        pub const D31 = from_uc_reg(c.UC_ARM_REG_D31);
        pub const FPINST2 = from_uc_reg(c.UC_ARM_REG_FPINST2);
        pub const MVFR0 = from_uc_reg(c.UC_ARM_REG_MVFR0);
        pub const MVFR1 = from_uc_reg(c.UC_ARM_REG_MVFR1);
        pub const MVFR2 = from_uc_reg(c.UC_ARM_REG_MVFR2);
        pub const Q0 = from_uc_reg(c.UC_ARM_REG_Q0);
        pub const Q1 = from_uc_reg(c.UC_ARM_REG_Q1);
        pub const Q2 = from_uc_reg(c.UC_ARM_REG_Q2);
        pub const Q3 = from_uc_reg(c.UC_ARM_REG_Q3);
        pub const Q4 = from_uc_reg(c.UC_ARM_REG_Q4);
        pub const Q5 = from_uc_reg(c.UC_ARM_REG_Q5);
        pub const Q6 = from_uc_reg(c.UC_ARM_REG_Q6);
        pub const Q7 = from_uc_reg(c.UC_ARM_REG_Q7);
        pub const Q8 = from_uc_reg(c.UC_ARM_REG_Q8);
        pub const Q9 = from_uc_reg(c.UC_ARM_REG_Q9);
        pub const Q10 = from_uc_reg(c.UC_ARM_REG_Q10);
        pub const Q11 = from_uc_reg(c.UC_ARM_REG_Q11);
        pub const Q12 = from_uc_reg(c.UC_ARM_REG_Q12);
        pub const Q13 = from_uc_reg(c.UC_ARM_REG_Q13);
        pub const Q14 = from_uc_reg(c.UC_ARM_REG_Q14);
        pub const Q15 = from_uc_reg(c.UC_ARM_REG_Q15);
        pub const R0 = from_uc_reg(c.UC_ARM_REG_R0);
        pub const R1 = from_uc_reg(c.UC_ARM_REG_R1);
        pub const R2 = from_uc_reg(c.UC_ARM_REG_R2);
        pub const R3 = from_uc_reg(c.UC_ARM_REG_R3);
        pub const R4 = from_uc_reg(c.UC_ARM_REG_R4);
        pub const R5 = from_uc_reg(c.UC_ARM_REG_R5);
        pub const R6 = from_uc_reg(c.UC_ARM_REG_R6);
        pub const R7 = from_uc_reg(c.UC_ARM_REG_R7);
        pub const R8 = from_uc_reg(c.UC_ARM_REG_R8);
        pub const R9 = from_uc_reg(c.UC_ARM_REG_R9);
        pub const R10 = from_uc_reg(c.UC_ARM_REG_R10);
        pub const R11 = from_uc_reg(c.UC_ARM_REG_R11);
        pub const R12 = from_uc_reg(c.UC_ARM_REG_R12);
        pub const S0 = from_uc_reg(c.UC_ARM_REG_S0);
        pub const S1 = from_uc_reg(c.UC_ARM_REG_S1);
        pub const S2 = from_uc_reg(c.UC_ARM_REG_S2);
        pub const S3 = from_uc_reg(c.UC_ARM_REG_S3);
        pub const S4 = from_uc_reg(c.UC_ARM_REG_S4);
        pub const S5 = from_uc_reg(c.UC_ARM_REG_S5);
        pub const S6 = from_uc_reg(c.UC_ARM_REG_S6);
        pub const S7 = from_uc_reg(c.UC_ARM_REG_S7);
        pub const S8 = from_uc_reg(c.UC_ARM_REG_S8);
        pub const S9 = from_uc_reg(c.UC_ARM_REG_S9);
        pub const S10 = from_uc_reg(c.UC_ARM_REG_S10);
        pub const S11 = from_uc_reg(c.UC_ARM_REG_S11);
        pub const S12 = from_uc_reg(c.UC_ARM_REG_S12);
        pub const S13 = from_uc_reg(c.UC_ARM_REG_S13);
        pub const S14 = from_uc_reg(c.UC_ARM_REG_S14);
        pub const S15 = from_uc_reg(c.UC_ARM_REG_S15);
        pub const S16 = from_uc_reg(c.UC_ARM_REG_S16);
        pub const S17 = from_uc_reg(c.UC_ARM_REG_S17);
        pub const S18 = from_uc_reg(c.UC_ARM_REG_S18);
        pub const S19 = from_uc_reg(c.UC_ARM_REG_S19);
        pub const S20 = from_uc_reg(c.UC_ARM_REG_S20);
        pub const S21 = from_uc_reg(c.UC_ARM_REG_S21);
        pub const S22 = from_uc_reg(c.UC_ARM_REG_S22);
        pub const S23 = from_uc_reg(c.UC_ARM_REG_S23);
        pub const S24 = from_uc_reg(c.UC_ARM_REG_S24);
        pub const S25 = from_uc_reg(c.UC_ARM_REG_S25);
        pub const S26 = from_uc_reg(c.UC_ARM_REG_S26);
        pub const S27 = from_uc_reg(c.UC_ARM_REG_S27);
        pub const S28 = from_uc_reg(c.UC_ARM_REG_S28);
        pub const S29 = from_uc_reg(c.UC_ARM_REG_S29);
        pub const S30 = from_uc_reg(c.UC_ARM_REG_S30);
        pub const S31 = from_uc_reg(c.UC_ARM_REG_S31);

        pub const C1_C0_2 = from_uc_reg(c.UC_ARM_REG_C1_C0_2); // Depreciated, use CP_REG instead;
        pub const C13_C0_2 = from_uc_reg(c.UC_ARM_REG_C13_C0_2); // Depreciated, use CP_REG instead;
        pub const C13_C0_3 = from_uc_reg(c.UC_ARM_REG_C13_C0_3); // Depreciated, use CP_REG instead;

        pub const IPSR = from_uc_reg(c.UC_ARM_REG_IPSR);
        pub const MSP = from_uc_reg(c.UC_ARM_REG_MSP);
        pub const PSP = from_uc_reg(c.UC_ARM_REG_PSP);
        pub const CONTROL = from_uc_reg(c.UC_ARM_REG_CONTROL);
        pub const IAPSR = from_uc_reg(c.UC_ARM_REG_IAPSR);
        pub const EAPSR = from_uc_reg(c.UC_ARM_REG_EAPSR);
        pub const XPSR = from_uc_reg(c.UC_ARM_REG_XPSR);
        pub const EPSR = from_uc_reg(c.UC_ARM_REG_EPSR);
        pub const IEPSR = from_uc_reg(c.UC_ARM_REG_IEPSR);
        pub const PRIMASK = from_uc_reg(c.UC_ARM_REG_PRIMASK);
        pub const BASEPRI = from_uc_reg(c.UC_ARM_REG_BASEPRI);
        pub const BASEPRI_MAX = from_uc_reg(c.UC_ARM_REG_BASEPRI_MAX);
        pub const FAULTMASK = from_uc_reg(c.UC_ARM_REG_FAULTMASK);
        pub const APSR_NZCVQ = from_uc_reg(c.UC_ARM_REG_APSR_NZCVQ);
        pub const APSR_G = from_uc_reg(c.UC_ARM_REG_APSR_G);
        pub const APSR_NZCVQG = from_uc_reg(c.UC_ARM_REG_APSR_NZCVQG);
        pub const IAPSR_NZCVQ = from_uc_reg(c.UC_ARM_REG_IAPSR_NZCVQ);
        pub const IAPSR_G = from_uc_reg(c.UC_ARM_REG_IAPSR_G);
        pub const IAPSR_NZCVQG = from_uc_reg(c.UC_ARM_REG_IAPSR_NZCVQG);
        pub const EAPSR_NZCVQ = from_uc_reg(c.UC_ARM_REG_EAPSR_NZCVQ);
        pub const EAPSR_G = from_uc_reg(c.UC_ARM_REG_EAPSR_G);
        pub const EAPSR_NZCVQG = from_uc_reg(c.UC_ARM_REG_EAPSR_NZCVQG);
        pub const XPSR_NZCVQ = from_uc_reg(c.UC_ARM_REG_XPSR_NZCVQ);
        pub const XPSR_G = from_uc_reg(c.UC_ARM_REG_XPSR_G);
        pub const XPSR_NZCVQG = from_uc_reg(c.UC_ARM_REG_XPSR_NZCVQG);
        pub const CP_REG = from_uc_reg(c.UC_ARM_REG_CP_REG);
        pub const ENDING = from_uc_reg(c.UC_ARM_REG_ENDING); // <-- mark the end of the list or registers;

        pub const R13 = SP;
        pub const R14 = LR;
        pub const R15 = PC;

        pub const SB = R9;
        pub const SL = R10;
        pub const FP = R11;
        pub const IP = R12;
    };

    pub const Arm64 = struct {
        pub const INVALID = from_uc_reg(c.ARM64_REG_INVALID);
        pub const X29 = from_uc_reg(c.ARM64_REG_X29);
        pub const X30 = from_uc_reg(c.ARM64_REG_X30);
        pub const NZCV = from_uc_reg(c.ARM64_REG_NZCV);
        pub const SP = from_uc_reg(c.ARM64_REG_SP);
        pub const WSP = from_uc_reg(c.ARM64_REG_WSP);
        pub const WZR = from_uc_reg(c.ARM64_REG_WZR);
        pub const XZR = from_uc_reg(c.ARM64_REG_XZR);
        pub const B0 = from_uc_reg(c.ARM64_REG_B0);
        pub const B1 = from_uc_reg(c.ARM64_REG_B1);
        pub const B2 = from_uc_reg(c.ARM64_REG_B2);
        pub const B3 = from_uc_reg(c.ARM64_REG_B3);
        pub const B4 = from_uc_reg(c.ARM64_REG_B4);
        pub const B5 = from_uc_reg(c.ARM64_REG_B5);
        pub const B6 = from_uc_reg(c.ARM64_REG_B6);
        pub const B7 = from_uc_reg(c.ARM64_REG_B7);
        pub const B8 = from_uc_reg(c.ARM64_REG_B8);
        pub const B9 = from_uc_reg(c.ARM64_REG_B9);
        pub const B10 = from_uc_reg(c.ARM64_REG_B10);
        pub const B11 = from_uc_reg(c.ARM64_REG_B11);
        pub const B12 = from_uc_reg(c.ARM64_REG_B12);
        pub const B13 = from_uc_reg(c.ARM64_REG_B13);
        pub const B14 = from_uc_reg(c.ARM64_REG_B14);
        pub const B15 = from_uc_reg(c.ARM64_REG_B15);
        pub const B16 = from_uc_reg(c.ARM64_REG_B16);
        pub const B17 = from_uc_reg(c.ARM64_REG_B17);
        pub const B18 = from_uc_reg(c.ARM64_REG_B18);
        pub const B19 = from_uc_reg(c.ARM64_REG_B19);
        pub const B20 = from_uc_reg(c.ARM64_REG_B20);
        pub const B21 = from_uc_reg(c.ARM64_REG_B21);
        pub const B22 = from_uc_reg(c.ARM64_REG_B22);
        pub const B23 = from_uc_reg(c.ARM64_REG_B23);
        pub const B24 = from_uc_reg(c.ARM64_REG_B24);
        pub const B25 = from_uc_reg(c.ARM64_REG_B25);
        pub const B26 = from_uc_reg(c.ARM64_REG_B26);
        pub const B27 = from_uc_reg(c.ARM64_REG_B27);
        pub const B28 = from_uc_reg(c.ARM64_REG_B28);
        pub const B29 = from_uc_reg(c.ARM64_REG_B29);
        pub const B30 = from_uc_reg(c.ARM64_REG_B30);
        pub const B31 = from_uc_reg(c.ARM64_REG_B31);
        pub const D0 = from_uc_reg(c.ARM64_REG_D0);
        pub const D1 = from_uc_reg(c.ARM64_REG_D1);
        pub const D2 = from_uc_reg(c.ARM64_REG_D2);
        pub const D3 = from_uc_reg(c.ARM64_REG_D3);
        pub const D4 = from_uc_reg(c.ARM64_REG_D4);
        pub const D5 = from_uc_reg(c.ARM64_REG_D5);
        pub const D6 = from_uc_reg(c.ARM64_REG_D6);
        pub const D7 = from_uc_reg(c.ARM64_REG_D7);
        pub const D8 = from_uc_reg(c.ARM64_REG_D8);
        pub const D9 = from_uc_reg(c.ARM64_REG_D9);
        pub const D10 = from_uc_reg(c.ARM64_REG_D10);
        pub const D11 = from_uc_reg(c.ARM64_REG_D11);
        pub const D12 = from_uc_reg(c.ARM64_REG_D12);
        pub const D13 = from_uc_reg(c.ARM64_REG_D13);
        pub const D14 = from_uc_reg(c.ARM64_REG_D14);
        pub const D15 = from_uc_reg(c.ARM64_REG_D15);
        pub const D16 = from_uc_reg(c.ARM64_REG_D16);
        pub const D17 = from_uc_reg(c.ARM64_REG_D17);
        pub const D18 = from_uc_reg(c.ARM64_REG_D18);
        pub const D19 = from_uc_reg(c.ARM64_REG_D19);
        pub const D20 = from_uc_reg(c.ARM64_REG_D20);
        pub const D21 = from_uc_reg(c.ARM64_REG_D21);
        pub const D22 = from_uc_reg(c.ARM64_REG_D22);
        pub const D23 = from_uc_reg(c.ARM64_REG_D23);
        pub const D24 = from_uc_reg(c.ARM64_REG_D24);
        pub const D25 = from_uc_reg(c.ARM64_REG_D25);
        pub const D26 = from_uc_reg(c.ARM64_REG_D26);
        pub const D27 = from_uc_reg(c.ARM64_REG_D27);
        pub const D28 = from_uc_reg(c.ARM64_REG_D28);
        pub const D29 = from_uc_reg(c.ARM64_REG_D29);
        pub const D30 = from_uc_reg(c.ARM64_REG_D30);
        pub const D31 = from_uc_reg(c.ARM64_REG_D31);
        pub const H0 = from_uc_reg(c.ARM64_REG_H0);
        pub const H1 = from_uc_reg(c.ARM64_REG_H1);
        pub const H2 = from_uc_reg(c.ARM64_REG_H2);
        pub const H3 = from_uc_reg(c.ARM64_REG_H3);
        pub const H4 = from_uc_reg(c.ARM64_REG_H4);
        pub const H5 = from_uc_reg(c.ARM64_REG_H5);
        pub const H6 = from_uc_reg(c.ARM64_REG_H6);
        pub const H7 = from_uc_reg(c.ARM64_REG_H7);
        pub const H8 = from_uc_reg(c.ARM64_REG_H8);
        pub const H9 = from_uc_reg(c.ARM64_REG_H9);
        pub const H10 = from_uc_reg(c.ARM64_REG_H10);
        pub const H11 = from_uc_reg(c.ARM64_REG_H11);
        pub const H12 = from_uc_reg(c.ARM64_REG_H12);
        pub const H13 = from_uc_reg(c.ARM64_REG_H13);
        pub const H14 = from_uc_reg(c.ARM64_REG_H14);
        pub const H15 = from_uc_reg(c.ARM64_REG_H15);
        pub const H16 = from_uc_reg(c.ARM64_REG_H16);
        pub const H17 = from_uc_reg(c.ARM64_REG_H17);
        pub const H18 = from_uc_reg(c.ARM64_REG_H18);
        pub const H19 = from_uc_reg(c.ARM64_REG_H19);
        pub const H20 = from_uc_reg(c.ARM64_REG_H20);
        pub const H21 = from_uc_reg(c.ARM64_REG_H21);
        pub const H22 = from_uc_reg(c.ARM64_REG_H22);
        pub const H23 = from_uc_reg(c.ARM64_REG_H23);
        pub const H24 = from_uc_reg(c.ARM64_REG_H24);
        pub const H25 = from_uc_reg(c.ARM64_REG_H25);
        pub const H26 = from_uc_reg(c.ARM64_REG_H26);
        pub const H27 = from_uc_reg(c.ARM64_REG_H27);
        pub const H28 = from_uc_reg(c.ARM64_REG_H28);
        pub const H29 = from_uc_reg(c.ARM64_REG_H29);
        pub const H30 = from_uc_reg(c.ARM64_REG_H30);
        pub const H31 = from_uc_reg(c.ARM64_REG_H31);
        pub const Q0 = from_uc_reg(c.ARM64_REG_Q0);
        pub const Q1 = from_uc_reg(c.ARM64_REG_Q1);
        pub const Q2 = from_uc_reg(c.ARM64_REG_Q2);
        pub const Q3 = from_uc_reg(c.ARM64_REG_Q3);
        pub const Q4 = from_uc_reg(c.ARM64_REG_Q4);
        pub const Q5 = from_uc_reg(c.ARM64_REG_Q5);
        pub const Q6 = from_uc_reg(c.ARM64_REG_Q6);
        pub const Q7 = from_uc_reg(c.ARM64_REG_Q7);
        pub const Q8 = from_uc_reg(c.ARM64_REG_Q8);
        pub const Q9 = from_uc_reg(c.ARM64_REG_Q9);
        pub const Q10 = from_uc_reg(c.ARM64_REG_Q10);
        pub const Q11 = from_uc_reg(c.ARM64_REG_Q11);
        pub const Q12 = from_uc_reg(c.ARM64_REG_Q12);
        pub const Q13 = from_uc_reg(c.ARM64_REG_Q13);
        pub const Q14 = from_uc_reg(c.ARM64_REG_Q14);
        pub const Q15 = from_uc_reg(c.ARM64_REG_Q15);
        pub const Q16 = from_uc_reg(c.ARM64_REG_Q16);
        pub const Q17 = from_uc_reg(c.ARM64_REG_Q17);
        pub const Q18 = from_uc_reg(c.ARM64_REG_Q18);
        pub const Q19 = from_uc_reg(c.ARM64_REG_Q19);
        pub const Q20 = from_uc_reg(c.ARM64_REG_Q20);
        pub const Q21 = from_uc_reg(c.ARM64_REG_Q21);
        pub const Q22 = from_uc_reg(c.ARM64_REG_Q22);
        pub const Q23 = from_uc_reg(c.ARM64_REG_Q23);
        pub const Q24 = from_uc_reg(c.ARM64_REG_Q24);
        pub const Q25 = from_uc_reg(c.ARM64_REG_Q25);
        pub const Q26 = from_uc_reg(c.ARM64_REG_Q26);
        pub const Q27 = from_uc_reg(c.ARM64_REG_Q27);
        pub const Q28 = from_uc_reg(c.ARM64_REG_Q28);
        pub const Q29 = from_uc_reg(c.ARM64_REG_Q29);
        pub const Q30 = from_uc_reg(c.ARM64_REG_Q30);
        pub const Q31 = from_uc_reg(c.ARM64_REG_Q31);
        pub const S0 = from_uc_reg(c.ARM64_REG_S0);
        pub const S1 = from_uc_reg(c.ARM64_REG_S1);
        pub const S2 = from_uc_reg(c.ARM64_REG_S2);
        pub const S3 = from_uc_reg(c.ARM64_REG_S3);
        pub const S4 = from_uc_reg(c.ARM64_REG_S4);
        pub const S5 = from_uc_reg(c.ARM64_REG_S5);
        pub const S6 = from_uc_reg(c.ARM64_REG_S6);
        pub const S7 = from_uc_reg(c.ARM64_REG_S7);
        pub const S8 = from_uc_reg(c.ARM64_REG_S8);
        pub const S9 = from_uc_reg(c.ARM64_REG_S9);
        pub const S10 = from_uc_reg(c.ARM64_REG_S10);
        pub const S11 = from_uc_reg(c.ARM64_REG_S11);
        pub const S12 = from_uc_reg(c.ARM64_REG_S12);
        pub const S13 = from_uc_reg(c.ARM64_REG_S13);
        pub const S14 = from_uc_reg(c.ARM64_REG_S14);
        pub const S15 = from_uc_reg(c.ARM64_REG_S15);
        pub const S16 = from_uc_reg(c.ARM64_REG_S16);
        pub const S17 = from_uc_reg(c.ARM64_REG_S17);
        pub const S18 = from_uc_reg(c.ARM64_REG_S18);
        pub const S19 = from_uc_reg(c.ARM64_REG_S19);
        pub const S20 = from_uc_reg(c.ARM64_REG_S20);
        pub const S21 = from_uc_reg(c.ARM64_REG_S21);
        pub const S22 = from_uc_reg(c.ARM64_REG_S22);
        pub const S23 = from_uc_reg(c.ARM64_REG_S23);
        pub const S24 = from_uc_reg(c.ARM64_REG_S24);
        pub const S25 = from_uc_reg(c.ARM64_REG_S25);
        pub const S26 = from_uc_reg(c.ARM64_REG_S26);
        pub const S27 = from_uc_reg(c.ARM64_REG_S27);
        pub const S28 = from_uc_reg(c.ARM64_REG_S28);
        pub const S29 = from_uc_reg(c.ARM64_REG_S29);
        pub const S30 = from_uc_reg(c.ARM64_REG_S30);
        pub const S31 = from_uc_reg(c.ARM64_REG_S31);
        pub const W0 = from_uc_reg(c.ARM64_REG_W0);
        pub const W1 = from_uc_reg(c.ARM64_REG_W1);
        pub const W2 = from_uc_reg(c.ARM64_REG_W2);
        pub const W3 = from_uc_reg(c.ARM64_REG_W3);
        pub const W4 = from_uc_reg(c.ARM64_REG_W4);
        pub const W5 = from_uc_reg(c.ARM64_REG_W5);
        pub const W6 = from_uc_reg(c.ARM64_REG_W6);
        pub const W7 = from_uc_reg(c.ARM64_REG_W7);
        pub const W8 = from_uc_reg(c.ARM64_REG_W8);
        pub const W9 = from_uc_reg(c.ARM64_REG_W9);
        pub const W10 = from_uc_reg(c.ARM64_REG_W10);
        pub const W11 = from_uc_reg(c.ARM64_REG_W11);
        pub const W12 = from_uc_reg(c.ARM64_REG_W12);
        pub const W13 = from_uc_reg(c.ARM64_REG_W13);
        pub const W14 = from_uc_reg(c.ARM64_REG_W14);
        pub const W15 = from_uc_reg(c.ARM64_REG_W15);
        pub const W16 = from_uc_reg(c.ARM64_REG_W16);
        pub const W17 = from_uc_reg(c.ARM64_REG_W17);
        pub const W18 = from_uc_reg(c.ARM64_REG_W18);
        pub const W19 = from_uc_reg(c.ARM64_REG_W19);
        pub const W20 = from_uc_reg(c.ARM64_REG_W20);
        pub const W21 = from_uc_reg(c.ARM64_REG_W21);
        pub const W22 = from_uc_reg(c.ARM64_REG_W22);
        pub const W23 = from_uc_reg(c.ARM64_REG_W23);
        pub const W24 = from_uc_reg(c.ARM64_REG_W24);
        pub const W25 = from_uc_reg(c.ARM64_REG_W25);
        pub const W26 = from_uc_reg(c.ARM64_REG_W26);
        pub const W27 = from_uc_reg(c.ARM64_REG_W27);
        pub const W28 = from_uc_reg(c.ARM64_REG_W28);
        pub const W29 = from_uc_reg(c.ARM64_REG_W29);
        pub const W30 = from_uc_reg(c.ARM64_REG_W30);
        pub const X0 = from_uc_reg(c.ARM64_REG_X0);
        pub const X1 = from_uc_reg(c.ARM64_REG_X1);
        pub const X2 = from_uc_reg(c.ARM64_REG_X2);
        pub const X3 = from_uc_reg(c.ARM64_REG_X3);
        pub const X4 = from_uc_reg(c.ARM64_REG_X4);
        pub const X5 = from_uc_reg(c.ARM64_REG_X5);
        pub const X6 = from_uc_reg(c.ARM64_REG_X6);
        pub const X7 = from_uc_reg(c.ARM64_REG_X7);
        pub const X8 = from_uc_reg(c.ARM64_REG_X8);
        pub const X9 = from_uc_reg(c.ARM64_REG_X9);
        pub const X10 = from_uc_reg(c.ARM64_REG_X10);
        pub const X11 = from_uc_reg(c.ARM64_REG_X11);
        pub const X12 = from_uc_reg(c.ARM64_REG_X12);
        pub const X13 = from_uc_reg(c.ARM64_REG_X13);
        pub const X14 = from_uc_reg(c.ARM64_REG_X14);
        pub const X15 = from_uc_reg(c.ARM64_REG_X15);
        pub const X16 = from_uc_reg(c.ARM64_REG_X16);
        pub const X17 = from_uc_reg(c.ARM64_REG_X17);
        pub const X18 = from_uc_reg(c.ARM64_REG_X18);
        pub const X19 = from_uc_reg(c.ARM64_REG_X19);
        pub const X20 = from_uc_reg(c.ARM64_REG_X20);
        pub const X21 = from_uc_reg(c.ARM64_REG_X21);
        pub const X22 = from_uc_reg(c.ARM64_REG_X22);
        pub const X23 = from_uc_reg(c.ARM64_REG_X23);
        pub const X24 = from_uc_reg(c.ARM64_REG_X24);
        pub const X25 = from_uc_reg(c.ARM64_REG_X25);
        pub const X26 = from_uc_reg(c.ARM64_REG_X26);
        pub const X27 = from_uc_reg(c.ARM64_REG_X27);
        pub const X28 = from_uc_reg(c.ARM64_REG_X28);
        pub const V0 = from_uc_reg(c.ARM64_REG_V0);
        pub const V1 = from_uc_reg(c.ARM64_REG_V1);
        pub const V2 = from_uc_reg(c.ARM64_REG_V2);
        pub const V3 = from_uc_reg(c.ARM64_REG_V3);
        pub const V4 = from_uc_reg(c.ARM64_REG_V4);
        pub const V5 = from_uc_reg(c.ARM64_REG_V5);
        pub const V6 = from_uc_reg(c.ARM64_REG_V6);
        pub const V7 = from_uc_reg(c.ARM64_REG_V7);
        pub const V8 = from_uc_reg(c.ARM64_REG_V8);
        pub const V9 = from_uc_reg(c.ARM64_REG_V9);
        pub const V10 = from_uc_reg(c.ARM64_REG_V10);
        pub const V11 = from_uc_reg(c.ARM64_REG_V11);
        pub const V12 = from_uc_reg(c.ARM64_REG_V12);
        pub const V13 = from_uc_reg(c.ARM64_REG_V13);
        pub const V14 = from_uc_reg(c.ARM64_REG_V14);
        pub const V15 = from_uc_reg(c.ARM64_REG_V15);
        pub const V16 = from_uc_reg(c.ARM64_REG_V16);
        pub const V17 = from_uc_reg(c.ARM64_REG_V17);
        pub const V18 = from_uc_reg(c.ARM64_REG_V18);
        pub const V19 = from_uc_reg(c.ARM64_REG_V19);
        pub const V20 = from_uc_reg(c.ARM64_REG_V20);
        pub const V21 = from_uc_reg(c.ARM64_REG_V21);
        pub const V22 = from_uc_reg(c.ARM64_REG_V22);
        pub const V23 = from_uc_reg(c.ARM64_REG_V23);
        pub const V24 = from_uc_reg(c.ARM64_REG_V24);
        pub const V25 = from_uc_reg(c.ARM64_REG_V25);
        pub const V26 = from_uc_reg(c.ARM64_REG_V26);
        pub const V27 = from_uc_reg(c.ARM64_REG_V27);
        pub const V28 = from_uc_reg(c.ARM64_REG_V28);
        pub const V29 = from_uc_reg(c.ARM64_REG_V29);
        pub const V30 = from_uc_reg(c.ARM64_REG_V30);
        pub const V31 = from_uc_reg(c.ARM64_REG_V31);

        // pseudo registers
        pub const PC = from_uc_reg(c.ARM64_REG_PC);
        pub const CPACR_EL1 = from_uc_reg(c.ARM64_REG_CPACR_EL1);

        // thread registers, depreciated, use UC_ARM64_REG_CP_REG instead
        pub const TPIDR_EL0 = from_uc_reg(c.ARM64_REG_TPIDR_EL0);
        pub const TPIDRRO_EL0 = from_uc_reg(c.ARM64_REG_TPIDRRO_EL0);
        pub const TPIDR_EL1 = from_uc_reg(c.ARM64_REG_TPIDR_EL1);
        pub const PSTATE = from_uc_reg(c.ARM64_REG_PSTATE);

        // exception link registers, depreciated, use UC_ARM64_REG_CP_REG instead
        pub const ELR_EL0 = from_uc_reg(c.ARM64_REG_ELR_EL0);
        pub const ELR_EL1 = from_uc_reg(c.ARM64_REG_ELR_EL1);
        pub const ELR_EL2 = from_uc_reg(c.ARM64_REG_ELR_EL2);
        pub const ELR_EL3 = from_uc_reg(c.ARM64_REG_ELR_EL3);

        // stack pointers registers, depreciated, use UC_ARM64_REG_CP_REG instead
        pub const SP_EL0 = from_uc_reg(c.ARM64_REG_SP_EL0);
        pub const SP_EL1 = from_uc_reg(c.ARM64_REG_SP_EL1);
        pub const SP_EL2 = from_uc_reg(c.ARM64_REG_SP_EL2);
        pub const SP_EL3 = from_uc_reg(c.ARM64_REG_SP_EL3);

        // other CP15 registers, depreciated, use UC_ARM64_REG_CP_REG instead
        pub const TTBR0_EL1 = from_uc_reg(c.ARM64_REG_TTBR0_EL1);
        pub const TTBR1_EL1 = from_uc_reg(c.ARM64_REG_TTBR1_EL1);
        pub const ESR_EL0 = from_uc_reg(c.ARM64_REG_ESR_EL0);
        pub const ESR_EL1 = from_uc_reg(c.ARM64_REG_ESR_EL1);
        pub const ESR_EL2 = from_uc_reg(c.ARM64_REG_ESR_EL2);
        pub const ESR_EL3 = from_uc_reg(c.ARM64_REG_ESR_EL3);
        pub const FAR_EL0 = from_uc_reg(c.ARM64_REG_FAR_EL0);
        pub const FAR_EL1 = from_uc_reg(c.ARM64_REG_FAR_EL1);
        pub const FAR_EL2 = from_uc_reg(c.ARM64_REG_FAR_EL2);
        pub const FAR_EL3 = from_uc_reg(c.ARM64_REG_FAR_EL3);
        pub const PAR_EL1 = from_uc_reg(c.ARM64_REG_PAR_EL1);
        pub const MAIR_EL1 = from_uc_reg(c.ARM64_REG_MAIR_EL1);
        pub const VBAR_EL0 = from_uc_reg(c.ARM64_REG_VBAR_EL0);
        pub const VBAR_EL1 = from_uc_reg(c.ARM64_REG_VBAR_EL1);
        pub const VBAR_EL2 = from_uc_reg(c.ARM64_REG_VBAR_EL2);
        pub const VBAR_EL3 = from_uc_reg(c.ARM64_REG_VBAR_EL3);
        pub const CP_REG = from_uc_reg(c.ARM64_REG_CP_REG);

        // floating point control and status registers
        pub const FPCR = from_uc_reg(c.ARM64_REG_FPCR);
        pub const FPSR = from_uc_reg(c.ARM64_REG_FPSR);
        pub const ENDING = from_uc_reg(c.ARM64_REG_ENDING);

        // alias registers
        pub const IP0 = from_uc_reg(c.ARM64_REG_IP0);
        pub const IP1 = from_uc_reg(c.ARM64_REG_IP1);
        pub const FP = from_uc_reg(c.ARM64_REG_FP);
        pub const LR = from_uc_reg(c.ARM64_REG_LR);
    };

    pub const Mips = struct {
        pub const INVALID = from_uc_reg(c.MIPS_REG_INVALID);

        // General purpose registers
        pub const PC = from_uc_reg(c.MIPS_REG_PC);
        pub const @"0" = from_uc_reg(c.MIPS_REG_0);
        pub const @"1" = from_uc_reg(c.MIPS_REG_1);
        pub const @"2" = from_uc_reg(c.MIPS_REG_2);
        pub const @"3" = from_uc_reg(c.MIPS_REG_3);
        pub const @"4" = from_uc_reg(c.MIPS_REG_4);
        pub const @"5" = from_uc_reg(c.MIPS_REG_5);
        pub const @"6" = from_uc_reg(c.MIPS_REG_6);
        pub const @"7" = from_uc_reg(c.MIPS_REG_7);
        pub const @"8" = from_uc_reg(c.MIPS_REG_8);
        pub const @"9" = from_uc_reg(c.MIPS_REG_9);
        pub const @"10" = from_uc_reg(c.MIPS_REG_10);
        pub const @"11" = from_uc_reg(c.MIPS_REG_11);
        pub const @"12" = from_uc_reg(c.MIPS_REG_12);
        pub const @"13" = from_uc_reg(c.MIPS_REG_13);
        pub const @"14" = from_uc_reg(c.MIPS_REG_14);
        pub const @"15" = from_uc_reg(c.MIPS_REG_15);
        pub const @"16" = from_uc_reg(c.MIPS_REG_16);
        pub const @"17" = from_uc_reg(c.MIPS_REG_17);
        pub const @"18" = from_uc_reg(c.MIPS_REG_18);
        pub const @"19" = from_uc_reg(c.MIPS_REG_19);
        pub const @"20" = from_uc_reg(c.MIPS_REG_20);
        pub const @"21" = from_uc_reg(c.MIPS_REG_21);
        pub const @"22" = from_uc_reg(c.MIPS_REG_22);
        pub const @"23" = from_uc_reg(c.MIPS_REG_23);
        pub const @"24" = from_uc_reg(c.MIPS_REG_24);
        pub const @"25" = from_uc_reg(c.MIPS_REG_25);
        pub const @"26" = from_uc_reg(c.MIPS_REG_26);
        pub const @"27" = from_uc_reg(c.MIPS_REG_27);
        pub const @"28" = from_uc_reg(c.MIPS_REG_28);
        pub const @"29" = from_uc_reg(c.MIPS_REG_29);
        pub const @"30" = from_uc_reg(c.MIPS_REG_30);
        pub const @"31" = from_uc_reg(c.MIPS_REG_31);

        // DSP registers
        pub const DSPCCOND = from_uc_reg(c.MIPS_REG_DSPCCOND);
        pub const DSPCARRY = from_uc_reg(c.MIPS_REG_DSPCARRY);
        pub const DSPEFI = from_uc_reg(c.MIPS_REG_DSPEFI);
        pub const DSPOUTFLAG = from_uc_reg(c.MIPS_REG_DSPOUTFLAG);
        pub const DSPOUTFLAG16_19 = from_uc_reg(c.MIPS_REG_DSPOUTFLAG16_19);
        pub const DSPOUTFLAG20 = from_uc_reg(c.MIPS_REG_DSPOUTFLAG20);
        pub const DSPOUTFLAG21 = from_uc_reg(c.MIPS_REG_DSPOUTFLAG21);
        pub const DSPOUTFLAG22 = from_uc_reg(c.MIPS_REG_DSPOUTFLAG22);
        pub const DSPOUTFLAG23 = from_uc_reg(c.MIPS_REG_DSPOUTFLAG23);
        pub const DSPPOS = from_uc_reg(c.MIPS_REG_DSPPOS);
        pub const DSPSCOUNT = from_uc_reg(c.MIPS_REG_DSPSCOUNT);

        // ACC registers
        pub const AC0 = from_uc_reg(c.MIPS_REG_AC0);
        pub const AC1 = from_uc_reg(c.MIPS_REG_AC1);
        pub const AC2 = from_uc_reg(c.MIPS_REG_AC2);
        pub const AC3 = from_uc_reg(c.MIPS_REG_AC3);

        // COP registers
        pub const CC0 = from_uc_reg(c.MIPS_REG_CC0);
        pub const CC1 = from_uc_reg(c.MIPS_REG_CC1);
        pub const CC2 = from_uc_reg(c.MIPS_REG_CC2);
        pub const CC3 = from_uc_reg(c.MIPS_REG_CC3);
        pub const CC4 = from_uc_reg(c.MIPS_REG_CC4);
        pub const CC5 = from_uc_reg(c.MIPS_REG_CC5);
        pub const CC6 = from_uc_reg(c.MIPS_REG_CC6);
        pub const CC7 = from_uc_reg(c.MIPS_REG_CC7);

        // FPU registers
        pub const F0 = from_uc_reg(c.MIPS_REG_F0);
        pub const F1 = from_uc_reg(c.MIPS_REG_F1);
        pub const F2 = from_uc_reg(c.MIPS_REG_F2);
        pub const F3 = from_uc_reg(c.MIPS_REG_F3);
        pub const F4 = from_uc_reg(c.MIPS_REG_F4);
        pub const F5 = from_uc_reg(c.MIPS_REG_F5);
        pub const F6 = from_uc_reg(c.MIPS_REG_F6);
        pub const F7 = from_uc_reg(c.MIPS_REG_F7);
        pub const F8 = from_uc_reg(c.MIPS_REG_F8);
        pub const F9 = from_uc_reg(c.MIPS_REG_F9);
        pub const F10 = from_uc_reg(c.MIPS_REG_F10);
        pub const F11 = from_uc_reg(c.MIPS_REG_F11);
        pub const F12 = from_uc_reg(c.MIPS_REG_F12);
        pub const F13 = from_uc_reg(c.MIPS_REG_F13);
        pub const F14 = from_uc_reg(c.MIPS_REG_F14);
        pub const F15 = from_uc_reg(c.MIPS_REG_F15);
        pub const F16 = from_uc_reg(c.MIPS_REG_F16);
        pub const F17 = from_uc_reg(c.MIPS_REG_F17);
        pub const F18 = from_uc_reg(c.MIPS_REG_F18);
        pub const F19 = from_uc_reg(c.MIPS_REG_F19);
        pub const F20 = from_uc_reg(c.MIPS_REG_F20);
        pub const F21 = from_uc_reg(c.MIPS_REG_F21);
        pub const F22 = from_uc_reg(c.MIPS_REG_F22);
        pub const F23 = from_uc_reg(c.MIPS_REG_F23);
        pub const F24 = from_uc_reg(c.MIPS_REG_F24);
        pub const F25 = from_uc_reg(c.MIPS_REG_F25);
        pub const F26 = from_uc_reg(c.MIPS_REG_F26);
        pub const F27 = from_uc_reg(c.MIPS_REG_F27);
        pub const F28 = from_uc_reg(c.MIPS_REG_F28);
        pub const F29 = from_uc_reg(c.MIPS_REG_F29);
        pub const F30 = from_uc_reg(c.MIPS_REG_F30);
        pub const F31 = from_uc_reg(c.MIPS_REG_F31);
        pub const FCC0 = from_uc_reg(c.MIPS_REG_FCC0);
        pub const FCC1 = from_uc_reg(c.MIPS_REG_FCC1);
        pub const FCC2 = from_uc_reg(c.MIPS_REG_FCC2);
        pub const FCC3 = from_uc_reg(c.MIPS_REG_FCC3);
        pub const FCC4 = from_uc_reg(c.MIPS_REG_FCC4);
        pub const FCC5 = from_uc_reg(c.MIPS_REG_FCC5);
        pub const FCC6 = from_uc_reg(c.MIPS_REG_FCC6);
        pub const FCC7 = from_uc_reg(c.MIPS_REG_FCC7);

        // AFPR128
        pub const W0 = from_uc_reg(c.MIPS_REG_W0);
        pub const W1 = from_uc_reg(c.MIPS_REG_W1);
        pub const W2 = from_uc_reg(c.MIPS_REG_W2);
        pub const W3 = from_uc_reg(c.MIPS_REG_W3);
        pub const W4 = from_uc_reg(c.MIPS_REG_W4);
        pub const W5 = from_uc_reg(c.MIPS_REG_W5);
        pub const W6 = from_uc_reg(c.MIPS_REG_W6);
        pub const W7 = from_uc_reg(c.MIPS_REG_W7);
        pub const W8 = from_uc_reg(c.MIPS_REG_W8);
        pub const W9 = from_uc_reg(c.MIPS_REG_W9);
        pub const W10 = from_uc_reg(c.MIPS_REG_W10);
        pub const W11 = from_uc_reg(c.MIPS_REG_W11);
        pub const W12 = from_uc_reg(c.MIPS_REG_W12);
        pub const W13 = from_uc_reg(c.MIPS_REG_W13);
        pub const W14 = from_uc_reg(c.MIPS_REG_W14);
        pub const W15 = from_uc_reg(c.MIPS_REG_W15);
        pub const W16 = from_uc_reg(c.MIPS_REG_W16);
        pub const W17 = from_uc_reg(c.MIPS_REG_W17);
        pub const W18 = from_uc_reg(c.MIPS_REG_W18);
        pub const W19 = from_uc_reg(c.MIPS_REG_W19);
        pub const W20 = from_uc_reg(c.MIPS_REG_W20);
        pub const W21 = from_uc_reg(c.MIPS_REG_W21);
        pub const W22 = from_uc_reg(c.MIPS_REG_W22);
        pub const W23 = from_uc_reg(c.MIPS_REG_W23);
        pub const W24 = from_uc_reg(c.MIPS_REG_W24);
        pub const W25 = from_uc_reg(c.MIPS_REG_W25);
        pub const W26 = from_uc_reg(c.MIPS_REG_W26);
        pub const W27 = from_uc_reg(c.MIPS_REG_W27);
        pub const W28 = from_uc_reg(c.MIPS_REG_W28);
        pub const W29 = from_uc_reg(c.MIPS_REG_W29);
        pub const W30 = from_uc_reg(c.MIPS_REG_W30);
        pub const W31 = from_uc_reg(c.MIPS_REG_W31);
        pub const HI = from_uc_reg(c.MIPS_REG_HI);
        pub const LO = from_uc_reg(c.MIPS_REG_LO);
        pub const P0 = from_uc_reg(c.MIPS_REG_P0);
        pub const P1 = from_uc_reg(c.MIPS_REG_P1);
        pub const P2 = from_uc_reg(c.MIPS_REG_P2);
        pub const MPL0 = from_uc_reg(c.MIPS_REG_MPL0);
        pub const MPL1 = from_uc_reg(c.MIPS_REG_MPL1);
        pub const MPL2 = from_uc_reg(c.MIPS_REG_MPL2);
        pub const CP0_CONFIG3 = from_uc_reg(c.MIPS_REG_CP0_CONFIG3);
        pub const CP0_USERLOCAL = from_uc_reg(c.MIPS_REG_CP0_USERLOCAL);
        pub const CP0_STATUS = from_uc_reg(c.MIPS_REG_CP0_STATUS);
        pub const ENDING = from_uc_reg(c.MIPS_REG_ENDING);
        pub const ZERO = from_uc_reg(c.MIPS_REG_ZERO);
        pub const AT = from_uc_reg(c.MIPS_REG_AT);
        pub const V0 = from_uc_reg(c.MIPS_REG_V0);
        pub const V1 = from_uc_reg(c.MIPS_REG_V1);
        pub const A0 = from_uc_reg(c.MIPS_REG_A0);
        pub const A1 = from_uc_reg(c.MIPS_REG_A1);
        pub const A2 = from_uc_reg(c.MIPS_REG_A2);
        pub const A3 = from_uc_reg(c.MIPS_REG_A3);
        pub const T0 = from_uc_reg(c.MIPS_REG_T0);
        pub const T1 = from_uc_reg(c.MIPS_REG_T1);
        pub const T2 = from_uc_reg(c.MIPS_REG_T2);
        pub const T3 = from_uc_reg(c.MIPS_REG_T3);
        pub const T4 = from_uc_reg(c.MIPS_REG_T4);
        pub const T5 = from_uc_reg(c.MIPS_REG_T5);
        pub const T6 = from_uc_reg(c.MIPS_REG_T6);
        pub const T7 = from_uc_reg(c.MIPS_REG_T7);
        pub const S0 = from_uc_reg(c.MIPS_REG_S0);
        pub const S1 = from_uc_reg(c.MIPS_REG_S1);
        pub const S2 = from_uc_reg(c.MIPS_REG_S2);
        pub const S3 = from_uc_reg(c.MIPS_REG_S3);
        pub const S4 = from_uc_reg(c.MIPS_REG_S4);
        pub const S5 = from_uc_reg(c.MIPS_REG_S5);
        pub const S6 = from_uc_reg(c.MIPS_REG_S6);
        pub const S7 = from_uc_reg(c.MIPS_REG_S7);
        pub const T8 = from_uc_reg(c.MIPS_REG_T8);
        pub const T9 = from_uc_reg(c.MIPS_REG_T9);
        pub const K0 = from_uc_reg(c.MIPS_REG_K0);
        pub const K1 = from_uc_reg(c.MIPS_REG_K1);
        pub const GP = from_uc_reg(c.MIPS_REG_GP);
        pub const SP = from_uc_reg(c.MIPS_REG_SP);
        pub const FP = from_uc_reg(c.MIPS_REG_FP);
        pub const S8 = from_uc_reg(c.MIPS_REG_S8);
        pub const RA = from_uc_reg(c.MIPS_REG_RA);
        pub const HI0 = from_uc_reg(c.MIPS_REG_HI0);
        pub const HI1 = from_uc_reg(c.MIPS_REG_HI1);
        pub const HI2 = from_uc_reg(c.MIPS_REG_HI2);
        pub const HI3 = from_uc_reg(c.MIPS_REG_HI3);
        pub const LO0 = from_uc_reg(c.MIPS_REG_LO0);
        pub const LO1 = from_uc_reg(c.MIPS_REG_LO1);
        pub const LO2 = from_uc_reg(c.MIPS_REG_LO2);
        pub const LO3 = from_uc_reg(c.MIPS_REG_LO3);
    };

    pub const Mips32 = Mips;
    pub const Mips64 = Mips;

    pub const Ppc = struct {
        pub const INVALID = from_uc_reg(c.PPC_REG_INVALID);

        // General purpose registers
        pub const PC = from_uc_reg(c.PPC_REG_PC);
        pub const @"0" = from_uc_reg(c.PPC_REG_0);
        pub const @"1" = from_uc_reg(c.PPC_REG_1);
        pub const @"2" = from_uc_reg(c.PPC_REG_2);
        pub const @"3" = from_uc_reg(c.PPC_REG_3);
        pub const @"4" = from_uc_reg(c.PPC_REG_4);
        pub const @"5" = from_uc_reg(c.PPC_REG_5);
        pub const @"6" = from_uc_reg(c.PPC_REG_6);
        pub const @"7" = from_uc_reg(c.PPC_REG_7);
        pub const @"8" = from_uc_reg(c.PPC_REG_8);
        pub const @"9" = from_uc_reg(c.PPC_REG_9);
        pub const @"10" = from_uc_reg(c.PPC_REG_10);
        pub const @"11" = from_uc_reg(c.PPC_REG_11);
        pub const @"12" = from_uc_reg(c.PPC_REG_12);
        pub const @"13" = from_uc_reg(c.PPC_REG_13);
        pub const @"14" = from_uc_reg(c.PPC_REG_14);
        pub const @"15" = from_uc_reg(c.PPC_REG_15);
        pub const @"16" = from_uc_reg(c.PPC_REG_16);
        pub const @"17" = from_uc_reg(c.PPC_REG_17);
        pub const @"18" = from_uc_reg(c.PPC_REG_18);
        pub const @"19" = from_uc_reg(c.PPC_REG_19);
        pub const @"20" = from_uc_reg(c.PPC_REG_20);
        pub const @"21" = from_uc_reg(c.PPC_REG_21);
        pub const @"22" = from_uc_reg(c.PPC_REG_22);
        pub const @"23" = from_uc_reg(c.PPC_REG_23);
        pub const @"24" = from_uc_reg(c.PPC_REG_24);
        pub const @"25" = from_uc_reg(c.PPC_REG_25);
        pub const @"26" = from_uc_reg(c.PPC_REG_26);
        pub const @"27" = from_uc_reg(c.PPC_REG_27);
        pub const @"28" = from_uc_reg(c.PPC_REG_28);
        pub const @"29" = from_uc_reg(c.PPC_REG_29);
        pub const @"30" = from_uc_reg(c.PPC_REG_30);
        pub const @"31" = from_uc_reg(c.PPC_REG_31);
        pub const CR0 = from_uc_reg(c.PPC_REG_CR0);
        pub const CR1 = from_uc_reg(c.PPC_REG_CR1);
        pub const CR2 = from_uc_reg(c.PPC_REG_CR2);
        pub const CR3 = from_uc_reg(c.PPC_REG_CR3);
        pub const CR4 = from_uc_reg(c.PPC_REG_CR4);
        pub const CR5 = from_uc_reg(c.PPC_REG_CR5);
        pub const CR6 = from_uc_reg(c.PPC_REG_CR6);
        pub const CR7 = from_uc_reg(c.PPC_REG_CR7);
        pub const FPR0 = from_uc_reg(c.PPC_REG_FPR0);
        pub const FPR1 = from_uc_reg(c.PPC_REG_FPR1);
        pub const FPR2 = from_uc_reg(c.PPC_REG_FPR2);
        pub const FPR3 = from_uc_reg(c.PPC_REG_FPR3);
        pub const FPR4 = from_uc_reg(c.PPC_REG_FPR4);
        pub const FPR5 = from_uc_reg(c.PPC_REG_FPR5);
        pub const FPR6 = from_uc_reg(c.PPC_REG_FPR6);
        pub const FPR7 = from_uc_reg(c.PPC_REG_FPR7);
        pub const FPR8 = from_uc_reg(c.PPC_REG_FPR8);
        pub const FPR9 = from_uc_reg(c.PPC_REG_FPR9);
        pub const FPR10 = from_uc_reg(c.PPC_REG_FPR10);
        pub const FPR11 = from_uc_reg(c.PPC_REG_FPR11);
        pub const FPR12 = from_uc_reg(c.PPC_REG_FPR12);
        pub const FPR13 = from_uc_reg(c.PPC_REG_FPR13);
        pub const FPR14 = from_uc_reg(c.PPC_REG_FPR14);
        pub const FPR15 = from_uc_reg(c.PPC_REG_FPR15);
        pub const FPR16 = from_uc_reg(c.PPC_REG_FPR16);
        pub const FPR17 = from_uc_reg(c.PPC_REG_FPR17);
        pub const FPR18 = from_uc_reg(c.PPC_REG_FPR18);
        pub const FPR19 = from_uc_reg(c.PPC_REG_FPR19);
        pub const FPR20 = from_uc_reg(c.PPC_REG_FPR20);
        pub const FPR21 = from_uc_reg(c.PPC_REG_FPR21);
        pub const FPR22 = from_uc_reg(c.PPC_REG_FPR22);
        pub const FPR23 = from_uc_reg(c.PPC_REG_FPR23);
        pub const FPR24 = from_uc_reg(c.PPC_REG_FPR24);
        pub const FPR25 = from_uc_reg(c.PPC_REG_FPR25);
        pub const FPR26 = from_uc_reg(c.PPC_REG_FPR26);
        pub const FPR27 = from_uc_reg(c.PPC_REG_FPR27);
        pub const FPR28 = from_uc_reg(c.PPC_REG_FPR28);
        pub const FPR29 = from_uc_reg(c.PPC_REG_FPR29);
        pub const FPR30 = from_uc_reg(c.PPC_REG_FPR30);
        pub const FPR31 = from_uc_reg(c.PPC_REG_FPR31);
        pub const LR = from_uc_reg(c.PPC_REG_LR);
        pub const XER = from_uc_reg(c.PPC_REG_XER);
        pub const CTR = from_uc_reg(c.PPC_REG_CTR);
        pub const MSR = from_uc_reg(c.PPC_REG_MSR);
        pub const FPSCR = from_uc_reg(c.PPC_REG_FPSCR);
        pub const CR = from_uc_reg(c.PPC_REG_CR);
        pub const ENDING = from_uc_reg(c.PPC_REG_ENDING);
    };

    pub const Ppc32 = Ppc;
    pub const Ppc64 = Ppc;

    pub const Sparc = struct {
        pub const INVALID = from_uc_reg(c.SPARC_REG_INVALID);
        pub const F0 = from_uc_reg(c.SPARC_REG_F0);
        pub const F1 = from_uc_reg(c.SPARC_REG_F1);
        pub const F2 = from_uc_reg(c.SPARC_REG_F2);
        pub const F3 = from_uc_reg(c.SPARC_REG_F3);
        pub const F4 = from_uc_reg(c.SPARC_REG_F4);
        pub const F5 = from_uc_reg(c.SPARC_REG_F5);
        pub const F6 = from_uc_reg(c.SPARC_REG_F6);
        pub const F7 = from_uc_reg(c.SPARC_REG_F7);
        pub const F8 = from_uc_reg(c.SPARC_REG_F8);
        pub const F9 = from_uc_reg(c.SPARC_REG_F9);
        pub const F10 = from_uc_reg(c.SPARC_REG_F10);
        pub const F11 = from_uc_reg(c.SPARC_REG_F11);
        pub const F12 = from_uc_reg(c.SPARC_REG_F12);
        pub const F13 = from_uc_reg(c.SPARC_REG_F13);
        pub const F14 = from_uc_reg(c.SPARC_REG_F14);
        pub const F15 = from_uc_reg(c.SPARC_REG_F15);
        pub const F16 = from_uc_reg(c.SPARC_REG_F16);
        pub const F17 = from_uc_reg(c.SPARC_REG_F17);
        pub const F18 = from_uc_reg(c.SPARC_REG_F18);
        pub const F19 = from_uc_reg(c.SPARC_REG_F19);
        pub const F20 = from_uc_reg(c.SPARC_REG_F20);
        pub const F21 = from_uc_reg(c.SPARC_REG_F21);
        pub const F22 = from_uc_reg(c.SPARC_REG_F22);
        pub const F23 = from_uc_reg(c.SPARC_REG_F23);
        pub const F24 = from_uc_reg(c.SPARC_REG_F24);
        pub const F25 = from_uc_reg(c.SPARC_REG_F25);
        pub const F26 = from_uc_reg(c.SPARC_REG_F26);
        pub const F27 = from_uc_reg(c.SPARC_REG_F27);
        pub const F28 = from_uc_reg(c.SPARC_REG_F28);
        pub const F29 = from_uc_reg(c.SPARC_REG_F29);
        pub const F30 = from_uc_reg(c.SPARC_REG_F30);
        pub const F31 = from_uc_reg(c.SPARC_REG_F31);
        pub const F32 = from_uc_reg(c.SPARC_REG_F32);
        pub const F34 = from_uc_reg(c.SPARC_REG_F34);
        pub const F36 = from_uc_reg(c.SPARC_REG_F36);
        pub const F38 = from_uc_reg(c.SPARC_REG_F38);
        pub const F40 = from_uc_reg(c.SPARC_REG_F40);
        pub const F42 = from_uc_reg(c.SPARC_REG_F42);
        pub const F44 = from_uc_reg(c.SPARC_REG_F44);
        pub const F46 = from_uc_reg(c.SPARC_REG_F46);
        pub const F48 = from_uc_reg(c.SPARC_REG_F48);
        pub const F50 = from_uc_reg(c.SPARC_REG_F50);
        pub const F52 = from_uc_reg(c.SPARC_REG_F52);
        pub const F54 = from_uc_reg(c.SPARC_REG_F54);
        pub const F56 = from_uc_reg(c.SPARC_REG_F56);
        pub const F58 = from_uc_reg(c.SPARC_REG_F58);
        pub const F60 = from_uc_reg(c.SPARC_REG_F60);
        pub const F62 = from_uc_reg(c.SPARC_REG_F62);
        pub const FCC0 = from_uc_reg(c.SPARC_REG_FCC0);
        pub const FCC1 = from_uc_reg(c.SPARC_REG_FCC1);
        pub const FCC2 = from_uc_reg(c.SPARC_REG_FCC2);
        pub const FCC3 = from_uc_reg(c.SPARC_REG_FCC3);
        pub const G0 = from_uc_reg(c.SPARC_REG_G0);
        pub const G1 = from_uc_reg(c.SPARC_REG_G1);
        pub const G2 = from_uc_reg(c.SPARC_REG_G2);
        pub const G3 = from_uc_reg(c.SPARC_REG_G3);
        pub const G4 = from_uc_reg(c.SPARC_REG_G4);
        pub const G5 = from_uc_reg(c.SPARC_REG_G5);
        pub const G6 = from_uc_reg(c.SPARC_REG_G6);
        pub const G7 = from_uc_reg(c.SPARC_REG_G7);
        pub const I0 = from_uc_reg(c.SPARC_REG_I0);
        pub const I1 = from_uc_reg(c.SPARC_REG_I1);
        pub const I2 = from_uc_reg(c.SPARC_REG_I2);
        pub const I3 = from_uc_reg(c.SPARC_REG_I3);
        pub const I4 = from_uc_reg(c.SPARC_REG_I4);
        pub const I5 = from_uc_reg(c.SPARC_REG_I5);
        pub const FP = from_uc_reg(c.SPARC_REG_FP);
        pub const I7 = from_uc_reg(c.SPARC_REG_I7);
        pub const ICC = from_uc_reg(c.SPARC_REG_ICC);
        pub const L0 = from_uc_reg(c.SPARC_REG_L0);
        pub const L1 = from_uc_reg(c.SPARC_REG_L1);
        pub const L2 = from_uc_reg(c.SPARC_REG_L2);
        pub const L3 = from_uc_reg(c.SPARC_REG_L3);
        pub const L4 = from_uc_reg(c.SPARC_REG_L4);
        pub const L5 = from_uc_reg(c.SPARC_REG_L5);
        pub const L6 = from_uc_reg(c.SPARC_REG_L6);
        pub const L7 = from_uc_reg(c.SPARC_REG_L7);
        pub const O0 = from_uc_reg(c.SPARC_REG_O0);
        pub const O1 = from_uc_reg(c.SPARC_REG_O1);
        pub const O2 = from_uc_reg(c.SPARC_REG_O2);
        pub const O3 = from_uc_reg(c.SPARC_REG_O3);
        pub const O4 = from_uc_reg(c.SPARC_REG_O4);
        pub const O5 = from_uc_reg(c.SPARC_REG_O5);
        pub const SP = from_uc_reg(c.SPARC_REG_SP);
        pub const O7 = from_uc_reg(c.SPARC_REG_O7);
        pub const Y = from_uc_reg(c.SPARC_REG_Y);
        pub const XCC = from_uc_reg(c.SPARC_REG_XCC);
        pub const PC = from_uc_reg(c.SPARC_REG_PC);
        pub const ENDING = from_uc_reg(c.SPARC_REG_ENDING);
        pub const O6 = from_uc_reg(c.SPARC_REG_O6);
        pub const I6 = from_uc_reg(c.SPARC_REG_I6);
    };

    pub const Sparc32 = Sparc;
    pub const Sparc64 = Sparc;

    pub const M68k = struct {
        pub const INVALID = from_uc_reg(c.M68K_REG_INVALID);
        pub const A0 = from_uc_reg(c.M68K_REG_A0);
        pub const A1 = from_uc_reg(c.M68K_REG_A1);
        pub const A2 = from_uc_reg(c.M68K_REG_A2);
        pub const A3 = from_uc_reg(c.M68K_REG_A3);
        pub const A4 = from_uc_reg(c.M68K_REG_A4);
        pub const A5 = from_uc_reg(c.M68K_REG_A5);
        pub const A6 = from_uc_reg(c.M68K_REG_A6);
        pub const A7 = from_uc_reg(c.M68K_REG_A7);
        pub const D0 = from_uc_reg(c.M68K_REG_D0);
        pub const D1 = from_uc_reg(c.M68K_REG_D1);
        pub const D2 = from_uc_reg(c.M68K_REG_D2);
        pub const D3 = from_uc_reg(c.M68K_REG_D3);
        pub const D4 = from_uc_reg(c.M68K_REG_D4);
        pub const D5 = from_uc_reg(c.M68K_REG_D5);
        pub const D6 = from_uc_reg(c.M68K_REG_D6);
        pub const D7 = from_uc_reg(c.M68K_REG_D7);
        pub const SR = from_uc_reg(c.M68K_REG_SR);
        pub const PC = from_uc_reg(c.M68K_REG_PC);
        pub const ENDING = from_uc_reg(c.M68K_REG_ENDING);
    };

    pub const Riscv = struct {
        pub const INVALID = from_uc_reg(c.RISCV_REG_INVALID);

        // General purpose registers
        pub const X0 = from_uc_reg(c.RISCV_REG_X0);
        pub const X1 = from_uc_reg(c.RISCV_REG_X1);
        pub const X2 = from_uc_reg(c.RISCV_REG_X2);
        pub const X3 = from_uc_reg(c.RISCV_REG_X3);
        pub const X4 = from_uc_reg(c.RISCV_REG_X4);
        pub const X5 = from_uc_reg(c.RISCV_REG_X5);
        pub const X6 = from_uc_reg(c.RISCV_REG_X6);
        pub const X7 = from_uc_reg(c.RISCV_REG_X7);
        pub const X8 = from_uc_reg(c.RISCV_REG_X8);
        pub const X9 = from_uc_reg(c.RISCV_REG_X9);
        pub const X10 = from_uc_reg(c.RISCV_REG_X10);
        pub const X11 = from_uc_reg(c.RISCV_REG_X11);
        pub const X12 = from_uc_reg(c.RISCV_REG_X12);
        pub const X13 = from_uc_reg(c.RISCV_REG_X13);
        pub const X14 = from_uc_reg(c.RISCV_REG_X14);
        pub const X15 = from_uc_reg(c.RISCV_REG_X15);
        pub const X16 = from_uc_reg(c.RISCV_REG_X16);
        pub const X17 = from_uc_reg(c.RISCV_REG_X17);
        pub const X18 = from_uc_reg(c.RISCV_REG_X18);
        pub const X19 = from_uc_reg(c.RISCV_REG_X19);
        pub const X20 = from_uc_reg(c.RISCV_REG_X20);
        pub const X21 = from_uc_reg(c.RISCV_REG_X21);
        pub const X22 = from_uc_reg(c.RISCV_REG_X22);
        pub const X23 = from_uc_reg(c.RISCV_REG_X23);
        pub const X24 = from_uc_reg(c.RISCV_REG_X24);
        pub const X25 = from_uc_reg(c.RISCV_REG_X25);
        pub const X26 = from_uc_reg(c.RISCV_REG_X26);
        pub const X27 = from_uc_reg(c.RISCV_REG_X27);
        pub const X28 = from_uc_reg(c.RISCV_REG_X28);
        pub const X29 = from_uc_reg(c.RISCV_REG_X29);
        pub const X30 = from_uc_reg(c.RISCV_REG_X30);
        pub const X31 = from_uc_reg(c.RISCV_REG_X31);

        // RISCV CSR
        pub const USTATUS = from_uc_reg(c.RISCV_REG_USTATUS);
        pub const UIE = from_uc_reg(c.RISCV_REG_UIE);
        pub const UTVEC = from_uc_reg(c.RISCV_REG_UTVEC);
        pub const USCRATCH = from_uc_reg(c.RISCV_REG_USCRATCH);
        pub const UEPC = from_uc_reg(c.RISCV_REG_UEPC);
        pub const UCAUSE = from_uc_reg(c.RISCV_REG_UCAUSE);
        pub const UTVAL = from_uc_reg(c.RISCV_REG_UTVAL);
        pub const UIP = from_uc_reg(c.RISCV_REG_UIP);
        pub const FFLAGS = from_uc_reg(c.RISCV_REG_FFLAGS);
        pub const FRM = from_uc_reg(c.RISCV_REG_FRM);
        pub const FCSR = from_uc_reg(c.RISCV_REG_FCSR);
        pub const CYCLE = from_uc_reg(c.RISCV_REG_CYCLE);
        pub const TIME = from_uc_reg(c.RISCV_REG_TIME);
        pub const INSTRET = from_uc_reg(c.RISCV_REG_INSTRET);
        pub const HPMCOUNTER3 = from_uc_reg(c.RISCV_REG_HPMCOUNTER3);
        pub const HPMCOUNTER4 = from_uc_reg(c.RISCV_REG_HPMCOUNTER4);
        pub const HPMCOUNTER5 = from_uc_reg(c.RISCV_REG_HPMCOUNTER5);
        pub const HPMCOUNTER6 = from_uc_reg(c.RISCV_REG_HPMCOUNTER6);
        pub const HPMCOUNTER7 = from_uc_reg(c.RISCV_REG_HPMCOUNTER7);
        pub const HPMCOUNTER8 = from_uc_reg(c.RISCV_REG_HPMCOUNTER8);
        pub const HPMCOUNTER9 = from_uc_reg(c.RISCV_REG_HPMCOUNTER9);
        pub const HPMCOUNTER10 = from_uc_reg(c.RISCV_REG_HPMCOUNTER10);
        pub const HPMCOUNTER11 = from_uc_reg(c.RISCV_REG_HPMCOUNTER11);
        pub const HPMCOUNTER12 = from_uc_reg(c.RISCV_REG_HPMCOUNTER12);
        pub const HPMCOUNTER13 = from_uc_reg(c.RISCV_REG_HPMCOUNTER13);
        pub const HPMCOUNTER14 = from_uc_reg(c.RISCV_REG_HPMCOUNTER14);
        pub const HPMCOUNTER15 = from_uc_reg(c.RISCV_REG_HPMCOUNTER15);
        pub const HPMCOUNTER16 = from_uc_reg(c.RISCV_REG_HPMCOUNTER16);
        pub const HPMCOUNTER17 = from_uc_reg(c.RISCV_REG_HPMCOUNTER17);
        pub const HPMCOUNTER18 = from_uc_reg(c.RISCV_REG_HPMCOUNTER18);
        pub const HPMCOUNTER19 = from_uc_reg(c.RISCV_REG_HPMCOUNTER19);
        pub const HPMCOUNTER20 = from_uc_reg(c.RISCV_REG_HPMCOUNTER20);
        pub const HPMCOUNTER21 = from_uc_reg(c.RISCV_REG_HPMCOUNTER21);
        pub const HPMCOUNTER22 = from_uc_reg(c.RISCV_REG_HPMCOUNTER22);
        pub const HPMCOUNTER23 = from_uc_reg(c.RISCV_REG_HPMCOUNTER23);
        pub const HPMCOUNTER24 = from_uc_reg(c.RISCV_REG_HPMCOUNTER24);
        pub const HPMCOUNTER25 = from_uc_reg(c.RISCV_REG_HPMCOUNTER25);
        pub const HPMCOUNTER26 = from_uc_reg(c.RISCV_REG_HPMCOUNTER26);
        pub const HPMCOUNTER27 = from_uc_reg(c.RISCV_REG_HPMCOUNTER27);
        pub const HPMCOUNTER28 = from_uc_reg(c.RISCV_REG_HPMCOUNTER28);
        pub const HPMCOUNTER29 = from_uc_reg(c.RISCV_REG_HPMCOUNTER29);
        pub const HPMCOUNTER30 = from_uc_reg(c.RISCV_REG_HPMCOUNTER30);
        pub const HPMCOUNTER31 = from_uc_reg(c.RISCV_REG_HPMCOUNTER31);
        pub const CYCLEH = from_uc_reg(c.RISCV_REG_CYCLEH);
        pub const TIMEH = from_uc_reg(c.RISCV_REG_TIMEH);
        pub const INSTRETH = from_uc_reg(c.RISCV_REG_INSTRETH);
        pub const HPMCOUNTER3H = from_uc_reg(c.RISCV_REG_HPMCOUNTER3H);
        pub const HPMCOUNTER4H = from_uc_reg(c.RISCV_REG_HPMCOUNTER4H);
        pub const HPMCOUNTER5H = from_uc_reg(c.RISCV_REG_HPMCOUNTER5H);
        pub const HPMCOUNTER6H = from_uc_reg(c.RISCV_REG_HPMCOUNTER6H);
        pub const HPMCOUNTER7H = from_uc_reg(c.RISCV_REG_HPMCOUNTER7H);
        pub const HPMCOUNTER8H = from_uc_reg(c.RISCV_REG_HPMCOUNTER8H);
        pub const HPMCOUNTER9H = from_uc_reg(c.RISCV_REG_HPMCOUNTER9H);
        pub const HPMCOUNTER10H = from_uc_reg(c.RISCV_REG_HPMCOUNTER10H);
        pub const HPMCOUNTER11H = from_uc_reg(c.RISCV_REG_HPMCOUNTER11H);
        pub const HPMCOUNTER12H = from_uc_reg(c.RISCV_REG_HPMCOUNTER12H);
        pub const HPMCOUNTER13H = from_uc_reg(c.RISCV_REG_HPMCOUNTER13H);
        pub const HPMCOUNTER14H = from_uc_reg(c.RISCV_REG_HPMCOUNTER14H);
        pub const HPMCOUNTER15H = from_uc_reg(c.RISCV_REG_HPMCOUNTER15H);
        pub const HPMCOUNTER16H = from_uc_reg(c.RISCV_REG_HPMCOUNTER16H);
        pub const HPMCOUNTER17H = from_uc_reg(c.RISCV_REG_HPMCOUNTER17H);
        pub const HPMCOUNTER18H = from_uc_reg(c.RISCV_REG_HPMCOUNTER18H);
        pub const HPMCOUNTER19H = from_uc_reg(c.RISCV_REG_HPMCOUNTER19H);
        pub const HPMCOUNTER20H = from_uc_reg(c.RISCV_REG_HPMCOUNTER20H);
        pub const HPMCOUNTER21H = from_uc_reg(c.RISCV_REG_HPMCOUNTER21H);
        pub const HPMCOUNTER22H = from_uc_reg(c.RISCV_REG_HPMCOUNTER22H);
        pub const HPMCOUNTER23H = from_uc_reg(c.RISCV_REG_HPMCOUNTER23H);
        pub const HPMCOUNTER24H = from_uc_reg(c.RISCV_REG_HPMCOUNTER24H);
        pub const HPMCOUNTER25H = from_uc_reg(c.RISCV_REG_HPMCOUNTER25H);
        pub const HPMCOUNTER26H = from_uc_reg(c.RISCV_REG_HPMCOUNTER26H);
        pub const HPMCOUNTER27H = from_uc_reg(c.RISCV_REG_HPMCOUNTER27H);
        pub const HPMCOUNTER28H = from_uc_reg(c.RISCV_REG_HPMCOUNTER28H);
        pub const HPMCOUNTER29H = from_uc_reg(c.RISCV_REG_HPMCOUNTER29H);
        pub const HPMCOUNTER30H = from_uc_reg(c.RISCV_REG_HPMCOUNTER30H);
        pub const HPMCOUNTER31H = from_uc_reg(c.RISCV_REG_HPMCOUNTER31H);
        pub const MCYCLE = from_uc_reg(c.RISCV_REG_MCYCLE);
        pub const MINSTRET = from_uc_reg(c.RISCV_REG_MINSTRET);
        pub const MCYCLEH = from_uc_reg(c.RISCV_REG_MCYCLEH);
        pub const MINSTRETH = from_uc_reg(c.RISCV_REG_MINSTRETH);
        pub const MVENDORID = from_uc_reg(c.RISCV_REG_MVENDORID);
        pub const MARCHID = from_uc_reg(c.RISCV_REG_MARCHID);
        pub const MIMPID = from_uc_reg(c.RISCV_REG_MIMPID);
        pub const MHARTID = from_uc_reg(c.RISCV_REG_MHARTID);
        pub const MSTATUS = from_uc_reg(c.RISCV_REG_MSTATUS);
        pub const MISA = from_uc_reg(c.RISCV_REG_MISA);
        pub const MEDELEG = from_uc_reg(c.RISCV_REG_MEDELEG);
        pub const MIDELEG = from_uc_reg(c.RISCV_REG_MIDELEG);
        pub const MIE = from_uc_reg(c.RISCV_REG_MIE);
        pub const MTVEC = from_uc_reg(c.RISCV_REG_MTVEC);
        pub const MCOUNTEREN = from_uc_reg(c.RISCV_REG_MCOUNTEREN);
        pub const MSTATUSH = from_uc_reg(c.RISCV_REG_MSTATUSH);
        pub const MUCOUNTEREN = from_uc_reg(c.RISCV_REG_MUCOUNTEREN);
        pub const MSCOUNTEREN = from_uc_reg(c.RISCV_REG_MSCOUNTEREN);
        pub const MHCOUNTEREN = from_uc_reg(c.RISCV_REG_MHCOUNTEREN);
        pub const MSCRATCH = from_uc_reg(c.RISCV_REG_MSCRATCH);
        pub const MEPC = from_uc_reg(c.RISCV_REG_MEPC);
        pub const MCAUSE = from_uc_reg(c.RISCV_REG_MCAUSE);
        pub const MTVAL = from_uc_reg(c.RISCV_REG_MTVAL);
        pub const MIP = from_uc_reg(c.RISCV_REG_MIP);
        pub const MBADADDR = from_uc_reg(c.RISCV_REG_MBADADDR);
        pub const SSTATUS = from_uc_reg(c.RISCV_REG_SSTATUS);
        pub const SEDELEG = from_uc_reg(c.RISCV_REG_SEDELEG);
        pub const SIDELEG = from_uc_reg(c.RISCV_REG_SIDELEG);
        pub const SIE = from_uc_reg(c.RISCV_REG_SIE);
        pub const STVEC = from_uc_reg(c.RISCV_REG_STVEC);
        pub const SCOUNTEREN = from_uc_reg(c.RISCV_REG_SCOUNTEREN);
        pub const SSCRATCH = from_uc_reg(c.RISCV_REG_SSCRATCH);
        pub const SEPC = from_uc_reg(c.RISCV_REG_SEPC);
        pub const SCAUSE = from_uc_reg(c.RISCV_REG_SCAUSE);
        pub const STVAL = from_uc_reg(c.RISCV_REG_STVAL);
        pub const SIP = from_uc_reg(c.RISCV_REG_SIP);
        pub const SBADADDR = from_uc_reg(c.RISCV_REG_SBADADDR);
        pub const SPTBR = from_uc_reg(c.RISCV_REG_SPTBR);
        pub const SATP = from_uc_reg(c.RISCV_REG_SATP);
        pub const HSTATUS = from_uc_reg(c.RISCV_REG_HSTATUS);
        pub const HEDELEG = from_uc_reg(c.RISCV_REG_HEDELEG);
        pub const HIDELEG = from_uc_reg(c.RISCV_REG_HIDELEG);
        pub const HIE = from_uc_reg(c.RISCV_REG_HIE);
        pub const HCOUNTEREN = from_uc_reg(c.RISCV_REG_HCOUNTEREN);
        pub const HTVAL = from_uc_reg(c.RISCV_REG_HTVAL);
        pub const HIP = from_uc_reg(c.RISCV_REG_HIP);
        pub const HTINST = from_uc_reg(c.RISCV_REG_HTINST);
        pub const HGATP = from_uc_reg(c.RISCV_REG_HGATP);
        pub const HTIMEDELTA = from_uc_reg(c.RISCV_REG_HTIMEDELTA);
        pub const HTIMEDELTAH = from_uc_reg(c.RISCV_REG_HTIMEDELTAH);

        // Floating-point registers
        pub const F0 = from_uc_reg(c.RISCV_REG_F0);
        pub const F1 = from_uc_reg(c.RISCV_REG_F1);
        pub const F2 = from_uc_reg(c.RISCV_REG_F2);
        pub const F3 = from_uc_reg(c.RISCV_REG_F3);
        pub const F4 = from_uc_reg(c.RISCV_REG_F4);
        pub const F5 = from_uc_reg(c.RISCV_REG_F5);
        pub const F6 = from_uc_reg(c.RISCV_REG_F6);
        pub const F7 = from_uc_reg(c.RISCV_REG_F7);
        pub const F8 = from_uc_reg(c.RISCV_REG_F8);
        pub const F9 = from_uc_reg(c.RISCV_REG_F9);
        pub const F10 = from_uc_reg(c.RISCV_REG_F10);
        pub const F11 = from_uc_reg(c.RISCV_REG_F11);
        pub const F12 = from_uc_reg(c.RISCV_REG_F12);
        pub const F13 = from_uc_reg(c.RISCV_REG_F13);
        pub const F14 = from_uc_reg(c.RISCV_REG_F14);
        pub const F15 = from_uc_reg(c.RISCV_REG_F15);
        pub const F16 = from_uc_reg(c.RISCV_REG_F16);
        pub const F17 = from_uc_reg(c.RISCV_REG_F17);
        pub const F18 = from_uc_reg(c.RISCV_REG_F18);
        pub const F19 = from_uc_reg(c.RISCV_REG_F19);
        pub const F20 = from_uc_reg(c.RISCV_REG_F20);
        pub const F21 = from_uc_reg(c.RISCV_REG_F21);
        pub const F22 = from_uc_reg(c.RISCV_REG_F22);
        pub const F23 = from_uc_reg(c.RISCV_REG_F23);
        pub const F24 = from_uc_reg(c.RISCV_REG_F24);
        pub const F25 = from_uc_reg(c.RISCV_REG_F25);
        pub const F26 = from_uc_reg(c.RISCV_REG_F26);
        pub const F27 = from_uc_reg(c.RISCV_REG_F27);
        pub const F28 = from_uc_reg(c.RISCV_REG_F28);
        pub const F29 = from_uc_reg(c.RISCV_REG_F29);
        pub const F30 = from_uc_reg(c.RISCV_REG_F30);
        pub const F31 = from_uc_reg(c.RISCV_REG_F31);
        pub const PC = from_uc_reg(c.RISCV_REG_PC);
        pub const ENDING = from_uc_reg(c.RISCV_REG_ENDING);

        // Alias registers
        pub const ZERO = from_uc_reg(c.RISCV_REG_ZERO);
        pub const RA = from_uc_reg(c.RISCV_REG_RA);
        pub const SP = from_uc_reg(c.RISCV_REG_SP);
        pub const GP = from_uc_reg(c.RISCV_REG_GP);
        pub const TP = from_uc_reg(c.RISCV_REG_TP);
        pub const T0 = from_uc_reg(c.RISCV_REG_T0);
        pub const T1 = from_uc_reg(c.RISCV_REG_T1);
        pub const T2 = from_uc_reg(c.RISCV_REG_T2);
        pub const S0 = from_uc_reg(c.RISCV_REG_S0);
        pub const FP = from_uc_reg(c.RISCV_REG_FP);
        pub const S1 = from_uc_reg(c.RISCV_REG_S1);
        pub const A0 = from_uc_reg(c.RISCV_REG_A0);
        pub const A1 = from_uc_reg(c.RISCV_REG_A1);
        pub const A2 = from_uc_reg(c.RISCV_REG_A2);
        pub const A3 = from_uc_reg(c.RISCV_REG_A3);
        pub const A4 = from_uc_reg(c.RISCV_REG_A4);
        pub const A5 = from_uc_reg(c.RISCV_REG_A5);
        pub const A6 = from_uc_reg(c.RISCV_REG_A6);
        pub const A7 = from_uc_reg(c.RISCV_REG_A7);
        pub const S2 = from_uc_reg(c.RISCV_REG_S2);
        pub const S3 = from_uc_reg(c.RISCV_REG_S3);
        pub const S4 = from_uc_reg(c.RISCV_REG_S4);
        pub const S5 = from_uc_reg(c.RISCV_REG_S5);
        pub const S6 = from_uc_reg(c.RISCV_REG_S6);
        pub const S7 = from_uc_reg(c.RISCV_REG_S7);
        pub const S8 = from_uc_reg(c.RISCV_REG_S8);
        pub const S9 = from_uc_reg(c.RISCV_REG_S9);
        pub const S10 = from_uc_reg(c.RISCV_REG_S10);
        pub const S11 = from_uc_reg(c.RISCV_REG_S11);
        pub const T3 = from_uc_reg(c.RISCV_REG_T3);
        pub const T4 = from_uc_reg(c.RISCV_REG_T4);
        pub const T5 = from_uc_reg(c.RISCV_REG_T5);
        pub const T6 = from_uc_reg(c.RISCV_REG_T6);
        pub const FT0 = from_uc_reg(c.RISCV_REG_FT0);
        pub const FT1 = from_uc_reg(c.RISCV_REG_FT1);
        pub const FT2 = from_uc_reg(c.RISCV_REG_FT2);
        pub const FT3 = from_uc_reg(c.RISCV_REG_FT3);
        pub const FT4 = from_uc_reg(c.RISCV_REG_FT4);
        pub const FT5 = from_uc_reg(c.RISCV_REG_FT5);
        pub const FT6 = from_uc_reg(c.RISCV_REG_FT6);
        pub const FT7 = from_uc_reg(c.RISCV_REG_FT7);
        pub const FS0 = from_uc_reg(c.RISCV_REG_FS0);
        pub const FS1 = from_uc_reg(c.RISCV_REG_FS1);
        pub const FA0 = from_uc_reg(c.RISCV_REG_FA0);
        pub const FA1 = from_uc_reg(c.RISCV_REG_FA1);
        pub const FA2 = from_uc_reg(c.RISCV_REG_FA2);
        pub const FA3 = from_uc_reg(c.RISCV_REG_FA3);
        pub const FA4 = from_uc_reg(c.RISCV_REG_FA4);
        pub const FA5 = from_uc_reg(c.RISCV_REG_FA5);
        pub const FA6 = from_uc_reg(c.RISCV_REG_FA6);
        pub const FA7 = from_uc_reg(c.RISCV_REG_FA7);
        pub const FS2 = from_uc_reg(c.RISCV_REG_FS2);
        pub const FS3 = from_uc_reg(c.RISCV_REG_FS3);
        pub const FS4 = from_uc_reg(c.RISCV_REG_FS4);
        pub const FS5 = from_uc_reg(c.RISCV_REG_FS5);
        pub const FS6 = from_uc_reg(c.RISCV_REG_FS6);
        pub const FS7 = from_uc_reg(c.RISCV_REG_FS7);
        pub const FS8 = from_uc_reg(c.RISCV_REG_FS8);
        pub const FS9 = from_uc_reg(c.RISCV_REG_FS9);
        pub const FS10 = from_uc_reg(c.RISCV_REG_FS10);
        pub const FS11 = from_uc_reg(c.RISCV_REG_FS11);
        pub const FT8 = from_uc_reg(c.RISCV_REG_FT8);
        pub const FT9 = from_uc_reg(c.RISCV_REG_FT9);
        pub const FT10 = from_uc_reg(c.RISCV_REG_FT10);
        pub const FT11 = from_uc_reg(c.RISCV_REG_FT11);
    };

    pub const Riscv32 = Riscv;
    pub const Riscv64 = Riscv;

    pub const S390x = struct {
        pub const INVALID = from_uc_reg(c.S390X_REG_INVALID);

        // General purpose registers
        pub const R0 = from_uc_reg(c.S390X_REG_R0);
        pub const R1 = from_uc_reg(c.S390X_REG_R1);
        pub const R2 = from_uc_reg(c.S390X_REG_R2);
        pub const R3 = from_uc_reg(c.S390X_REG_R3);
        pub const R4 = from_uc_reg(c.S390X_REG_R4);
        pub const R5 = from_uc_reg(c.S390X_REG_R5);
        pub const R6 = from_uc_reg(c.S390X_REG_R6);
        pub const R7 = from_uc_reg(c.S390X_REG_R7);
        pub const R8 = from_uc_reg(c.S390X_REG_R8);
        pub const R9 = from_uc_reg(c.S390X_REG_R9);
        pub const R10 = from_uc_reg(c.S390X_REG_R10);
        pub const R11 = from_uc_reg(c.S390X_REG_R11);
        pub const R12 = from_uc_reg(c.S390X_REG_R12);
        pub const R13 = from_uc_reg(c.S390X_REG_R13);
        pub const R14 = from_uc_reg(c.S390X_REG_R14);
        pub const R15 = from_uc_reg(c.S390X_REG_R15);

        // Floating point registers
        pub const F0 = from_uc_reg(c.S390X_REG_F0);
        pub const F1 = from_uc_reg(c.S390X_REG_F1);
        pub const F2 = from_uc_reg(c.S390X_REG_F2);
        pub const F3 = from_uc_reg(c.S390X_REG_F3);
        pub const F4 = from_uc_reg(c.S390X_REG_F4);
        pub const F5 = from_uc_reg(c.S390X_REG_F5);
        pub const F6 = from_uc_reg(c.S390X_REG_F6);
        pub const F7 = from_uc_reg(c.S390X_REG_F7);
        pub const F8 = from_uc_reg(c.S390X_REG_F8);
        pub const F9 = from_uc_reg(c.S390X_REG_F9);
        pub const F10 = from_uc_reg(c.S390X_REG_F10);
        pub const F11 = from_uc_reg(c.S390X_REG_F11);
        pub const F12 = from_uc_reg(c.S390X_REG_F12);
        pub const F13 = from_uc_reg(c.S390X_REG_F13);
        pub const F14 = from_uc_reg(c.S390X_REG_F14);
        pub const F15 = from_uc_reg(c.S390X_REG_F15);
        pub const F16 = from_uc_reg(c.S390X_REG_F16);
        pub const F17 = from_uc_reg(c.S390X_REG_F17);
        pub const F18 = from_uc_reg(c.S390X_REG_F18);
        pub const F19 = from_uc_reg(c.S390X_REG_F19);
        pub const F20 = from_uc_reg(c.S390X_REG_F20);
        pub const F21 = from_uc_reg(c.S390X_REG_F21);
        pub const F22 = from_uc_reg(c.S390X_REG_F22);
        pub const F23 = from_uc_reg(c.S390X_REG_F23);
        pub const F24 = from_uc_reg(c.S390X_REG_F24);
        pub const F25 = from_uc_reg(c.S390X_REG_F25);
        pub const F26 = from_uc_reg(c.S390X_REG_F26);
        pub const F27 = from_uc_reg(c.S390X_REG_F27);
        pub const F28 = from_uc_reg(c.S390X_REG_F28);
        pub const F29 = from_uc_reg(c.S390X_REG_F29);
        pub const F30 = from_uc_reg(c.S390X_REG_F30);
        pub const F31 = from_uc_reg(c.S390X_REG_F31);

        // Access registers
        pub const A0 = from_uc_reg(c.S390X_REG_A0);
        pub const A1 = from_uc_reg(c.S390X_REG_A1);
        pub const A2 = from_uc_reg(c.S390X_REG_A2);
        pub const A3 = from_uc_reg(c.S390X_REG_A3);
        pub const A4 = from_uc_reg(c.S390X_REG_A4);
        pub const A5 = from_uc_reg(c.S390X_REG_A5);
        pub const A6 = from_uc_reg(c.S390X_REG_A6);
        pub const A7 = from_uc_reg(c.S390X_REG_A7);
        pub const A8 = from_uc_reg(c.S390X_REG_A8);
        pub const A9 = from_uc_reg(c.S390X_REG_A9);
        pub const A10 = from_uc_reg(c.S390X_REG_A10);
        pub const A11 = from_uc_reg(c.S390X_REG_A11);
        pub const A12 = from_uc_reg(c.S390X_REG_A12);
        pub const A13 = from_uc_reg(c.S390X_REG_A13);
        pub const A14 = from_uc_reg(c.S390X_REG_A14);
        pub const A15 = from_uc_reg(c.S390X_REG_A15);
        pub const PC = from_uc_reg(c.S390X_REG_PC);
        pub const PSWM = from_uc_reg(c.S390X_REG_PSWM);
        pub const ENDING = from_uc_reg(c.S390X_REG_ENDING);
    };

    pub const Tricore = struct {
        pub const INVALID = from_uc_reg(c.TRICORE_REG_INVALID);
        pub const A0 = from_uc_reg(c.TRICORE_REG_A0);
        pub const A1 = from_uc_reg(c.TRICORE_REG_A1);
        pub const A2 = from_uc_reg(c.TRICORE_REG_A2);
        pub const A3 = from_uc_reg(c.TRICORE_REG_A3);
        pub const A4 = from_uc_reg(c.TRICORE_REG_A4);
        pub const A5 = from_uc_reg(c.TRICORE_REG_A5);
        pub const A6 = from_uc_reg(c.TRICORE_REG_A6);
        pub const A7 = from_uc_reg(c.TRICORE_REG_A7);
        pub const A8 = from_uc_reg(c.TRICORE_REG_A8);
        pub const A9 = from_uc_reg(c.TRICORE_REG_A9);
        pub const A10 = from_uc_reg(c.TRICORE_REG_A10);
        pub const A11 = from_uc_reg(c.TRICORE_REG_A11);
        pub const A12 = from_uc_reg(c.TRICORE_REG_A12);
        pub const A13 = from_uc_reg(c.TRICORE_REG_A13);
        pub const A14 = from_uc_reg(c.TRICORE_REG_A14);
        pub const A15 = from_uc_reg(c.TRICORE_REG_A15);
        pub const D0 = from_uc_reg(c.TRICORE_REG_D0);
        pub const D1 = from_uc_reg(c.TRICORE_REG_D1);
        pub const D2 = from_uc_reg(c.TRICORE_REG_D2);
        pub const D3 = from_uc_reg(c.TRICORE_REG_D3);
        pub const D4 = from_uc_reg(c.TRICORE_REG_D4);
        pub const D5 = from_uc_reg(c.TRICORE_REG_D5);
        pub const D6 = from_uc_reg(c.TRICORE_REG_D6);
        pub const D7 = from_uc_reg(c.TRICORE_REG_D7);
        pub const D8 = from_uc_reg(c.TRICORE_REG_D8);
        pub const D9 = from_uc_reg(c.TRICORE_REG_D9);
        pub const D10 = from_uc_reg(c.TRICORE_REG_D10);
        pub const D11 = from_uc_reg(c.TRICORE_REG_D11);
        pub const D12 = from_uc_reg(c.TRICORE_REG_D12);
        pub const D13 = from_uc_reg(c.TRICORE_REG_D13);
        pub const D14 = from_uc_reg(c.TRICORE_REG_D14);
        pub const D15 = from_uc_reg(c.TRICORE_REG_D15);
        pub const PCXI = from_uc_reg(c.TRICORE_REG_PCXI);
        pub const PSW = from_uc_reg(c.TRICORE_REG_PSW);
        pub const PSW_USB_C = from_uc_reg(c.TRICORE_REG_PSW_USB_C);
        pub const PSW_USB_V = from_uc_reg(c.TRICORE_REG_PSW_USB_V);
        pub const PSW_USB_SV = from_uc_reg(c.TRICORE_REG_PSW_USB_SV);
        pub const PSW_USB_AV = from_uc_reg(c.TRICORE_REG_PSW_USB_AV);
        pub const PSW_USB_SAV = from_uc_reg(c.TRICORE_REG_PSW_USB_SAV);
        pub const PC = from_uc_reg(c.TRICORE_REG_PC);
        pub const SYSCON = from_uc_reg(c.TRICORE_REG_SYSCON);
        pub const CPU_ID = from_uc_reg(c.TRICORE_REG_CPU_ID);
        pub const BIV = from_uc_reg(c.TRICORE_REG_BIV);
        pub const BTV = from_uc_reg(c.TRICORE_REG_BTV);
        pub const ISP = from_uc_reg(c.TRICORE_REG_ISP);
        pub const ICR = from_uc_reg(c.TRICORE_REG_ICR);
        pub const FCX = from_uc_reg(c.TRICORE_REG_FCX);
        pub const LCX = from_uc_reg(c.TRICORE_REG_LCX);
        pub const COMPAT = from_uc_reg(c.TRICORE_REG_COMPAT);
        pub const DPR0_U = from_uc_reg(c.TRICORE_REG_DPR0_U);
        pub const DPR1_U = from_uc_reg(c.TRICORE_REG_DPR1_U);
        pub const DPR2_U = from_uc_reg(c.TRICORE_REG_DPR2_U);
        pub const DPR3_U = from_uc_reg(c.TRICORE_REG_DPR3_U);
        pub const DPR0_L = from_uc_reg(c.TRICORE_REG_DPR0_L);
        pub const DPR1_L = from_uc_reg(c.TRICORE_REG_DPR1_L);
        pub const DPR2_L = from_uc_reg(c.TRICORE_REG_DPR2_L);
        pub const DPR3_L = from_uc_reg(c.TRICORE_REG_DPR3_L);
        pub const CPR0_U = from_uc_reg(c.TRICORE_REG_CPR0_U);
        pub const CPR1_U = from_uc_reg(c.TRICORE_REG_CPR1_U);
        pub const CPR2_U = from_uc_reg(c.TRICORE_REG_CPR2_U);
        pub const CPR3_U = from_uc_reg(c.TRICORE_REG_CPR3_U);
        pub const CPR0_L = from_uc_reg(c.TRICORE_REG_CPR0_L);
        pub const CPR1_L = from_uc_reg(c.TRICORE_REG_CPR1_L);
        pub const CPR2_L = from_uc_reg(c.TRICORE_REG_CPR2_L);
        pub const CPR3_L = from_uc_reg(c.TRICORE_REG_CPR3_L);
        pub const DPM0 = from_uc_reg(c.TRICORE_REG_DPM0);
        pub const DPM1 = from_uc_reg(c.TRICORE_REG_DPM1);
        pub const DPM2 = from_uc_reg(c.TRICORE_REG_DPM2);
        pub const DPM3 = from_uc_reg(c.TRICORE_REG_DPM3);
        pub const CPM0 = from_uc_reg(c.TRICORE_REG_CPM0);
        pub const CPM1 = from_uc_reg(c.TRICORE_REG_CPM1);
        pub const CPM2 = from_uc_reg(c.TRICORE_REG_CPM2);
        pub const CPM3 = from_uc_reg(c.TRICORE_REG_CPM3);
        pub const MMU_CON = from_uc_reg(c.TRICORE_REG_MMU_CON);
        pub const MMU_ASI = from_uc_reg(c.TRICORE_REG_MMU_ASI);
        pub const MMU_TVA = from_uc_reg(c.TRICORE_REG_MMU_TVA);
        pub const MMU_TPA = from_uc_reg(c.TRICORE_REG_MMU_TPA);
        pub const MMU_TPX = from_uc_reg(c.TRICORE_REG_MMU_TPX);
        pub const MMU_TFA = from_uc_reg(c.TRICORE_REG_MMU_TFA);
        pub const BMACON = from_uc_reg(c.TRICORE_REG_BMACON);
        pub const SMACON = from_uc_reg(c.TRICORE_REG_SMACON);
        pub const DIEAR = from_uc_reg(c.TRICORE_REG_DIEAR);
        pub const DIETR = from_uc_reg(c.TRICORE_REG_DIETR);
        pub const CCDIER = from_uc_reg(c.TRICORE_REG_CCDIER);
        pub const MIECON = from_uc_reg(c.TRICORE_REG_MIECON);
        pub const PIEAR = from_uc_reg(c.TRICORE_REG_PIEAR);
        pub const PIETR = from_uc_reg(c.TRICORE_REG_PIETR);
        pub const CCPIER = from_uc_reg(c.TRICORE_REG_CCPIER);
        pub const DBGSR = from_uc_reg(c.TRICORE_REG_DBGSR);
        pub const EXEVT = from_uc_reg(c.TRICORE_REG_EXEVT);
        pub const CREVT = from_uc_reg(c.TRICORE_REG_CREVT);
        pub const SWEVT = from_uc_reg(c.TRICORE_REG_SWEVT);
        pub const TR0EVT = from_uc_reg(c.TRICORE_REG_TR0EVT);
        pub const TR1EVT = from_uc_reg(c.TRICORE_REG_TR1EVT);
        pub const DMS = from_uc_reg(c.TRICORE_REG_DMS);
        pub const DCX = from_uc_reg(c.TRICORE_REG_DCX);
        pub const DBGTCR = from_uc_reg(c.TRICORE_REG_DBGTCR);
        pub const CCTRL = from_uc_reg(c.TRICORE_REG_CCTRL);
        pub const CCNT = from_uc_reg(c.TRICORE_REG_CCNT);
        pub const ICNT = from_uc_reg(c.TRICORE_REG_ICNT);
        pub const M1CNT = from_uc_reg(c.TRICORE_REG_M1CNT);
        pub const M2CNT = from_uc_reg(c.TRICORE_REG_M2CNT);
        pub const M3CNT = from_uc_reg(c.TRICORE_REG_M3CNT);
        pub const ENDING = from_uc_reg(c.TRICORE_REG_ENDING);
        pub const GA0 = from_uc_reg(c.TRICORE_REG_GA0);
        pub const GA1 = from_uc_reg(c.TRICORE_REG_GA1);
        pub const GA8 = from_uc_reg(c.TRICORE_REG_GA8);
        pub const GA9 = from_uc_reg(c.TRICORE_REG_GA9);
        pub const SP = from_uc_reg(c.TRICORE_REG_SP);
        pub const LR = from_uc_reg(c.TRICORE_REG_LR);
        pub const IA = from_uc_reg(c.TRICORE_REG_IA);
        pub const ID = from_uc_reg(c.TRICORE_REG_ID);
    };

    fn from_uc_reg(reg: c_int) Reg {
        return @enumFromInt(reg);
    }

    _,
};

pub const Unicorn = struct {
    uc: ?*c.uc_engine,

    pub fn open(arch: Arch, mode: Mode) Error!Unicorn {
        var uc: ?*c.uc_engine = null;

        try zig_error_from_uc_err(c.uc_open(@intFromEnum(arch), @intFromEnum(mode), &uc));

        return Unicorn{
            .uc = uc,
        };
    }

    pub fn close(self: Unicorn) Error!void {
        try zig_error_from_uc_err(c.uc_close(self.uc));
    }

    pub fn arch_supported(arch: Arch) bool {
        return c.uc_arch_supported(arch);
    }

    pub const QueryType = enum(c.uc_query_type) {
        Mode,
        PageSize,
        Arch,
        Timeout,

        pub fn to_type(self: QueryType) type {
            return switch (self) {
                .Mode => Mode,
                .PageSize => usize,
                .Arch => Arch,
                .Timeout => usize,
            };
        }
    };

    pub fn query(self: Unicorn, comptime query_: QueryType) Error!query_.to_type() {
        var result: usize = undefined;

        try zig_error_from_uc_err(c.uc_query(self.uc, @intFromEnum(query_), &result));

        return switch (query_) {
            .Mode, .Arch => @enumFromInt(result),
            .PageSize, .Timeout => result,
        };
    }

    pub fn errno(self: Unicorn) Error {
        return zig_error_from_uc_err(c.uc_errno(self.uc));
    }

    pub fn reg_write(self: Unicorn, comptime T: type, register: Reg, value: T) Error!void {
        try zig_error_from_uc_err(c.uc_reg_write(self.uc, @intFromEnum(register), &value));
    }

    pub fn reg_read(self: Unicorn, comptime T: type, register: Reg) Error!T {
        var value: T = undefined;
        try zig_error_from_uc_err(c.uc_reg_read(self.uc, @intFromEnum(register), &value));
        return value;
    }

    // TODO: reg_write_batch
    // TODO: reg_read_batch

    pub fn mem_write(self: Unicorn, address: u64, data: []const u8) Error!void {
        try zig_error_from_uc_err(c.uc_mem_write(self.uc, address, data.ptr, data.len));
    }

    pub fn mem_read(self: Unicorn, address: u64, data: []u8) Error!void {
        try zig_error_from_uc_err(c.uc_mem_read(self.uc, address, data.ptr, data.len));
    }

    pub fn emu_start(self: Unicorn, begin: u64, until: u64, timeout: u64, count: usize) !void {
        try zig_error_from_uc_err(c.uc_emu_start(self.uc, begin, until, timeout, count));
    }

    pub fn emu_stop(self: Unicorn) !void {
        try zig_error_from_uc_err(c.uc_emu_stop(self.uc));
    }

    pub const HookType = enum(c_int) {
        Intr = c.UC_HOOK_INTR,
        Insn = c.UC_HOOK_INSN,
        Code = c.UC_HOOK_CODE,
        Block = c.UC_HOOK_BLOCK,
        ReadUnmapped = c.UC_HOOK_MEM_READ_UNMAPPED,
        WriteUnmapped = c.UC_HOOK_MEM_WRITE_UNMAPPED,
        FetchUnmapped = c.UC_HOOK_MEM_FETCH_UNMAPPED,
        MemReadProt = c.UC_HOOK_MEM_READ_PROT,
        MemWriteProt = c.UC_HOOK_MEM_WRITE_PROT,
        MemFetchProt = c.UC_HOOK_MEM_FETCH_PROT,
        MemRead = c.UC_HOOK_MEM_READ,
        MemWrite = c.UC_HOOK_MEM_WRITE,
        MemFetch = c.UC_HOOK_MEM_FETCH,
        MemReadAfter = c.UC_HOOK_MEM_READ_AFTER,
        InsnInvalid = c.UC_HOOK_INSN_INVALID,
        EdgeGenerated = c.UC_HOOK_EDGE_GENERATED,
        TcgOpcode = c.UC_HOOK_TCG_OPCODE,
        _,

        fn callback_type(comptime self: HookType, comptime UserdataType: type) type {
            return switch (self) {
                .Intr => *const fn (Unicorn, u32, UserdataType) void,
                .Code => *const fn (Unicorn, u64, u32, UserdataType) void,
                .InsnInvalid => *const fn (Unicorn, UserdataType) void,
                else => @compileError("TODO"),
            };
        }

        fn callback_wrapper(
            comptime self: HookType,
            comptime callback: anytype,
        ) *const anyopaque {
            const wrappers = struct {
                fn Intr(uc: ?*c.uc_engine, intno: u32, ud: ?*anyopaque) callconv(.C) void {
                    callback(Unicorn{ .uc = uc.? }, intno, @ptrCast(@alignCast(ud)));
                }
                fn Code(uc: ?*c.uc_engine, offset: u64, size: u32, ud: ?*anyopaque) callconv(.C) void {
                    callback(Unicorn{ .uc = uc.? }, offset, size, @ptrCast(@alignCast(ud)));
                }
                fn InsnInvalid(uc: ?*c.uc_engine, ud: ?*anyopaque) callconv(.C) void {
                    callback(Unicorn{ .uc = uc.? }, @ptrCast(@alignCast(ud)));
                }
            };

            return @ptrCast(&@field(wrappers, @tagName(self)));
        }
    };

    pub const Hook = struct { h: c.uc_hook };

    pub fn hook_add(
        self: *Unicorn,
        comptime type_: HookType,
        userdata: anytype,
        comptime callback: type_.callback_type(@TypeOf(userdata)),
        begin: u64,
        end: u64,
    ) Error!Hook {
        var h: Hook = undefined;

        try zig_error_from_uc_err(c.uc_hook_add(
            self.uc,
            &h.h,
            @intFromEnum(type_),
            @constCast(type_.callback_wrapper(callback)),
            userdata,
            begin,
            end,
        ));

        return h;
    }

    pub fn hook_del(self: Unicorn, h: Hook) Error!void {
        try zig_error_from_uc_err(c.uc_hook_del(self.uc, h.h));
    }

    pub const Prot = enum(u32) {
        None = c.UC_PROT_NONE,
        Read = c.UC_PROT_READ,
        ReadWrite = c.UC_PROT_READ | c.UC_PROT_WRITE,
        // ReadWriteExecute = c.UC_PROT_READ | c.UC_PROT_WRITE | c.UC_PROT_EXEC,
        Write = c.UC_PROT_WRITE,
        WriteExecute = c.UC_PROT_WRITE | c.UC_PROT_EXEC,
        Exec = c.UC_PROT_EXEC,
        All = c.UC_PROT_ALL,
    };

    pub fn mem_map(self: Unicorn, address: u64, size: usize, perms: Prot) Error!void {
        try zig_error_from_uc_err(c.uc_mem_map(self.uc, address, size, @intFromEnum(perms)));
    }

    pub fn mem_map_ptr(self: Unicorn, address: u64, size: usize, perms: Prot, ptr: *anyopaque) Error!void {
        try zig_error_from_uc_err(c.uc_mem_map_ptr(self.uc, address, size, @intFromEnum(perms), ptr));
    }

    pub fn mmio_map(
        self: *const Unicorn,
        address: u64,
        size: usize,
        read_userdata: anytype,
        comptime read_cb: ?fn (Unicorn, u64, usize, @TypeOf(read_userdata)) u64,
        write_userdata: anytype,
        comptime write_cb: ?fn (Unicorn, u64, usize, u64, @TypeOf(write_userdata)) void,
    ) !void {
        comptime {
            std.debug.assert(@typeInfo(@TypeOf(read_userdata)) == .Pointer);
            std.debug.assert(@typeInfo(@TypeOf(write_userdata)) == .Pointer);
        }
        const wrappers = struct {
            fn read(uc: ?*c.uc_engine, offset: u64, size_: c_uint, userdata: ?*anyopaque) callconv(.C) u64 {
                return read_cb.?(Unicorn{ .uc = uc }, offset, size_, @ptrCast(@alignCast(userdata)));
            }
            fn write(uc: ?*c.uc_engine, offset: u64, size_: c_uint, value: u64, userdata: ?*anyopaque) callconv(.C) void {
                write_cb.?(Unicorn{ .uc = uc }, offset, size_, value, @ptrCast(@alignCast(userdata)));
            }
        };

        try zig_error_from_uc_err(c.uc_mmio_map(
            self.uc,
            address,
            size,
            if (read_cb != null) wrappers.read else null,
            read_userdata,
            if (write_cb != null) wrappers.write else null,
            write_userdata,
        ));
    }

    pub fn mem_unmap(self: Unicorn, address: u64, size: usize) Error!void {
        try zig_error_from_uc_err(self.uc, address, size);
    }

    pub fn set_cpu(self: Unicorn, cpu: Cpu) Error!void {
        try zig_error_from_uc_err(c.uc_ctl_set_cpu_model(self.uc, @intFromEnum(cpu)));
    }

    pub fn get_cpu(self: Unicorn) Error!Cpu {
        var result: c_int = undefined;
        try zig_error_from_uc_err(c.uc_ctl_get_cpu_model(self.uc, &result));
        return @enumFromInt(result);
    }
};
