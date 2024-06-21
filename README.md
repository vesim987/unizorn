Unizorn
==============

Zig bindings for the Unicorn emulator with the support for building directly by build.zig

```zig
const std = @import("std");
const uz = @import("unizorn");

pub fn main() !void {
  const emu = try uz.Unicorn.open(uz.Arch.Arm, uz.Mode.LittleEndian);
  defer emu.close();

  try emu.mem_map(0x1000, 0x4000, .All);
  try emu.mem_write(0x1000, &.{0x17, 0x00, 0x40, 0xe2}); // sub r0, #23

  try emu.reg_write(u32, uz.Reg.Arm.R0, 123);
  try emu.reg_write(u32, uz.Reg.Arm.R5, 1337);

  try emu.emu_start(0x1000, 0x1000 + 4, 10 * std.time.ns_per_s, 1000);

  std.debug.assert(try emu.reg_read(u32, uz.Reg.Arm.R0) == 100);
  std.debug.assert(try emu.reg_read(u32, uz.Reg.Arm.R5) == 1337);
}

```

Host support matrix
==============

|         | Linux | Macos | Windows |
|---------|-------|-------|---------|
| x86     | ?     | ?     | Y*      |
| x86_64  | Y     | Y     | Y*      |
| arm     | ?     | N/A   | N/A     |
| aarch64 | Y     | Y     | Y*      |

Supported targets
==============

- ARM
