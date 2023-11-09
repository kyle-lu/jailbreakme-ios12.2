start:
b fn_load
nop

payload:
.xword 0x64616f6c796170

dlsym:
.xword 0x6d79736c64

startOfFixedExecutableMemoryPool:
.xword 0x6d654d78

endOfFixedExecutableMemoryPool:
.xword 0x646e456d654d78

jitWriteSeparateHeapsFunction:
.xword 0x657469725774696a

fn_load:
stp  x19, x20, [sp, -0x60]!
stp  x21, x22, [sp, 0x10]
stp  x23, x24, [sp, 0x20]
stp  x25, x26, [sp, 0x30]
stp  x27, x28, [sp, 0x40]
stp  x29, x30, [sp, 0x50]
add  x29,  sp, 0x50
sub   sp,  sp, 0x200

.equ LC_SEGMENT_64, 0x19
.equ LC_DYLD_INFO,  0x22

idx             .req x19
num             .req x20
mem_start       .req x21
mem_end         .req x22
mem_x_start     .req x23
mem_x_end       .req x24
mem_w_start     .req x25
mem_w_end       .req x26
ncmds           .req x27
ncmds_          .req w27
load_command    .req x28

mov  mem_start  , 0xffffffffffffffff
mov  mem_end    , 0x0
mov  mem_x_start, 0xffffffffffffffff
mov  mem_x_end  , 0x0
mov  mem_w_start, 0xffffffffffffffff
mov  mem_w_end  , 0x0

; [sp] to [sp, 0xf8]  ; segments
; [sp, 0x100]         ; temp string
str  xzr, [sp, 0x108] ; linkedit_base
; [sp, 0x110]         ; mmap
; [sp, 0x118]         ; memcpy
; [sp, 0x120]         ; buffer
; [sp, 0x128]         ; buffer_w

ldr  x10, payload            ; mach_header
ldr  ncmds_, [x10, 0x10]
add  load_command, x10, 0x20
mov  idx, 0x0
mov  num, 0x0

loop1:
cmp  idx, ncmds ; i < ncmds
b.hs loop1break

ldr  w10, [load_command] ; cmd
cmp  w10, LC_SEGMENT_64
b.ne loop1continue

ldr  x10, [load_command, 0x8] ; segname
mov  x11, 0x5f5f              ; "__PAGEZE"
movk x11, 0x4150, lsl 0x10
movk x11, 0x4547, lsl 0x20
movk x11, 0x455a, lsl 0x30
cmp  x10, x11
b.eq loop1continue

ldr  x12, [load_command, 0x18] ; vmaddr
str  x12, [sp, num, lsl 0x3]   ; segments
add  num, num, 0x1
ldr  x13, [load_command, 0x20] ; vmsize
add  x13, x12, x13

mov  x11, 0x5f5f            ; "__LINKED"
movk x11, 0x494c, lsl 0x10
movk x11, 0x4b4e, lsl 0x20
movk x11, 0x4445, lsl 0x30
cmp  x10, x11
b.ne not_linkedit

ldr  x10, [load_command, 0x28] ; fileoff
sub  x10, x12, x10
str  x10, [sp, 0x108] ; linkedit_base

not_linkedit:
ldr  w10, [load_command, 0x3c] ; initprot
tbz  w10, 0x2, mem_w_

mem_x_start_:
cmp  mem_x_start, x12
b.ls mem_x_end_

mov  mem_x_start, x12

mem_x_end_:
cmp  mem_x_end, x13
b.hs mem_w_

mov  mem_x_end, x13

mem_w_:
tbz  w10, 0x1, mem_start_

mem_w_start_:
cmp  mem_w_start, x12
b.ls mem_w_end_

mov  mem_w_start, x12

mem_w_end_:
cmp  mem_w_end, x13
b.hs mem_start_

mov  mem_w_end, x13

mem_start_:
cmp  mem_start, x12
b.ls mem_end_

mov  mem_start, x12

mem_end_:
cmp  mem_end, x13
b.hs loop1continue

mov  mem_end, x13

loop1continue:
add  idx, idx, 0x1   ; i++
ldr  w10, [load_command, 0x4] ; cmdsize
add  load_command, load_command, x10
b    loop1

loop1break:
mov  x0, -0x2
mov  x1, 0x6d6d           ; "mmap"
movk x1, 0x7061, lsl 0x10
str  x1, [sp, 0x100]
add  x1, sp, 0x100
ldr  x8, dlsym
blr  x8
str  x0, [sp, 0x110] ; mmap

mov  x0, -0x2
mov  x1, 0x656d           ; "memcpy"
movk x1, 0x636d, lsl 0x10
movk x1, 0x7970, lsl 0x20
str  x1, [sp, 0x100]
add  x1, sp, 0x100
ldr  x8, dlsym
blr  x8
str  x0, [sp, 0x118] ; memcpy

mov  x0, 0x0
sub  x1, mem_end, mem_start
mov  x2, 0x3
mov  w3, 0x1002
mov  w4, -0x1
mov  x5, 0x0
ldr  x8, [sp, 0x110] ; mmap
blr  x8
str  x0, [sp, 0x120] ; buffer

ldr  x10, payload            ; mach_header
add  load_command, x10, 0x20
mov  idx, 0x0 ; i

loop2:
cmp  idx, ncmds ; i < ncmds
b.hs loop2break

ldr  w10, [load_command] ; cmd
cmp  w10, LC_SEGMENT_64
b.ne loop2continue

ldr  x10, [load_command, 0x8] ; segname
mov  x11, 0x5f5f              ; "__PAGEZE"
movk x11, 0x4150, lsl 0x10
movk x11, 0x4547, lsl 0x20
movk x11, 0x455a, lsl 0x30
cmp  x10, x11
b.eq loop2continue

ldr  x9, [sp, 0x120]          ; buffer
ldr  x0, [load_command, 0x18] ; vmaddr
add  x0, x9, x0
ldr  x9, payload              ; mach_header
ldr  x1, [load_command, 0x28] ; fileoff
add  x1, x9, x1
ldr  x2, [load_command, 0x30] ; filesize
ldr  x8, [sp, 0x118]          ; memcpy
blr  x8

loop2continue:
add  idx, idx, 0x1
ldr  w10, [load_command, 0x4] ; cmdsize
add  load_command, load_command, x10
b    loop2

loop2break:
ldr  x0, endOfFixedExecutableMemoryPool
sub  x1, mem_end, mem_w_start
mov  x2, 0x3
mov  w3, 0x1012
mov  w4, -0x1
mov  x5, 0
ldr  x8, [sp, 0x110] ; mmap
blr  x8
str  x0, [sp, 0x128] ; buffer_w

ldr  x10, payload              ; mach_header
add  load_command, x10, 0x20   ; load_command
mov  idx, 0x0 ; i

loop3:
cmp  idx, ncmds ; i < ncmds
b.hs loop3break

ldr  w10, [load_command] ; cmd
and  w10, w10, 0xff
cmp  w10, LC_DYLD_INFO
b.ne loop3continue
;mov  w11, 0x22
;movk w11, 0x8000, lsl 0x10
;cmp  w10, w11 ; LC_DYLD_INFO_ONLY
;b.ne loop3continue

mov  x0, load_command ; cmd
ldr  x1, [sp, 0x120]  ; buffer
mov  x2, sp           ; segments
ldr  x3, [sp, 0x108]  ; linkedit_base
ldr  x4, endOfFixedExecutableMemoryPool
sub  x4, x4, mem_w_start
add  x4, x4, mem_start
bl   fn_rebase

mov  x0, load_command ; cmd
ldr  x1, [sp, 0x120]  ; buffer
mov  x2, sp           ; segments
ldr  x3, [sp, 0x108]  ; linkedit_base
ldr  x4, dlsym
mov  x5, 0x10         ; bind_off
bl   fn_bind

;mov  x0, load_command ; cmd
;ldr  x1, [sp, 0x120]  ; buffer
;mov  x2, sp           ; segments
;ldr  x3, [sp, 0x108]  ; linkedit_base
;ldr  x4, dlsym
;mov  x5, 0x18         ; weak_bind_off
;bl   fn_bind

mov  x0, load_command ; cmd
ldr  x1, [sp, 0x120]  ; buffer
mov  x2, sp           ; segments
ldr  x3, [sp, 0x108]  ; linkedit_base
ldr  x4, dlsym
mov  x5, 0x20         ; lazy_bind_off
bl   fn_bind

loop3continue:
add  idx, idx, 0x1
ldr  w10, [load_command, 0x4] ; cmdsize
add  load_command, load_command, x10
b    loop3

loop3break:
ldr  x0, endOfFixedExecutableMemoryPool
sub  x0, x0, mem_w_start
add  x0, x0, mem_start
ldr  x9, startOfFixedExecutableMemoryPool
sub  x0, x0, x9
ldr  x1, [sp, 0x120]  ; buffer
sub  x2, mem_w_start, mem_start
ldr  x8, jitWriteSeparateHeapsFunction
blr  x8

ldr  x0, [sp, 0x128]  ; buffer_w
ldr  x1, [sp, 0x120]  ; buffer
add  x1, x1, mem_w_start
sub  x1, x1, mem_start
sub  x2, mem_end, mem_w_start
ldr  x8, [sp, 0x118]  ; memcpy
blr  x8

ldr  x10, payload              ; mach_header
add  load_command, x10, 0x20   ; load_command
mov  idx, 0x0 ; i

loop4:
cmp  idx, ncmds ; i < ncmds
b.hs loop4break

ldr  w10, [load_command] ; cmd
cmp  w10, LC_SEGMENT_64
b.ne loop4continue

ldr  x10, [load_command, 0x8] ; segname
mov  x11, 0x5f5f              ; "__PAGEZE"
movk x11, 0x4150, lsl 0x10
movk x11, 0x4547, lsl 0x20
movk x11, 0x455a, lsl 0x30
cmp  x10, x11
b.eq loop4continue

ldr  w10, [load_command, 0x40] ; nsects
mov  num, 0x0 ; n
add  x11, load_command, 0x48   ; section

loop4section:
cmp  num, x10 ; n < nsects
b.hs loop4continue

ldr  x12, [x11]
mov  x13, 0x5f5f              ; "__mod_in"
movk x13, 0x6f6d, lsl 0x10
movk x13, 0x5f64, lsl 0x20
movk x13, 0x6e69, lsl 0x30
cmp  x12, x13
b.ne loop4section_continue

ldr  x12, endOfFixedExecutableMemoryPool
sub  x12, x12, mem_w_start
add  x12, x12, mem_start
;mov  x13, 0x0
;wait:
;ldr  x13, [x12]
;cbz  x13, wait

ldr  x13, [x11, 0x20]  ; addr
ldr  x14, [sp, 0x120]  ; buffer
ldr  x15, [x14, x13]
blr  x15
b    loop4break

loop4section_continue:
add  num, num, 0x1
add  x11, x11, 0x50
b loop4section

loop4continue:
add  idx, idx, 0x1
ldr  w10, [load_command, 0x4] ; cmdsize
add  load_command, load_command, x10
b    loop4

loop4break:
b    loop4break ; dead loop

add   sp,  sp, 0x200
ldp  x29, x30, [sp, 0x50]
ldp  x27, x28, [sp, 0x40]
ldp  x25, x26, [sp, 0x30]
ldp  x23, x24, [sp, 0x20]
ldp  x21, x22, [sp, 0x10]
ldp  x19, x20, [sp], 0x60
ret


fn_rebase:
stp  x19, x20, [sp, -0x60]!
stp  x21, x22, [sp, 0x10]
stp  x23, x24, [sp, 0x20]
stp  x25, x26, [sp, 0x30]
stp  x27, x28, [sp, 0x40]
stp  x29, x30, [sp, 0x50]
add  x29,  sp, 0x50
sub   sp,  sp, 0x100

stp  x0, x1, [sp]       ; cmd, buffer
stp  x2, x3, [sp, 0x10] ; segments, linkedit_base

.equ REBASE_OPCODE_MASK,    0xf0
.equ REBASE_IMMEDIATE_MASK, 0x0f

idx             .req x19
idx_            .req w19
start           .req x20
end             .req x21
ptr             .req x22
address         .req x23
opcode_         .req w24
immediate       .req x25
immediate_      .req w25
segmet          .req x27
mem_base        .req x28

mov  mem_base, x4

ldp  w10, w11, [x0, 0x8] ; cmd->rebase_off, cmd->rebase_size
add  x10, x3, x10        ; linkedit_base + rebase_off
add  start, x1, x10      ; start = buffer + linkedit_base + rebase_off
add  end, start, x11     ; end = start + rebase_size

mov  ptr, start   ; ptr = start
mov  address, x1  ; address = buffer

rebase_loop:
cmp  ptr, end ; while (p < end)
b.hs rebase_done

ldrb w10, [ptr], 0x1
and  opcode_, w10, REBASE_OPCODE_MASK       ; opcode = *p & REBASE_OPCODE_MASK
and  immediate_, w10, REBASE_IMMEDIATE_MASK ; immediate = *p & REBASE_IMMEDIATE_MASK

REBASE_OPCODE_DONE:
cmp  opcode_, 0x00
b.ne  REBASE_OPCODE_SET_TYPE_IMM

b    rebase_loop

REBASE_OPCODE_SET_TYPE_IMM:
cmp  opcode_, 0x10
b.ne REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB

cmp  immediate_, 0x1  ; REBASE_TYPE_POINTER
b.eq rebase_loop

mov  x0, 0x66
movk x0, 0xa, lsl 0x20
bl   fn_fa11dead

REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
cmp  opcode_, 0x20
b.ne REBASE_OPCODE_ADD_ADDR_ULEB

ldp  x10, x11, [sp, 0x8] ; buffer, segments
ldr  segmet, [x11, immediate, lsl 0x3]
add  segmet, segmet, x10 ; segment = buffer + *(segments + immediate * 8)
mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
add  address, segmet, x0  ; address = segment + read_uleb128(p, end)
b    rebase_loop

REBASE_OPCODE_ADD_ADDR_ULEB:
cmp  opcode_, 0x30
b.ne REBASE_OPCODE_ADD_ADDR_IMM_SCALED

mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
add  address, address, x0 ; address += read_uleb128(p, end)
b    rebase_loop

REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
cmp  opcode_, 0x40
b.ne REBASE_OPCODE_DO_REBASE_IMM_TIMES

add address, address, immediate, lsl 0x3 ; address += immediate * 8
b    rebase_loop

REBASE_OPCODE_DO_REBASE_IMM_TIMES:
cmp  opcode_, 0x50
b.ne REBASE_OPCODE_DO_REBASE_ULEB_TIMES

mov  idx, 0x0 ; i
REBASE_OPCODE_DO_REBASE_IMM_TIMES_loop:
cmp  idx_, immediate_
b.hs rebase_loop

ldr  x10, [address]
add  x10, x10, mem_base
str  x10, [address]
add  address, address, 0x8
add  idx, idx, 0x1
b    REBASE_OPCODE_DO_REBASE_IMM_TIMES_loop

REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
cmp  opcode_, 0x60
b.ne REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB

mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
mov  idx, 0x0 ; i
REBASE_OPCODE_DO_REBASE_ULEB_TIMES_loop:
cmp  idx_, w0
b.hs rebase_loop

ldr  x10, [address]
add  x10, x10, mem_base
str  x10, [address]
add  address, address, 0x8
add  idx, idx, 0x1
b    REBASE_OPCODE_DO_REBASE_ULEB_TIMES_loop

REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
cmp  opcode_, 0x70
b.ne REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB

ldr  x10, [address]
add  x10, x10, mem_base
str  x10, [address]
mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
add  x10, x0, 0x8
add  address, address, x10
b    rebase_loop

REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
cmp  opcode_, 0x80
b.ne REBASE_OPCODE_UNKNOWN

mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
mov  x12, x0  ; count
mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
mov  x13, x0  ; skip
mov  idx, 0x0 ; i
REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB_loop:
cmp  idx_, w12
b.hs rebase_loop

ldr  x10, [address]
add  x10, x10, mem_base
str  x10, [address]
add  x10, x13, 0x8
add  address, address, x10
add  idx, idx, 0x1
b    REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB_loop

b    rebase_loop

REBASE_OPCODE_UNKNOWN:
mov  x0, 0x8d
movk x0, 0xa, lsl 0x20
bl   fn_fa11dead

rebase_done:
add  sp, sp, 0x100
ldp  x29, x30, [sp, 0x50]
ldp  x27, x28, [sp, 0x40]
ldp  x25, x26, [sp, 0x30]
ldp  x23, x24, [sp, 0x20]
ldp  x21, x22, [sp, 0x10]
ldp  x19, x20, [sp], 0x60
ret


fn_bind:
stp  x19, x20, [sp, -0x60]!
stp  x21, x22, [sp, 0x10]
stp  x23, x24, [sp, 0x20]
stp  x25, x26, [sp, 0x30]
stp  x27, x28, [sp, 0x40]
stp  x29, x30, [sp, 0x50]
add  x29, sp, 0x50
sub  sp, sp, 0x100

stp  x0, x1, [sp]       ; cmd, buffer
stp  x2, x3, [sp, 0x10] ; segments, linkedit_base

.equ BIND_OPCODE_MASK,    0xf0
.equ BIND_IMMEDIATE_MASK, 0x0f

idx             .req x19
idx_            .req w19
start           .req x20
end             .req x21
ptr             .req x22
address         .req x23
opcode_         .req w24
immediate_      .req w25
symbol_name     .req x26
segmet          .req x27
dlsym           .req x28

mov dlsym, x4

add  x9, x0, x5
ldp  w10, w11, [x9]   ; bind_off, bind_size
add  x10, x3, x10           ; linkedit_base + bind_off
add  start, x1, x10         ; start = buffer + linkedit_base + bind_off
add  end, start, x11        ; end = start + bind_size

mov  ptr, start   ; ptr = start
mov  address, x1  ; address = buffer

bind_loop:
cmp  ptr, end ; while (p < end)
b.hs bind_done

ldrb w10, [ptr], 0x1
and  opcode_, w10, BIND_OPCODE_MASK       ; opcode = *p & BIND_OPCODE_MASK
and  immediate_, w10, BIND_IMMEDIATE_MASK ; immediate = *p & BIND_IMMEDIATE_MASK

BIND_OPCODE_DONE:
cmp  opcode_, 0x00
b.ne BIND_OPCODE_SET_DYLIB_ORDINAL_IMM

b    bind_loop

BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
cmp  opcode_, 0x10
b.ne BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB

b    bind_loop

BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
cmp  opcode_, 0x20
b.ne BIND_OPCODE_SET_DYLIB_SPECIAL_IMM

mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1

b    bind_loop

BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
cmp  opcode_, 0x30
b.ne BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM

b    bind_loop

BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
cmp  opcode_, 0x40
b.ne BIND_OPCODE_SET_TYPE_IMM

ldrb w10, [ptr]
cmp  w10, 0x5f
b.ne BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM_symbol
add  ptr, ptr, 0x1

BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM_symbol:
mov  symbol_name, ptr

BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM_loop:
ldrb w10, [ptr], 0x1
cbz  w10, bind_loop

b    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM_loop

BIND_OPCODE_SET_TYPE_IMM:
cmp  opcode_, 0x50
b.ne BIND_OPCODE_SET_ADDEND_SLEB

b    bind_loop

BIND_OPCODE_SET_ADDEND_SLEB:
cmp  opcode_, 0x60
b.ne BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB

mov  x0, 0xbc
movk x0, 0xa, lsl 0x20
bl   fn_fa11dead

BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
cmp  opcode_, 0x70
b.ne BIND_OPCODE_ADD_ADDR_ULEB

ldp  x10, x11, [sp, 0x8] ; buffer, segments
ldr  segmet, [x11, immediate, lsl 0x3]
add  segmet, segmet, x10 ; segment = buffer + *(segments + immediate * 8)
mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
add  address, segmet, x0  ; address = segment + read_uleb128(p, end)

b    bind_loop

BIND_OPCODE_ADD_ADDR_ULEB:
cmp  opcode_, 0x80
b.ne BIND_OPCODE_DO_BIND

mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
add  address, address, x0 ; address += read_uleb128(p, end)

b    bind_loop

BIND_OPCODE_DO_BIND:
cmp  opcode_, 0x90
b.ne BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB

mov  x0, -0x2
mov  x1, symbol_name
blr  dlsym
str  x0, [address]
add  address, address, 0x8

b    bind_loop

BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
cmp  opcode_, 0xa0
b.ne BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED

mov  x0, -0x2
mov  x1, symbol_name
blr  dlsym
str  x0, [address]
mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
add  x0, x0, 0x8
add  address, address, x0

b    bind_loop

BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
cmp  opcode_, 0xb0
b.ne BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB

mov  x0, -0x2
mov  x1, symbol_name
blr  dlsym
str  x0, [address]
add  x10, immediate, 0x1
add  address, address, x10, lsl 0x3

b    bind_loop

BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
cmp  opcode_, 0xc0
b.ne BIND_OPCODE_UNKNOWN

mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
mov  x12, x0  ; count
mov  x0, ptr
mov  x1, end
bl   fn_read_uleb128
mov  ptr, x1
mov  x13, x0  ; skip
mov  idx, 0x0 ; i
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB_loop:
cmp  idx_, w12
b.hs bind_loop

mov  x0, -0x2
mov  x1, symbol_name
blr  dlsym
str  x0, [address]
add  x13, x13, 0x8
add  address, address, x13
add  idx, idx, 0x1
b    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB_loop

BIND_OPCODE_UNKNOWN:
mov  x0, 0xd6
movk x0, 0xa, lsl 0x20
bl   fn_fa11dead

bind_done:

add  sp, sp, 0x100
ldp  x29, x30, [sp, 0x50]
ldp  x27, x28, [sp, 0x40]
ldp  x25, x26, [sp, 0x30]
ldp  x23, x24, [sp, 0x20]
ldp  x21, x22, [sp, 0x10]
ldp  x19, x20, [sp], 0x60
ret


fn_read_uleb128:
mov  x9, x0   ; p
mov  x0, 0x0  ; result
mov  w8, 0x0  ; bit

read_uleb128_loop:
ldrb w7, [x9]
and  w6, w7, 0x7f
lsl  x6, x6, x8
orr  x0, x0, x6

add  w8, w8, 0x7
add  x9, x9, 0x1
tbnz w7, 0x7, read_uleb128_loop

mov  x1, x9
ret

fn_fa11dead:
mov  w10, 0xfa11dead
mov  x11, 0xbad000000000
add  x11, x11, x0
str  w10, [x11]
ret
