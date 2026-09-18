00203564: stp      x29, x30, [sp, #-0x60]!
00203568: stp      x28, x27, [sp, #0x10]
0020356c: stp      x26, x25, [sp, #0x20]
00203570: stp      x24, x23, [sp, #0x30]
00203574: stp      x22, x21, [sp, #0x40]
00203578: stp      x20, x19, [sp, #0x50]
0020357c: mov      x29, sp
00203580: sub      sp, sp, #0x230
00203584: mrs      x8, tpidr_el0
00203588: adrp     x9, #0xc6000
0020358c: add      x9, x9, #0x150  ; =0xc6150 "Qz=U\xc37*= "
00203590: str      x8, [sp, #8]
00203594: mov      x11, #0x2325
00203598: mov      x12, #0x1b3
0020359c: ldr      x8, [x8, #0x28]
002035a0: movk     x11, #0x8422, lsl #16
002035a4: movk     x12, #0x100, lsl #32
002035a8: movk     x11, #0x9ce4, lsl #32
002035ac: mov      x15, #0xa346
002035b0: mov      w24, #0x6f51
002035b4: stur     x8, [x29, #-0x10]
002035b8: movk     x11, #0xcbf2, lsl #48
002035bc: movk     x15, #0x338f, lsl #16
002035c0: ldr      x10, [x9]
002035c4: ldr      x8, [x9, #0x10]
002035c8: movk     x15, #0xdaff, lsl #32
002035cc: movk     x15, #0xadb8, lsl #48
002035d0: mov      w25, #0xddf8
002035d4: mov      w16, #0x5199
002035d8: add      x8, x8, x9
002035dc: mov      w17, #0xc132
002035e0: mov      w27, #0x171f
002035e4: ldr      x9, [x8]
002035e8: ldr      x13, [x8, #8]
002035ec: mov      w19, #0xbad
002035f0: mov      w20, wzr
002035f4: adrp     x22, #0x716000
002035f8: movk     w24, #0xddd, lsl #16
002035fc: eor      x9, x9, x11
00203600: movk     w25, #0xdd97, lsl #16
00203604: movk     w16, #0xcf68, lsl #16
00203608: mul      x9, x9, x12
0020360c: add      x28, sp, #0x20
00203610: movk     w17, #0xe132, lsl #16
00203614: movk     w27, #0x427a, lsl #16
00203618: movk     w19, #0x542e, lsl #16
0020361c: eor      x9, x13, x9, ror #37
00203620: ldr      x13, [x8, #0x10]
00203624: ldr      x8, [x8, #0x18]
00203628: mul      x9, x9, x12
0020362c: eor      x9, x13, x9, ror #37
00203630: mov      x13, #0x92d9
00203634: movk     x13, #0x114a, lsl #16
00203638: mul      x9, x9, x12
0020363c: movk     x13, #0x5055, lsl #32
00203640: movk     x13, #0xeea6, lsl #48
00203644: eor      x8, x8, x9, ror #37
00203648: mul      x8, x8, x12
0020364c: ror      x9, x8, #0x25
00203650: adrp     x8, #0x716000
00203654: add      x8, x8, #0xad0  ; =0x716ad0 ""
00203658: ldr      x14, [x8]
0020365c: eor      w9, w9, w10
00203660: add      x21, x9, x13
00203664: add      x9, x14, x21
00203668: mov      w14, #0xdaff
0020366c: ldr      x10, [x9]
00203670: ldr      x13, [x9, #0x10]
00203674: movk     w14, #0xadb8, lsl #16
00203678: add      x9, x13, x9
0020367c: ldr      x13, [x9]
00203680: eor      x11, x13, x11
00203684: ldr      x13, [x9, #8]
00203688: mul      x11, x11, x12
0020368c: eor      x11, x13, x11, ror #37
00203690: ldr      x13, [x9, #0x10]
00203694: ldr      x9, [x9, #0x18]
00203698: mul      x11, x11, x12
0020369c: eor      x11, x13, x11, ror #37
002036a0: mov      x13, #0xf7d1
002036a4: movk     x13, #0x7b00, lsl #16
002036a8: mul      x11, x11, x12
002036ac: movk     x13, #0xb9db, lsl #32
002036b0: movk     x13, #0x30f8, lsl #48
002036b4: eor      x9, x9, x11, ror #37
002036b8: mov      x11, #0x8399
002036bc: movk     x11, #0x6ae, lsl #16
002036c0: mul      x9, x9, x12
002036c4: movk     x11, #0x5ee4, lsl #32
002036c8: adrp     x12, #0x6e8000
002036cc: movk     x11, #0x8d7b, lsl #48
002036d0: ldr      x12, [x12, #0xd40]  ; =0x6e8d40 raw=0000000000000000
002036d4: eor      x9, x10, x9, ror #37
002036d8: add      x10, x11, w9, uxtw
002036dc: ldp      x11, x8, [x8, #8]
002036e0: add      w26, w9, w14
002036e4: eor      x23, x10, x12
002036e8: mov      w12, #0xfb54
002036ec: add      x11, x11, x21
002036f0: movk     w12, #0x2444, lsl #16
002036f4: eor      x10, x23, x11
002036f8: str      x10, [sp, #0x20]
002036fc: add      x10, x15, w9, uxtw
00203700: and      x9, x23, #0xffffffff00000000
00203704: ldr      x8, [x8, x21]
00203708: add      x8, x8, x13
0020370c: eor      x8, x23, x8
00203710: str      x8, [sp, #0x138]
00203714: eor      x8, x10, x23
00203718: stp      x8, x9, [sp, #0x10]
0020371c: ldr      x8, [x22, #0xae8]  ; =0x716ae8 raw=0000000000000000
00203720: add      x8, x8, x21
00203724: ldr      w9, [x8, w20, sxtw #2]
00203728: eor      w9, w9, w26
0020372c: cmp      w9, w24
00203730: b.le     #0x20379c
00203734: cmp      w9, w27
00203738: b.le     #0x203864
0020373c: cmp      w9, w19
00203740: b.gt     #0x2038c0
00203744: mov      w10, #0x1720
00203748: movk     w10, #0x427a, lsl #16
0020374c: cmp      w9, w10
00203750: b.eq     #0x203b3c
00203754: mov      w10, #0xdc95
00203758: movk     w10, #0x4b7e, lsl #16
0020375c: cmp      w9, w10
00203760: b.ne     #0x203bc4
00203764: add      w9, w20, #1
00203768: add      w10, w20, #2
0020376c: add      w11, w20, #3
00203770: ldr      w9, [x8, w9, sxtw #2]
00203774: ldr      w10, [x8, w10, sxtw #2]
00203778: eor      w10, w10, w26
0020377c: ldr      x10, [x28, w10, sxtw #3]
00203780: ldr      w8, [x8, w11, sxtw #2]
00203784: eor      w8, w8, w26
00203788: eor      x10, x10, x23
0020378c: ldr      x8, [x28, w8, sxtw #3]
00203790: eor      x8, x8, x23
00203794: mul      x8, x8, x10
00203798: b        #0x2039dc  ; ->0x2039dc
0020379c: cmp      w9, w25
002037a0: b.gt     #0x203800
002037a4: cmp      w9, w16
002037a8: b.gt     #0x203918
002037ac: mov      w10, #0xfe54
002037b0: movk     w10, #0x8add, lsl #16
002037b4: cmp      w9, w10
002037b8: b.eq     #0x203b10
002037bc: mov      w10, #0x64cb
002037c0: movk     w10, #0x8bd1, lsl #16
002037c4: cmp      w9, w10
002037c8: b.eq     #0x2039bc
002037cc: add      w9, w20, #1
002037d0: add      w10, w20, #3
002037d4: add      w11, w20, #2
002037d8: ldr      w9, [x8, w9, sxtw #2]
002037dc: eor      w9, w9, w26
002037e0: ldr      x9, [x28, w9, sxtw #3]
002037e4: ldr      w10, [x8, w10, sxtw #2]
002037e8: ldr      w8, [x8, w11, sxtw #2]
002037ec: eor      w9, w9, w23
002037f0: tst      x9, #1
002037f4: csel     w8, w10, w8, eq
002037f8: eor      w20, w8, w26
002037fc: b        #0x20371c  ; ->0x20371c
00203800: cmp      w9, w17
00203804: b.le     #0x203974
00203808: mov      w10, #0xc133
0020380c: movk     w10, #0xe132, lsl #16
00203810: cmp      w9, w10
00203814: b.eq     #0x2039e4
00203818: mov      w10, #0xdc1e
0020381c: movk     w10, #0xfe24, lsl #16
00203820: cmp      w9, w10
00203824: b.ne     #0x203a20
00203828: add      w9, w20, #1
0020382c: add      w10, w20, #2
00203830: add      w11, w20, #3
00203834: ldr      w9, [x8, w9, sxtw #2]
00203838: ldr      w10, [x8, w10, sxtw #2]
0020383c: eor      w10, w10, w26
00203840: eor      w9, w9, w26
00203844: ldr      x10, [x28, w10, sxtw #3]
00203848: ldr      w8, [x8, w11, sxtw #2]
0020384c: eor      w8, w8, w26
00203850: eor      x10, x10, x23
00203854: ldr      x8, [x28, w8, sxtw #3]
00203858: eor      x8, x8, x23
0020385c: add      x8, x8, x10
00203860: b        #0x203b00  ; ->0x203b00
00203864: cmp      w9, w12
00203868: b.le     #0x2039ac
0020386c: mov      w10, #0xfb55
00203870: movk     w10, #0x2444, lsl #16
00203874: cmp      w9, w10
00203878: b.eq     #0x203ac8
0020387c: mov      w10, #0x7273
00203880: movk     w10, #0x2b1c, lsl #16
00203884: cmp      w9, w10
00203888: b.ne     #0x203b8c
0020388c: add      w9, w20, #1
00203890: add      w10, w20, #2
00203894: add      w11, w20, #3
00203898: ldr      w9, [x8, w9, sxtw #2]
0020389c: ldr      w10, [x8, w10, sxtw #2]
002038a0: eor      w10, w10, w26
002038a4: eor      w9, w9, w26
002038a8: ldr      x10, [x28, w10, sxtw #3]
002038ac: ldr      w8, [x8, w11, sxtw #2]
002038b0: eor      w8, w8, w26
002038b4: ldr      x8, [x28, w8, sxtw #3]
002038b8: eor      w8, w8, w10
002038bc: b        #0x203b00  ; ->0x203b00
002038c0: mov      w10, #0xbae
002038c4: movk     w10, #0x542e, lsl #16
002038c8: cmp      w9, w10
002038cc: b.eq     #0x203b64
002038d0: mov      w10, #0xeaf7
002038d4: movk     w10, #0x6630, lsl #16
002038d8: cmp      w9, w10
002038dc: b.ne     #0x203bf8
002038e0: add      w9, w20, #1
002038e4: add      w10, w20, #2
002038e8: add      w11, w20, #3
002038ec: ldr      w9, [x8, w9, sxtw #2]
002038f0: ldr      w10, [x8, w10, sxtw #2]
002038f4: eor      w10, w10, w26
002038f8: ldr      x10, [x28, w10, sxtw #3]
002038fc: ldr      w8, [x8, w11, sxtw #2]
00203900: eor      w8, w8, w26
00203904: ldr      x8, [x28, w8, sxtw #3]
00203908: cmp      x10, x8
0020390c: eor      w8, w9, w26
00203910: cset     w9, ne
00203914: b        #0x20396c  ; ->0x20396c
00203918: mov      w10, #0xd384
0020391c: movk     w10, #0xcfec, lsl #16
00203920: cmp      w9, w10
00203924: b.eq     #0x203aa0
00203928: mov      w10, #0x6e
0020392c: movk     w10, #0xd9ef, lsl #16
00203930: cmp      w9, w10
00203934: b.ne     #0x203c2c
00203938: add      w9, w20, #1
0020393c: add      w10, w20, #2
00203940: add      w11, w20, #3
00203944: ldr      w9, [x8, w9, sxtw #2]
00203948: ldr      w10, [x8, w10, sxtw #2]
0020394c: eor      w10, w10, w26
00203950: ldr      x10, [x28, w10, sxtw #3]
00203954: ldr      w8, [x8, w11, sxtw #2]
00203958: eor      w8, w8, w26
0020395c: ldr      x8, [x28, w8, sxtw #3]
00203960: cmp      w10, w8
00203964: eor      w8, w9, w26
00203968: cset     w9, eq
0020396c: eor      x9, x23, x9
00203970: b        #0x203b58  ; ->0x203b58
00203974: mov      w10, #0xddf9
00203978: movk     w10, #0xdd97, lsl #16
0020397c: cmp      w9, w10
00203980: b.ne     #0x203a6c
00203984: ldr      w8, [sp, #0x90]
00203988: ldr      x9, [sp, #0xb8]
0020398c: add      w20, w20, #5
00203990: eor      w8, w8, w23
00203994: eor      x9, x9, x23
00203998: neg      w8, w8
0020399c: ror      x8, x9, x8
002039a0: eor      x8, x8, x23
002039a4: str      x8, [sp, #0xc0]
002039a8: b        #0x20371c  ; ->0x20371c
002039ac: mov      w10, #0x6f52
002039b0: movk     w10, #0xddd, lsl #16
002039b4: cmp      w9, w10
002039b8: b.ne     #0x203bb4
002039bc: add      w9, w20, #1
002039c0: add      w10, w20, #2
002039c4: ldr      w9, [x8, w9, sxtw #2]
002039c8: ldr      w8, [x8, w10, sxtw #2]
002039cc: eor      w8, w8, w26
002039d0: ldr      x8, [x28, w8, sxtw #3]
002039d4: eor      x8, x8, x23
002039d8: ldr      x8, [x8]
002039dc: eor      w9, w9, w26
002039e0: b        #0x203b00  ; ->0x203b00
002039e4: add      w9, w20, #1
002039e8: add      w10, w20, #2
002039ec: add      w11, w20, #3
002039f0: ldr      w9, [x8, w9, sxtw #2]
002039f4: ldr      w10, [x8, w10, sxtw #2]
002039f8: eor      w10, w10, w26
002039fc: eor      w9, w9, w26
00203a00: ldr      x10, [x28, w10, sxtw #3]
00203a04: ldr      w8, [x8, w11, sxtw #2]
00203a08: eor      w8, w8, w26
00203a0c: eor      w10, w10, w23
00203a10: ldr      x8, [x28, w8, sxtw #3]
00203a14: eor      w8, w8, w23
00203a18: add      w8, w8, w10
00203a1c: b        #0x203b00  ; ->0x203b00
00203a20: ldr      w8, [sp, #0x198]
00203a24: ldr      x9, [sp, #0x188]
00203a28: ldr      x10, [sp, #0x130]
00203a2c: eor      w8, w8, w23
00203a30: eor      x9, x9, x23
00203a34: eor      x0, x10, x23
00203a38: and      w1, w8, #1
00203a3c: blr      x9
00203a40: and      x8, x0, #1
00203a44: mov      w12, #0xfb54
00203a48: mov      w17, #0xc132
00203a4c: mov      w16, #0x5199
00203a50: eor      x8, x23, x8
00203a54: movk     w12, #0x2444, lsl #16
00203a58: movk     w17, #0xe132, lsl #16
00203a5c: movk     w16, #0xcf68, lsl #16
00203a60: add      w20, w20, #5
00203a64: str      x8, [sp, #0x190]
00203a68: b        #0x20371c  ; ->0x20371c
00203a6c: add      w9, w20, #1
00203a70: add      w10, w20, #2
00203a74: add      w11, w20, #3
00203a78: ldr      w9, [x8, w9, sxtw #2]
00203a7c: ldr      w10, [x8, w10, sxtw #2]
00203a80: eor      w10, w10, w26
00203a84: eor      w9, w9, w26
00203a88: ldr      x10, [x28, w10, sxtw #3]
00203a8c: ldr      w8, [x8, w11, sxtw #2]
00203a90: eor      w8, w8, w26
00203a94: ldr      x8, [x28, w8, sxtw #3]
00203a98: eor      x8, x10, x8
00203a9c: b        #0x203b00  ; ->0x203b00
00203aa0: ldr      w8, [sp, #0x90]
00203aa4: ldr      x9, [sp, #0x110]
00203aa8: add      w20, w20, #5
00203aac: eor      w8, w8, w23
00203ab0: eor      x9, x9, x23
00203ab4: neg      w8, w8
00203ab8: ror      x8, x9, x8
00203abc: eor      x8, x8, x23
00203ac0: str      x8, [sp, #0x118]
00203ac4: b        #0x20371c  ; ->0x20371c
00203ac8: add      w9, w20, #1
00203acc: add      w10, w20, #2
00203ad0: add      w11, w20, #3
00203ad4: ldr      w9, [x8, w9, sxtw #2]
00203ad8: ldr      w10, [x8, w10, sxtw #2]
00203adc: eor      w10, w10, w26
00203ae0: eor      w9, w9, w26
00203ae4: ldr      x10, [x28, w10, sxtw #3]
00203ae8: ldr      w8, [x8, w11, sxtw #2]
00203aec: eor      w8, w8, w26
00203af0: eor      w10, w10, w23
00203af4: ldr      x8, [x28, w8, sxtw #3]
00203af8: eor      w8, w8, w23
00203afc: sub      w8, w10, w8
00203b00: eor      x8, x8, x23
00203b04: str      x8, [x28, w9, sxtw #3]
00203b08: add      w20, w20, #5
00203b0c: b        #0x20371c  ; ->0x20371c
00203b10: add      w9, w20, #1
00203b14: add      w10, w20, #2
00203b18: ldr      w9, [x8, w9, sxtw #2]
00203b1c: ldr      w8, [x8, w10, sxtw #2]
00203b20: ldr      x10, [sp, #0x18]
00203b24: eor      w8, w8, w26
00203b28: eor      w9, w9, w26
00203b2c: sbfiz    x8, x8, #3, #0x20
00203b30: ldr      w8, [x28, x8]
00203b34: orr      x8, x8, x10
00203b38: b        #0x203b04  ; ->0x203b04
00203b3c: add      w9, w20, #2
00203b40: add      w10, w20, #1
00203b44: ldr      w9, [x8, w9, sxtw #2]
00203b48: eor      w9, w9, w26
00203b4c: ldr      x9, [x28, w9, sxtw #3]
00203b50: ldr      w8, [x8, w10, sxtw #2]
00203b54: eor      w8, w8, w26
00203b58: str      x9, [x28, w8, sxtw #3]
00203b5c: add      w20, w20, #5
00203b60: b        #0x20371c  ; ->0x20371c
00203b64: ldr      w8, [sp, #0x90]
00203b68: ldr      x9, [sp, #0xe0]
00203b6c: add      w20, w20, #5
00203b70: eor      w8, w8, w23
00203b74: eor      x9, x9, x23
00203b78: neg      w8, w8
00203b7c: ror      x8, x9, x8
00203b80: eor      x8, x8, x23
00203b84: str      x8, [sp, #0xe8]
00203b88: b        #0x20371c  ; ->0x20371c
00203b8c: ldr      w8, [sp, #0x90]
00203b90: ldr      x9, [sp, #0x80]
00203b94: add      w20, w20, #5
00203b98: eor      w8, w8, w23
00203b9c: eor      x9, x9, x23
00203ba0: neg      w8, w8
00203ba4: ror      x8, x9, x8
00203ba8: eor      x8, x8, x23
00203bac: str      x8, [sp, #0x88]
00203bb0: b        #0x20371c  ; ->0x20371c
00203bb4: add      w9, w20, #1
00203bb8: ldr      w8, [x8, w9, sxtw #2]
00203bbc: eor      w20, w8, w26
00203bc0: b        #0x20371c  ; ->0x20371c
00203bc4: ldr      x8, [sp, #0x138]
00203bc8: eor      x8, x8, x23
00203bcc: blr      x8
00203bd0: mov      w12, #0xfb54
00203bd4: mov      w17, #0xc132
00203bd8: mov      w16, #0x5199
00203bdc: eor      x8, x23, x0
00203be0: movk     w12, #0x2444, lsl #16
00203be4: movk     w17, #0xe132, lsl #16
00203be8: movk     w16, #0xcf68, lsl #16
00203bec: add      w20, w20, #5
00203bf0: str      x8, [sp, #0x130]
00203bf4: b        #0x20371c  ; ->0x20371c
00203bf8: add      w9, w20, #1
00203bfc: add      w10, w20, #2
00203c00: ldr      w9, [x8, w9, sxtw #2]
00203c04: ldr      w8, [x8, w10, sxtw #2]
00203c08: adrp     x10, #0x716000
00203c0c: ldr      x10, [x10, #0xaf0]  ; =0x716af0 raw=0000000000000000
00203c10: eor      w8, w8, w26
00203c14: eor      w9, w9, w26
00203c18: add      x10, x10, x21
00203c1c: ldr      x8, [x10, w8, sxtw #3]
00203c20: ldr      x10, [sp, #0x10]
00203c24: eor      x8, x10, x8
00203c28: b        #0x203b04  ; ->0x203b04
00203c2c: add      w9, w20, #1
00203c30: ldr      w8, [x8, w9, sxtw #2]
00203c34: add      x9, sp, #0x20
00203c38: eor      w8, w8, w26
00203c3c: ldr      x8, [x9, w8, sxtw #3]
00203c40: ldr      x9, [sp, #8]
00203c44: ldr      x9, [x9, #0x28]
00203c48: ldur     x10, [x29, #-0x10]
00203c4c: cmp      x9, x10
00203c50: b.ne     #0x203c7c
00203c54: eor      w8, w8, w23
00203c58: and      w0, w8, #1
00203c5c: add      sp, sp, #0x230
00203c60: ldp      x20, x19, [sp, #0x50]
00203c64: ldp      x22, x21, [sp, #0x40]
00203c68: ldp      x24, x23, [sp, #0x30]
00203c6c: ldp      x26, x25, [sp, #0x20]
00203c70: ldp      x28, x27, [sp, #0x10]
00203c74: ldp      x29, x30, [sp], #0x60
00203c78: ret      
00203c7c: bl       #0x6e39b0  ; ->0x6e39b0 plt[6e39b0]
