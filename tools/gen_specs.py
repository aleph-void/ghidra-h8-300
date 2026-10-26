#!/usr/bin/env python3
"""Write the .ldefs, .pspec, .cspec and .opinion files for the H8 languages."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, '..', 'data', 'languages')

# id, processor, size, variant, sla, pspec, cspec, description, gnu machine
LANGS = [
    ('h8_300:BE:16:normal', 'H8/300', 16, 'normal', 'h8_300', 'h8_300', 'h8_300',
     'Hitachi H8/300', 'h8300'),
    ('h8_300l:BE:16:normal', 'H8/300L', 16, 'normal', 'h8_300l', 'h8_300l', 'h8_300',
     'Hitachi H8/300L (H8/300 without the E-clock MOVFPE/MOVTPE)', 'h8300'),
    ('h8_300h:BE:32:normal', 'H8/300H', 32, 'normal', 'h8_300h_normal', 'h8_normal', 'h8_normal',
     'Hitachi H8/300H, normal mode (64-Kbyte address space)', 'h8300hn'),
    ('h8_300h:BE:32:advanced', 'H8/300H', 32, 'advanced', 'h8_300h_advanced', 'h8_advanced24', 'h8_advanced24',
     'Hitachi H8/300H, advanced mode (16-Mbyte address space)', 'h8300h'),
    ('h8s:BE:32:normal', 'H8S', 32, 'normal', 'h8s_normal', 'h8_normal', 'h8_normal',
     'Renesas H8S/2000 and H8S/2600 (MAC), normal mode', 'h8300sn'),
    ('h8s:BE:32:advanced', 'H8S', 32, 'advanced', 'h8s_advanced', 'h8_advanced24', 'h8_advanced24',
     'Renesas H8S/2000 and H8S/2600 (MAC), advanced mode (16-Mbyte address space)', 'h8300s'),
    ('h8sx:BE:32:normal', 'H8SX', 32, 'normal', 'h8sx_normal', 'h8sx_normal', 'h8_normal',
     'Renesas H8SX, normal mode (64-Kbyte address space)', 'h8300sxn'),
    ('h8sx:BE:32:middle', 'H8SX', 32, 'middle', 'h8sx_middle', 'h8sx_middle', 'h8_middle',
     'Renesas H8SX, middle mode (16-Mbyte program area, 64-Kbyte data area)', 'h8300sx'),
    ('h8sx:BE:32:advanced', 'H8SX', 32, 'advanced', 'h8sx_advanced', 'h8sx_advanced', 'h8_advanced',
     'Renesas H8SX, advanced mode (16-Mbyte program area, 4-Gbyte data area)', 'h8300sx'),
    ('h8sx:BE:32:maximum', 'H8SX', 32, 'maximum', 'h8sx_maximum', 'h8sx_maximum', 'h8_advanced',
     'Renesas H8SX, maximum mode (4-Gbyte address space)', 'h8300sx'),
]


def ldefs():
    out = ['<?xml version="1.0" encoding="UTF-8"?>', '<language_definitions>']
    for lid, proc, size, var, sla, pspec, cspec, desc, gnu in LANGS:
        out.append('''  <language processor="%s" endian="big" size="%d" variant="%s" version="1.0"
            slafile="%s.sla" processorspec="%s.pspec" id="%s">
    <description>%s</description>
    <compiler name="GCC" spec="%s.cspec" id="default"/>
    <external_name tool="gnu" name="%s"/>
    <external_name tool="DWARF.register.mapping.file" name="%s.dwarf"/>
  </language>''' % (proc, size, var, sla, pspec, lid, desc, cspec, gnu, cspec))
    out.append('</language_definitions>')
    return '\n'.join(out) + '\n'


# vector tables: normal mode one word per vector, other modes one longword
def pspec(name):
    core300 = name in ('h8_300', 'h8_300l')
    normal = name in ('h8_300', 'h8_300l', 'h8_normal', 'h8sx_normal')
    sx = name.startswith('h8sx')
    regs = ['r%d' % i for i in range(8)] if core300 else ['er%d' % i for i in range(8)]
    out = ['<?xml version="1.0" encoding="UTF-8"?>', '<processor_spec>',
           '  <programcounter register="pc"/>']
    if sx:
        out.append('''  <!-- @aa:8 operands are SBR-relative; SBR resets to H'FFFFFF00 -->
  <context_data>
    <tracked_set space="ram">
      <set name="sbr" val="0xffffff00"/>
    </tracked_set>
  </context_data>''')
    out.append('  <register_data>')
    for r in ('I', 'UI', 'H', 'U', 'N', 'Z', 'V', 'C'):
        out.append('    <register name="%s" group="CCR"/>' % r)
    if not core300:
        out.append('    <register name="macv" hidden="true"/>')
    out.append('  </register_data>')
    out.append('  <default_symbols>')
    if normal:
        out.append('    <symbol name="RESET" address="ram:0x0000" type="code_ptr" entry="true"/>')
    else:
        out.append('    <symbol name="RESET" address="ram:0x0000" type="code_ptr" entry="true"/>')
    out.append('  </default_symbols>')
    out.append('</processor_spec>')
    return '\n'.join(out) + '\n'


def cspec(name):
    core300 = name == 'h8_300'
    normal = name in ('h8_300', 'h8_normal')
    ptr = 2 if normal else 4
    # the decompiler's stack offsets must fit the address space: in 16-bit spaces (normal mode,
    # and H8SX middle mode whose data addresses are 16 bits sign-extended) the stack pointer is
    # R7, in the 24-bit H8/300H/H8S advanced space the low 24 bits of ER7
    sp = {'h8_300': 'r7', 'h8_normal': 'r7', 'h8_middle': 'r7', 'h8_advanced24': 'sp24'}.get(name, 'er7')
    R = (lambda i: 'r%d' % i) if core300 else (lambda i: 'er%d' % i)
    regsize = 2 if core300 else 4
    out = ['<?xml version="1.0" encoding="UTF-8"?>', '<compiler_spec>', '  <data_organization>',
           '    <absolute_max_alignment value="0"/>',
           '    <machine_alignment value="2"/>',
           '    <default_alignment value="1"/>',
           '    <default_pointer_alignment value="2"/>',
           '    <pointer_size value="%d"/>' % ptr,
           '    <short_size value="2"/>',
           '    <integer_size value="2"/>',
           '    <long_size value="4"/>',
           '    <long_long_size value="8"/>',
           '    <float_size value="4"/>',
           '    <double_size value="4"/>',
           '    <long_double_size value="4"/>',
           '    <size_alignment_map>',
           '      <entry size="1" alignment="1"/>',
           '      <entry size="2" alignment="2"/>',
           '      <entry size="4" alignment="2"/>',
           '      <entry size="8" alignment="2"/>',
           '    </size_alignment_map>',
           '  </data_organization>',
           '  <global>', '    <range space="ram"/>', '  </global>',
           '  <stackpointer register="%s" space="ram"/>' % sp,
           '  <returnaddress>', '    <varnode space="stack" offset="0" size="%d"/>' % ptr, '  </returnaddress>']
    # GCC: the first three arguments in r0-r2 (er0-er2), return value in r0/er0 (and r1/er1)
    out.append('  <default_proto>')
    out.append('    <prototype name="__stdcall" extrapop="%d" stackshift="%d">' % (ptr, ptr))
    out.append('      <input>')
    for i in range(3):
        out.append('        <pentry minsize="1" maxsize="%d"><register name="%s"/></pentry>' % (regsize, R(i)))
    out.append('        <pentry minsize="1" maxsize="500" align="2"><addr offset="%d" space="stack"/></pentry>' % ptr)
    out.append('      </input>')
    out.append('      <output>')
    out.append('        <pentry minsize="1" maxsize="%d"><register name="%s"/></pentry>' % (regsize, R(0)))
    if core300:
        out.append('        <pentry minsize="3" maxsize="4"><addr space="join" piece1="r0" piece2="r1"/></pentry>')
    else:
        out.append('        <pentry minsize="5" maxsize="8"><addr space="join" piece1="er0" piece2="er1"/></pentry>')
    out.append('      </output>')
    out.append('      <unaffected>')
    for i in (4, 5, 6):
        out.append('        <register name="%s"/>' % R(i))
    out.append('        <register name="%s"/>' % sp)
    out.append('      </unaffected>')
    out.append('      <killedbycall>')
    for i in (0, 1, 2, 3):
        out.append('        <register name="%s"/>' % R(i))
    out.append('      </killedbycall>')
    out.append('    </prototype>')
    out.append('  </default_proto>')
    if not core300:
        # Renesas H8S/H8/300 C/C++ compiler: two (or three) register parameters, er0/er1
        for nm, n in (('__regparam2', 2), ('__regparam3', 3)):
            out.append('  <prototype name="%s" extrapop="%d" stackshift="%d">' % (nm, ptr, ptr))
            out.append('    <input>')
            for i in range(n):
                out.append('      <pentry minsize="1" maxsize="4"><register name="er%d"/></pentry>' % i)
            out.append('      <pentry minsize="1" maxsize="500" align="2"><addr offset="%d" space="stack"/></pentry>' % ptr)
            out.append('    </input>')
            out.append('    <output>')
            out.append('      <pentry minsize="1" maxsize="4"><register name="er0"/></pentry>')
            out.append('    </output>')
            out.append('    <unaffected>')
            for i in range(n, 7):
                out.append('      <register name="er%d"/>' % i)
            out.append('      <register name="er7"/>')
            out.append('    </unaffected>')
            out.append('  </prototype>')
    out.append('</compiler_spec>')
    return '\n'.join(out) + '\n'


def dwarf(name):
    # GCC numbers r0-r7 (er0-er7) as DWARF registers 0-7; the CFA is SP + the return-address size
    core300 = name == 'h8_300'
    cfa = 2 if name in ('h8_300', 'h8_normal') else 4
    out = ['<dwarf>', '  <register_mappings>']
    for i in range(8):
        out.append('    <register_mapping dwarf="%d" ghidra="%s%d"%s/>'
                   % (i, 'r' if core300 else 'er', i, ' stackpointer="true"' if i == 7 else ''))
    out.append('  </register_mappings>')
    out.append('  <call_frame_cfa value="%d"/>' % cfa)
    out.append('</dwarf>')
    return '\n'.join(out) + '\n'


def opinion():
    # EM_H8_300 = 46.  GNU tools record the CPU in e_flags bits 16-23 (E_H8_MACH):
    # 0x80 H8/300, 0x81 H8/300H, 0x82 H8S, 0x83 H8/300H normal, 0x84 H8S normal,
    # 0x85 H8SX, 0x86 H8SX normal (checked with h8300-elf-gcc -mh/-ms/-msx/-mn and gas).
    rows = [('0x80', 'H8/300', 16, 'normal'), ('0x81', 'H8/300H', 32, 'advanced'),
            ('0x82', 'H8S', 32, 'advanced'), ('0x83', 'H8/300H', 32, 'normal'),
            ('0x84', 'H8S', 32, 'normal'), ('0x85', 'H8SX', 32, 'advanced'),
            ('0x86', 'H8SX', 32, 'normal')]
    out = ['<opinions>', '  <constraint loader="Executable and Linking Format (ELF)" compilerSpecID="default">']
    for flags, proc, size, var in rows:
        bits = format(int(flags, 16), '08b')
        sec = '0b.... .... %s %s .... .... .... ....' % (bits[:4], bits[4:])
        out.append('    <constraint primary="46" processor="%s" endian="big" size="%d" variant="%s" secondary="%s"/>'
                   % (proc, size, var, sec))
    out.append('  </constraint>')
    out.append('</opinions>')
    return '\n'.join(out) + '\n'


def main():
    open(os.path.join(OUT, 'h8.ldefs'), 'w').write(ldefs())
    for p in ('h8_300', 'h8_300l', 'h8_normal', 'h8_advanced24', 'h8sx_normal', 'h8sx_middle',
              'h8sx_advanced', 'h8sx_maximum'):
        open(os.path.join(OUT, p + '.pspec'), 'w').write(pspec(p))
    for c in ('h8_300', 'h8_normal', 'h8_middle', 'h8_advanced24', 'h8_advanced'):
        open(os.path.join(OUT, c + '.cspec'), 'w').write(cspec(c))
    open(os.path.join(OUT, 'h8.opinion'), 'w').write(opinion())
    for c in ('h8_300', 'h8_normal', 'h8_middle', 'h8_advanced24', 'h8_advanced'):
        open(os.path.join(OUT, c + '.dwarf'), 'w').write(dwarf(c))


if __name__ == '__main__':
    main()
