#
#       PEDA - Python Exploit Development Assistance for GDB
#
#       Copyright (C) 2012 Long Le Dinh <longld at vnsecurity.net>
#
#       License: see LICENSE file for details
#

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import gdb
from utils import *
import config

class Asm(object):
    """
    Wrapper class for assemble/disassemble using binutils
    """
    def __init__(self):
        pass

    @staticmethod
    def assemble(asmcode, mode=32):
        """
        Assemble ASM instructions
            - asmcode: input ASM instructions, multiple instructions are separated by ";" (String)
            - mode: 32/64 bits assembly

        Returns:
            - bin code (raw bytes)
        """
        asmcode = asmcode.strip('"').strip("'")
        asmcode = asmcode.replace(";", "\n")
        asmcode = decode_string_escape(asmcode)
        asmcode += "\n"
        infd = tmpfile()
        outfd = tmpfile(is_binary_file=True)
        infd.write(asmcode)
        infd.flush()
        syntax = gdb.parameter('disassembly-flavor')
        if syntax == 'intel':
            syntax += ' -mmnemonic=intel -mnaked-reg'
        execute_external_command("%s -msyntax='%s' --%d -o %s %s && %s -O binary -j .text %s %s" %
            (config.AS, syntax, mode, outfd.name, infd.name, config.OBJCOPY, outfd.name, outfd.name))
        infd.close()

        if os.path.exists(outfd.name):
            bincode = outfd.read()
            outfd.close()
            return bincode
        return None

    @staticmethod
    def format_shellcode(buf, mode=32):
        """
        Format raw shellcode to disassembly output display
            "\x6a\x01"  # 0x00000000:    push 0x1
            "\x5b"      # 0x00000002:    pop ebx

        TODO: understand syscall numbers, socket call
        """
        def asm2shellcode(asmcode):
            if not asmcode:
                return ""

            shellcode = []
            pattern = re.compile("^(\s*[0-9a-f]+):\s(([0-9a-f]{2}\s)+)\s\s\s\s+(.*)$")

            for line in asmcode.splitlines():
                m = pattern.match(line)
                if m:
                    (addr, bytes, _, code) = m.groups()
                    sc = '"%s"' % to_hexstr(codecs.decode(bytes.replace(' ', ''), 'hex'))
                    shellcode += [(sc, "0x"+addr.replace(' ', '0'), code)]

            maxlen = max([len(x[0]) for x in shellcode])
            text = ""
            for (sc, addr, code) in shellcode:
                text += "%s # %s:    %s\n" % (sc.ljust(maxlen+1), addr, code)

            return text

        arch = 'i386:x86-64' if mode == 64 else 'i386:x86'
        infd = tmpfile(is_binary_file=True)
        infd.write(buf)
        infd.flush()
        out = execute_external_command("%s -M %s -m %s -b binary -Dz %s" %
			(config.OBJDUMP, gdb.parameter('disassembly-flavor'), arch, infd.name))
        infd.close()
        return asm2shellcode(out)
