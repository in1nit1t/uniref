from typing import *
from capstone import *


class X86Disasm:

    def __init__(self, bit_long: int = 64, ATT_syntax: bool = False) -> None:
        if bit_long == 32:
            cs_mode = CS_MODE_32
        elif bit_long == 64:
            cs_mode = CS_MODE_64
        else:
            raise NotImplementedError("Current architecture is not supported")
        self._disasm = Cs(CS_ARCH_X86, cs_mode)
        self._disasm.detail = True
        if ATT_syntax:
            self._disasm.syntax = CS_OPT_SYNTAX_ATT

    def disassemble(self, code: bytes, base_address: int = 0, count: int = 0) -> List[CsInsn]:
        return [ins for ins in self._disasm.disasm(code, base_address, count)]
