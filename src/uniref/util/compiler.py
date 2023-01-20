from keystone import *


class X86Compiler:

    def __init__(self, bit_long: int = 64, ATT_syntax: bool = False) -> None:
        if bit_long == 32:
            ks_mode = KS_MODE_32
        elif bit_long == 64:
            ks_mode = KS_MODE_64
        else:
            raise NotImplementedError("Current architecture is not supported")
        self._compiler = Ks(KS_ARCH_X86, ks_mode)
        if ATT_syntax:
            self._compiler.syntax = KS_OPT_SYNTAX_ATT

    def compile(self, code: str, address: int = 0) -> bytes:
        if not isinstance(code, str):
            raise TypeError("code should be str")
        encoding, _ = self._compiler.asm(code, address)
        return bytes(encoding)
