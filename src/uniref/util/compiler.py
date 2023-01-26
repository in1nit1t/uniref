from keystone import *
from abc import ABCMeta


class _Compiler(metaclass=ABCMeta):

    @property
    def compiler(self):
        raise NotImplementedError

    def compile(self, code: str, address: int = 0) -> bytes:
        if not isinstance(code, str):
            raise TypeError("code should be str")
        encoding, _ = self.compiler.asm(code, address)
        return bytes(encoding)


class X86Compiler(_Compiler):

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

    @property
    def compiler(self):
        return self._compiler


class ArmCompiler(_Compiler):

    def __init__(self, bit_long: int = 64, thumb: bool = False) -> None:
        if bit_long == 32:
            self._compiler = Ks(KS_ARCH_ARM, KS_MODE_THUMB if thumb else KS_MODE_ARM)
        elif bit_long == 64:
            self._compiler = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        else:
            raise NotImplementedError("Current architecture is not supported")

    @property
    def compiler(self):
        return self._compiler
