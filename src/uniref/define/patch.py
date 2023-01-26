class NativePatch:
    """ This class's instance is returned by calling ``MonoMethod.native_patch`` and ``MonoMethod.native_nop``.
    You can use it to manage the patch. """

    def __init__(self, injector: object, address: int, enabled_code: bytes, disabled_code: bytes) -> None:
        self._address = address
        self._injector = injector
        self._enabled_code = enabled_code
        self._disabled_code = disabled_code

        self._enable = False
        self._try_patch()

    def _try_patch(self):
        disabled_code_len = len(self._disabled_code)
        while len(self._enabled_code) < disabled_code_len:
            self._enabled_code += b'\x90'

        if len(self._enabled_code) > disabled_code_len:
            raise NotImplementedError
        self.enable()

    @property
    def address(self) -> int:
        """ patch address """
        return self._address

    def is_enabled(self) -> bool:
        """ Check if the patch is enabled. """
        return self._enable

    def enable(self) -> None:
        """ Enable the patch. """
        if self._enable:
            return

        enabled_code_len = len(self._enabled_code)

        old_protect = self._injector.mem_set_protect(self._address, enabled_code_len)
        self._injector.mem_write_bytes(self._address, self._enabled_code)
        if isinstance(old_protect, str):
            self._injector.mem_set_protect(self._address, enabled_code_len, old_protect)

        self._enable = True

    def disable(self) -> None:
        """ Disable the patch. """
        if not self._enable:
            return

        disabled_code_len = len(self._disabled_code)

        old_protect = self._injector.mem_set_protect(self._address, disabled_code_len)
        self._injector.mem_write_bytes(self._address, self._disabled_code)
        if isinstance(old_protect, str):
            self._injector.mem_set_protect(self._address, disabled_code_len, old_protect)

        self._enable = False
