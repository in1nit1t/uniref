""" This module holds the uniref top-level classes for all supported platforms """
import frida.core

from uniref.mono.component import *
from uniref.mono.injector import WinMonoInjector, AndroidMonoInjector


class _UniRef:

    @property
    def injector(self) -> WinMonoInjector:
        """ target process injector """
        return self._mono_injector

    @property
    def pid(self) -> int:
        """ target process id """
        return self.injector.process_id

    @property
    def mono_module_handle(self) -> int:
        """ target process mono / il2cpp module handle """
        return self.injector.h_mono

    @property
    def root_domain(self) -> int:
        """ target process root application domain """
        return self.injector.root_domain

    def use_il2cpp(self) -> bool:
        """ Check if target process uses the ``IL2CPP`` scripting backend.

        :return: ``False`` if target process uses the ``Mono`` scripting backend, else ``True``.
        """
        return self.injector.use_il2cpp

    def list_assemblies(self) -> List[MonoAssembly]:
        """ List all assemblies in the application. """
        return self.injector.enum_assemblies()

    def get_assembly_image(self, assembly: MonoAssembly) -> MonoImage:
        """ Get the image of the specified assembly. """
        if not isinstance(assembly, MonoAssembly):
            raise TypeError("assembly should be MonoAssembly")
        return self.injector.get_assembly_image(assembly.handle)

    def list_images(self) -> List[MonoImage]:
        """ List all images in the application. """
        return self.injector.enum_images()

    def find_image_by_name(self, image_name: str) -> Optional[MonoImage]:
        """ Find the image by image name.

        :return: ``MonoImage`` instance if image is found, else ``None``.
        """
        if not isinstance(image_name, str):
            raise TypeError("image_name should be str")
        return self.injector.find_image_by_name(image_name)

    def list_classes_in_image(self, image: MonoImage) -> List[MonoClass]:
        """ List all classes in the image. """
        if not isinstance(image, MonoImage):
            raise TypeError("image should be MonoImage")
        return self.injector.enum_classes_in_image(image.handle)

    def find_class_in_image(self, image_name: str, class_path: str) -> Optional[MonoClass]:
        """ Find the class in the image.

        Probably the most commonly used method.
        This method looks up class reflection information through
        the given image name and class full path ([namespace].[class name]).

        This method supports resolving the classpath shown in Cheat Engine.
        For **inner** classes, you can concatenate the class names by ``+`` or ``/``.

        Examples:

        >>> ref.find_class_in_image("Assembly-CSharp", "PlayerStats")
        <uniref.mono.component.MonoClass object at 0x0000022F53050CF8>
        >>> ref.find_class_in_image("Assembly-CSharp", "Rewired.UI.ControlMapper.Window+Timer")
        <uniref.mono.component.MonoClass object at 0x0000022F53050C50>
        >>> ref.find_class_in_image("Assembly-CSharp", "MyClass") is None
        True

        :return: ``MonoClass`` instance if class is found, else ``None``.
        """
        if not isinstance(image_name, str):
            raise TypeError("image_name should be str")
        if not isinstance(class_path, str):
            raise TypeError("class_path should be str")
        image = self.find_image_by_name(image_name)
        if image:
            if '.' in class_path:
                dot = class_path.rfind('.')
                class_namespace = class_path[:dot]
                class_name = class_path[dot + 1:]
            else:
                class_namespace = ''
                class_name = class_path
            class_name = class_name.replace('+', '/')
            return self.injector.find_class_in_image(image.handle, class_namespace, class_name)
        return None

    def list_fields_in_class(self, klass: MonoClass) -> List[MonoField]:
        """ List all fields in the class. """
        if not isinstance(klass, MonoClass):
            raise TypeError("klass should be MonoClass")
        fields = self.injector.enum_fields_in_class(klass.handle)
        instance = klass.instance
        if instance > 0:
            for field in fields:
                field.set_instance(instance)
        return fields

    def find_field_in_class(self, klass: MonoClass, field_name: str) -> Optional[MonoField]:
        """ Find the field by its name.

        :return: ``MonoField`` instance if field is found, else ``None``.
        """
        if not isinstance(klass, MonoClass):
            raise TypeError("klass should be MonoClass")
        if not isinstance(field_name, str):
            raise TypeError("field_name should be str")
        field = self.injector.find_field_in_class(klass.handle, field_name)
        if field:
            if klass.instance > 0:
                field.set_instance(klass.instance)
            return field

    def list_methods_in_class(self, klass: MonoClass) -> List[MonoMethod]:
        """ List all methods in the class. """
        if not isinstance(klass, MonoClass):
            raise TypeError("klass should be MonoClass")
        methods = self.injector.enum_methods_in_class(klass.handle)
        instance = klass.instance
        if instance > 0:
            for method in methods:
                method.set_instance(instance)
        return methods

    def find_method_in_class(self, klass: MonoClass, method_name: str, param_count: int = -1) -> Optional[MonoMethod]:
        """ Find the method in the class.

        If there are different overloads of a method in the same class,
        you can distinguish them by the number of parameters. This is what the ``param_count`` means.

        :return: ``MonoMethod`` instance if method is found, else ``None``.
        """
        if not isinstance(klass, MonoClass):
            raise TypeError("klass should be MonoClass")
        if not isinstance(method_name, str):
            raise TypeError("method_name should be str")
        if not isinstance(param_count, int):
            raise TypeError("param_count should be int")
        method = self.injector.find_method_in_class(klass.handle, method_name, param_count)
        if method:
            if klass.instance > 0:
                method.set_instance(klass.instance)
            return method


class WinUniRef(_UniRef):
    """ The uniref top-level class for ``Windows``.

    :param exe_filename: target application exe filename
    :param process_id: process id

    Examples:

    >>> ref = WinUniRef("TheForest.exe")
    >>> ref = WinUniRef(process_id=1234)

    """
    def __init__(self, exe_filename: str = '', process_id: int = 0) -> None:
        if not exe_filename and not process_id:
            raise ValueError("Please specify the exe file name or process id")
        self._mono_injector = WinMonoInjector(exe_filename, process_id)

    @property
    def process_handle(self) -> int:
        """ target process handle """
        return self.injector.process_handle


class AndroidUniRef(_UniRef):
    """ The uniref top-level class for ``Android``.

    :param process_name: the process name of the target application, you can get it by ``frida-ps``
    :param package_name: the package name of the target application
    :param device_id: specify the device id, you can get it by ``adb devices``
    :param spawn: decide whether to create or attach a process when ``package_name`` is given, ``True`` by default

    Examples:

    .. code-block:: python

        # automatically attach the frontmost application & device
        ref = AndroidUniRef()

        # attach the application by its process name (automatically select device)
        ref = AndroidUniRef(process_name="My App")

        # spawn the application by its package name (automatically select device)
        ref = AndroidUniRef(package_name="com.test.my_app")

        # attach the application by its package name (automatically select device)
        ref = AndroidUniRef(package_name="com.test.my_app", spawn=False)

        # attach the application on the specified device
        ref = AndroidUniRef(device_id="12a34b5")
        ref = AndroidUniRef(process_name="My App", device_id="12a34b5")
        ref = AndroidUniRef(package_name="com.test.my_app", device_id="12a34b5")

    """
    def __init__(
        self,
        process_name: Optional[str] = None,
        package_name: Optional[str] = None,
        device_id: Optional[str] = None,
        spawn: bool = True
    ) -> None:
        self._mono_injector = AndroidMonoInjector(process_name, package_name, device_id, spawn)

    def execute_js(self, js_code: str, on_message_callback: Optional[Callable] = None) -> frida.core.Script:
        """ inject javascript through ``Frida``.

        :param js_code: javascript code
        :param on_message_callback: callback in the form of **on_message(message, data)**
        :return: ``frida.core.Script`` instance
        """
        return self._mono_injector.execute_js(js_code, on_message_callback)
