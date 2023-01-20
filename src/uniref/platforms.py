""" This module holds the uniref top-level classes for all supported platforms """

from uniref.mono.component import *
from uniref.mono.injector import WinMonoInjector


class WinUniRef:
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
    def pid(self) -> int:
        """ target process id """
        return self._mono_injector.process_id

    @property
    def injector(self) -> WinMonoInjector:
        """ target process injector """
        return self._mono_injector

    @property
    def process_handle(self) -> int:
        """ target process handle """
        return self._mono_injector.process_handle

    @property
    def mono_module_handle(self) -> int:
        """ target process mono / il2cpp module handle """
        return self._mono_injector.h_mono

    @property
    def root_domain(self) -> int:
        """ target process root application domain """
        return self._mono_injector.root_domain

    def use_il2cpp(self) -> bool:
        """ Check if target process uses the ``IL2CPP`` scripting backend.

        :return: ``False`` if target process uses the ``Mono`` scripting backend, else ``True``.
        """
        return self._mono_injector.use_il2cpp

    def list_assemblies(self) -> List[MonoAssembly]:
        """ List all assemblies in the application. """
        return self._mono_injector.enum_assemblies()

    def get_assembly_image(self, assembly: MonoAssembly) -> MonoImage:
        """ Get the image of the specified assembly. """
        if not isinstance(assembly, MonoAssembly):
            raise TypeError("assembly should be MonoAssembly")
        return self._mono_injector.get_assembly_image(assembly.handle)

    def list_images(self) -> List[MonoImage]:
        """ List all images in the application. """
        return self._mono_injector.enum_images()

    def find_image_by_name(self, image_name: str) -> Optional[MonoImage]:
        """ Find the image by image name.

        :return: ``MonoImage`` instance if image is found, else ``None``.
        """
        if not isinstance(image_name, str):
            raise TypeError("image_name should be str")
        return self._mono_injector.find_image_by_name(image_name)

    def list_classes_in_image(self, image: MonoImage) -> List[MonoClass]:
        """ List all classes in the image. """
        if not isinstance(image, MonoImage):
            raise TypeError("image should be MonoImage")
        return self._mono_injector.enum_classes_in_image(image.handle)

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
            return self._mono_injector.find_class_in_image(image.handle, class_namespace, class_name)
        return None

    def list_fields_in_class(self, klass: MonoClass) -> List[MonoField]:
        """ List all fields in the class. """
        if not isinstance(klass, MonoClass):
            raise TypeError("klass should be MonoClass")
        fields = self._mono_injector.enum_fields_in_class(klass.handle)
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
        field = self._mono_injector.find_field_in_class(klass.handle, field_name)
        if field:
            if klass.instance > 0:
                field.set_instance(klass.instance)
            return field

    def list_methods_in_class(self, klass: MonoClass) -> List[MonoMethod]:
        """ List all methods in the class. """
        if not isinstance(klass, MonoClass):
            raise TypeError("klass should be MonoClass")
        methods = self._mono_injector.enum_methods_in_class(klass.handle)
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
        method = self._mono_injector.find_method_in_class(klass.handle, method_name, param_count)
        if method:
            if klass.instance > 0:
                method.set_instance(klass.instance)
            return method
