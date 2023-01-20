import os
from unittest import *
from time import sleep
from pathlib import Path
from zipfile import ZipFile
from subprocess import Popen, DEVNULL

from uniref.mono.injector import WinMonoInjector


class MonoInjectorTest(TestCase):

    injector = None
    zip_path = Path(os.path.abspath(__file__)).parent.parent.parent / "examples/bin/Who is he.zip"

    @classmethod
    def setUpClass(cls) -> None:
        game_dir = cls.zip_path.parent / "Who is he"
        if not game_dir.exists():
            f = ZipFile(str(cls.zip_path))
            for file in f.namelist():
                f.extract(file, str(cls.zip_path.parent))
            f.close()

        Popen(".\\Who is he.exe", shell=True, cwd=str(game_dir), stdout=DEVNULL, stderr=DEVNULL)
        sleep(5)
        cls.injector = WinMonoInjector("Who is he.exe")

    @classmethod
    def tearDownClass(cls) -> None:
        pid = cls.injector.process_id
        del cls.injector
        Popen(f"taskkill /f /pid {pid}", shell=True, stdout=DEVNULL, stderr=DEVNULL).wait()

    def test_1_attach(self) -> None:
        self.assertNotEqual(0, self.injector.h_mono)
        self.assertNotEqual(0, self.injector.root_domain)
        self.assertNotEqual(0, self.injector.attach_thread)
        self.assertFalse(self.injector.use_il2cpp)

    def test_2_enum(self) -> None:
        assemblies = self.injector.enum_assemblies()
        self.assertNotEqual(0, len(assemblies))

        images = self.injector.enum_images()
        self.assertNotEqual(0, len(images))

        image = self.injector.find_image_by_name("Assembly-CSharp")
        classes = self.injector.enum_classes_in_image(image.handle)
        self.assertFalse(any([clazz is None for clazz in classes]))

        fields = self.injector.enum_fields_in_class(classes[1].handle)
        self.assertFalse(any([field is None for field in fields]))

        methods = self.injector.enum_methods_in_class(classes[1].handle)
        self.assertFalse(any([method is None for method in methods]))

    def test_3_image(self) -> None:
        image = self.injector.find_image_by_name("Assembly-CSharp")
        self.assertIsNotNone(image)

        assembly = self.injector.enum_assemblies()[0]
        image = self.injector.get_assembly_image(assembly.handle)
        found = self.injector.get_image_assembly(image.handle)
        self.assertEqual(assembly.handle, found.handle)

        image_name = self.injector.get_image_name(image.handle)
        self.assertGreater(len(image_name), 0)

        image_filename = self.injector.get_image_filename(image.handle)
        self.assertGreater(len(image_filename), 0)

    def test_4_class(self) -> None:
        class_name = "Main"
        class_namespace = "UnityEngine.UmbraModule"
        image = self.injector.find_image_by_name("UnityEngine.UmbraModule")
        klass = self.injector.find_class_in_image(image.handle, class_namespace, class_name)
        self.assertIsNotNone(klass)

        name = self.injector.get_class_name(klass.handle)
        self.assertEqual(name, class_name)

        namespace = self.injector.get_class_namespace(klass.handle)
        self.assertEqual(class_namespace, namespace)

        parent = self.injector.get_parent_class(klass.handle)
        self.assertEqual("MonoBehaviour", parent.name)

        class_image = self.injector.get_class_image(klass.handle)
        self.assertEqual(class_image.handle, image.handle)

        vtable = self.injector.get_class_vtable(klass.handle)
        self.assertIsNotNone(vtable)

        instance = self.injector.guess_class_instance_address(klass.handle)
        self.assertNotEqual(0, len(instance))

    def test_5_field(self) -> None:
        image = self.injector.find_image_by_name("UnityEngine.UmbraModule")
        klass = self.injector.find_class_in_image(image.handle, "UnityEngine.UmbraModule", "Main")
        self.assertIsNotNone(klass)

        field = self.injector.find_field_in_class(klass.handle, "encryptKey")
        self.assertIsNotNone(field)
        self.assertTrue(field.is_static())

        address = self.injector.get_static_field_address(klass.handle, field.handle)
        self.assertNotEqual(0, address)

        value = self.injector.get_static_field_value(klass.handle, field.handle, field.type_name)
        self.assertEqual("test", value)

    def test_6_method(self) -> None:
        image = self.injector.find_image_by_name("UnityEngine.UmbraModule")
        klass = self.injector.find_class_in_image(image.handle, "UnityEngine.UmbraModule", "Main")
        self.assertIsNotNone(klass)

        method = self.injector.find_method_in_class(klass.handle, "Encrypt")
        self.assertIsNotNone(method)
        self.assertFalse(method.is_static())

        name = self.injector.get_method_name(method.handle)
        self.assertEqual("Encrypt", name)

        clazz = self.injector.get_method_class(method.handle)
        self.assertEqual(clazz.handle, klass.handle)

        signature = self.injector.get_method_signature(method.handle)
        self.assertEqual("System.String (string str)", signature)

        address = self.injector.compile_method(method.handle)
        self.assertNotEqual(0, address)


class Il2cppInjectorTest(TestCase):

    injector = None
    zip_path = Path(os.path.abspath(__file__)).parent.parent.parent / "examples/bin/EzGame.zip"

    @classmethod
    def setUpClass(cls) -> None:
        game_dir = cls.zip_path.parent / "Game"
        if not game_dir.exists():
            f = ZipFile(str(cls.zip_path))
            for file in f.namelist():
                f.extract(file, str(cls.zip_path.parent))
            f.close()

        Popen(".\\GameHack.exe", shell=True, cwd=str(game_dir), stdout=DEVNULL, stderr=DEVNULL)
        sleep(3)
        cls.injector = WinMonoInjector("GameHack.exe")

    @classmethod
    def tearDownClass(cls) -> None:
        pid = cls.injector.process_id
        del cls.injector
        Popen(f"taskkill /f /pid {pid}", shell=True, stdout=DEVNULL, stderr=DEVNULL).wait()

    def test_1_attach(self) -> None:
        self.assertNotEqual(0, self.injector.h_mono)
        self.assertNotEqual(0, self.injector.root_domain)
        self.assertNotEqual(0, self.injector.attach_thread)
        self.assertTrue(self.injector.use_il2cpp)

    def test_2_enum(self) -> None:
        assemblies = self.injector.enum_assemblies()
        self.assertNotEqual(0, len(assemblies))

        images = self.injector.enum_images()
        self.assertNotEqual(0, len(images))

        image = self.injector.find_image_by_name("Assembly-CSharp.dll")
        classes = self.injector.enum_classes_in_image(image.handle)
        self.assertFalse(any([clazz is None for clazz in classes]))

        fields = self.injector.enum_fields_in_class(classes[1].handle)
        self.assertFalse(any([field is None for field in fields]))

        methods = self.injector.enum_methods_in_class(classes[1].handle)
        self.assertFalse(any([method is None for method in methods]))

    def test_3_image(self) -> None:
        image = self.injector.find_image_by_name("Assembly-CSharp.dll")
        self.assertIsNotNone(image)

        assembly = self.injector.enum_assemblies()[0]
        image = self.injector.get_assembly_image(assembly.handle)
        found = self.injector.get_image_assembly(image.handle)
        self.assertEqual(assembly.handle, found.handle)

        image_name = self.injector.get_image_name(image.handle)
        self.assertGreater(len(image_name), 0)

        image_filename = self.injector.get_image_filename(image.handle)
        self.assertGreater(len(image_filename), 0)

    def test_4_class(self) -> None:
        class_name = "GetFlag"
        class_namespace = "Platformer.Flag"
        cs = self.injector.find_image_by_name("Assembly-CSharp.dll")
        klass = self.injector.find_class_in_image(cs.handle, class_namespace, class_name)
        self.assertIsNotNone(klass)

        name = self.injector.get_class_name(klass.handle)
        self.assertEqual(name, class_name)

        namespace = self.injector.get_class_namespace(klass.handle)
        self.assertEqual(class_namespace, namespace)

        parent = self.injector.get_parent_class(klass.handle)
        self.assertEqual("Object", parent.name)

        class_image = self.injector.get_class_image(klass.handle)
        self.assertEqual(class_image.handle, cs.handle)

        vtable = self.injector.get_class_vtable(klass.handle)
        self.assertIsNotNone(vtable)

        instance = self.injector.guess_class_instance_address(klass.handle)
        self.assertNotEqual(0, len(instance))

    def test_5_field(self) -> None:
        class_name = "GetFlag"
        class_namespace = "Platformer.Flag"
        cs = self.injector.find_image_by_name("Assembly-CSharp.dll")
        klass = self.injector.find_class_in_image(cs.handle, class_namespace, class_name)
        self.assertIsNotNone(klass)

        field = self.injector.find_field_in_class(klass.handle, "eatCookie")
        self.assertIsNotNone(field)
        self.assertTrue(field.is_static())

        address = self.injector.get_static_field_address(klass.handle, field.handle)
        self.assertEqual(0, address)

        value = self.injector.get_static_field_value(klass.handle, field.handle, field.type_name)
        self.assertFalse(value)

        ret = self.injector.set_static_field_value(klass.handle, field.handle, field.type_name, True)
        self.assertTrue(ret)
        value = self.injector.get_static_field_value(klass.handle, field.handle, field.type_name)
        self.assertTrue(value)

    def test_6_method(self) -> None:
        class_name = "GetFlag"
        class_namespace = "Platformer.Flag"
        cs = self.injector.find_image_by_name("Assembly-CSharp.dll")
        klass = self.injector.find_class_in_image(cs.handle, class_namespace, class_name)
        self.assertIsNotNone(klass)

        method = self.injector.find_method_in_class(klass.handle, "EatTokenUpdateKey")
        self.assertIsNotNone(method)
        self.assertTrue(method.is_static())

        name = self.injector.get_method_name(method.handle)
        self.assertEqual("EatTokenUpdateKey", name)

        clazz = self.injector.get_method_class(method.handle)
        self.assertEqual(clazz.handle, klass.handle)

        signature = self.injector.get_method_signature(method.handle)
        self.assertEqual("System.Void ()", signature)

        address = self.injector.compile_method(method.handle)
        self.assertNotEqual(0, address)
