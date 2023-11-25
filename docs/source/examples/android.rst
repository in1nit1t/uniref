Mono
==================================

test game
------------

该应用是 `Github <https://github.com/d4wu/unity3d-android-reverse-demo/blob/master/game.apk>`_ 上的一个测试应用。

`示例代码1 <https://github.com/in1nit1t/uniref/blob/main/examples/android/mono/test%20game.py>`_ 完成了类方法的 nop
以及修改类静态属性值。


IL2CPP
==================================

Soul Knight
------------

您可以通过 `该链接 <http://www.chillyroom.com>`_ 进行下载。

`示例代码2 <https://github.com/in1nit1t/uniref/blob/main/examples/android/il2cpp/Soul%20Knight.py>`_ 完成了类方法的 patch。


Temple Run 2
------------

Google Play 上的应用，您可以通过 `该链接 <https://1drv.ms/u/s!AsGvxndj5W9qhCyopSbnVuZ1iLuP?e=Vhx1de>`_ 进行下载。

`示例代码3 <https://github.com/in1nit1t/uniref/blob/main/examples/android/il2cpp/Temple%20Run%202.py>`_ 展示了如何生成与
IL2CPPDumper 类似的 dump.cs 文件以及执行 frida 脚本。

通过 ``MonoImage`` 或 ``MonoAssembly`` 类的 ``dump_declaration`` 方法可以完成一个程序集的 dump.cs 文件生成：

.. code-block:: python
    :linenos:

    image = ref.find_image_by_name("System.Data.dll")
    image.dump_declaration("system_data_dump.cs", True) // True - show the progress bar

产生的部分文件内容展示如下：

.. code-block:: csharp
    :linenos:

    // Namespace: System.Data
    class ConstraintConverter : ExpandableObjectConverter
    {
        // Methods

        // Offset: 0x64eb83c
        public System.Void .ctor() { }

        // Offset: 0x64eb844
        public virtual System.Boolean CanConvertTo(System.ComponentModel.ITypeDescriptorContext context, System.Type destinationType) { }

        // Offset: 0x64eb90c
        public virtual System.Object ConvertTo(System.ComponentModel.ITypeDescriptorContext context, System.Globalization.CultureInfo culture, System.Object value, System.Type destinationType) { }
    }

    // Namespace: System.Data
    class ConstraintEnumerator : Object
    {
        // Fields
        private System.Collections.IEnumerator _tables; // 0x10
        private System.Collections.IEnumerator _constraints; // 0x18
        private System.Data.Constraint _currentObject; // 0x20

        // Methods

        // Offset: 0x64ec388
        public System.Void .ctor(System.Data.DataSet dataSet) { }

        // Offset: 0x64ec3f0
        public System.Boolean GetNext() { }

        // Offset: 0x64ec71c
        public System.Data.Constraint GetConstraint() { }

        // Offset: 0x64ec724
        public virtual System.Boolean IsValidCandidate(System.Data.Constraint constraint) { }

        // Offset: 0x64ec72c
        public System.Data.Constraint get_CurrentObject() { }
    }

通过 ``AndroidUniRef`` 类的 ``execute_js`` 方法可以完成 frida js 脚本的执行，使用方法与 frida 的 python 绑定类似：

.. code-block:: python
    :linenos:

    def on_message(msg, data):
        if msg["type"] == "send":
            print(msg["payload"])

    attr = ref.find_class_in_image("Assembly-CSharp.dll", "RoleAttributePlayer")
    get_skill_ready = attr.find_method("get_skill_ready")

    code = """
    Java.perform(function () {
        Interceptor.attach(ADDRESS, {
            onEnter: function(args) {
                send("function called.")
            },
            onLeave: function(retval) {
                retval.replace(1);
            }
        })
    });""".replace("ADDRESS", f"ptr({hex(get_skill_ready.address)})")
    ref.execute_js(code, on_message)


Dream Blast
------------

Google Play 上的应用，您可以通过 `这个链接 <https://1drv.ms/u/s!AsGvxndj5W9qhCo6QrWyMr-jrBFG?e=BxkFBl>`_ 进行下载。

`示例代码4 <https://github.com/in1nit1t/uniref/blob/main/examples/android/il2cpp/Dream%20Blast.py>`_ 展示了如何通过类名查找类所属 image：

.. code-block:: python
    :linenos:

    images = ref.list_images()
    for image in images:
        InventoryBase = ref.find_class_in_image(image.name, "DreamBlast.InventoryBase")
        if InventoryBase:
            print("Found class in " + image.name)
            break
