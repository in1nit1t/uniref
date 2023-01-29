=================================
uniref
=================================

uniref 是一个辅助分析 Unity 应用的框架。它可以帮助您获取 Unity 应用中的类、方法、成员变量等的反射信息，让您实时地查看和操作它们。
您可以将您的一些分析结果借助本框架转化为少量的 Python 代码，在一定程度上方便您进行 Unity 应用的插件开发。

uniref 同时支持 ``Mono`` 和 ``IL2CPP`` 两种脚本后端（Unity scripting backend）。

.. note::
    目前 uniref 支持分析:

    - Windows x86 64 位操作系统上运行的 32 / 64 位 Unity 应用
    - Android ARM 架构上运行的 32 / 64 位 Unity 应用


安装
------------

uniref 需要 Python 3.7+（64 位）的运行环境，您可以通过 pip 完成安装::

    pip install -U uniref


示例
------------

下方给出了一段使用 uniref 框架完成的代码，其解决了 MRCTF2021 的一道逆向赛题。

.. code-block:: python
    :linenos:

    from uniref import WinUniRef

    ref = WinUniRef("GameHack.exe")
    class_GetFlag = ref.find_class_in_image("Assembly-CSharp.dll", "Platformer.Flag.GetFlag")
    class_GetFlag.find_field("goHome").value = True
    class_GetFlag.find_field("findAlien").value = True
    class_GetFlag.find_field("eatCookie").value = True

    method_EatTokenUpdateKey = class_GetFlag.find_method("EatTokenUpdateKey")
    for i in range(105):
        method_EatTokenUpdateKey()


运行
------------

对于 Windows 应用（exe），直接运行 Python 脚本即可。

.. note::
    如果目标进程是以管理员权限启动的，那么请保证本框架运行在管理员权限下。即必要时，需要使用管理员权限运行 Python。


对于 Android 应用（apk），需要保证 frida 已可以在您的设备上工作。
最常用的方法是在设备上运行 frida-server，其他方式详见 `frida官方文档 <https://frida.re/docs/modes/>`_ 。


.. toctree::
    :hidden:
    :titlesonly:

    about


.. toctree::
    :hidden:
    :caption: 用户手册

    tutorial
    examples/index
    modules/index


.. toctree::
    :hidden:
    :caption: 项目链接

    GitHub <https://github.com/in1nit1t/uniref>
    PyPI <https://pypi.org/project/uniref/>
