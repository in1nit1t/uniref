=================================
uniref
=================================

uniref 是一个辅助分析 Unity 应用的框架。它可以帮助您获取 Unity 应用中的类、方法、成员变量等的反射信息，让您实时地查看和操作它们。
您可以将您的一些分析结果借助本框架转化为少量的 Python 代码，在一定程度上方便您进行 Unity 应用的插件开发。

uniref 同时支持 ``Mono`` 和 ``IL2CPP`` 两种脚本后端（Unity scripting backend）。

.. note::
    目前 uniref 支持分析 Windows x86 64 位操作系统上运行的 32 / 64 位 Unity 应用


安装
------------

uniref 需要 Python 3.7+（64 位）的运行环境，您可以通过 pip 完成安装::

    pip install -U uniref


示例
------------

下方给出了一段使用 uniref 框架完成的代码，其实现了修改鹅鸭杀游戏人物移速的效果。
您可以在游戏的 **教程关卡** 中运行这段代码 [1]_ 来体验 uniref。

.. attention::
    请勿在多人模式下使用，影响其他玩家游戏体验


.. code-block:: python
    :linenos:

    from uniref import WinUniRef

    # 指定待分析进程
    ref = WinUniRef("Goose Goose Duck.exe")

    # 查找类
    class_path = "Handlers.GameHandlers.PlayerHandlers.LocalPlayer"
    local_player = ref.find_class_in_image("Assembly-CSharp.dll", class_path)

    # 查找类中的成员变量，并打印其值
    movement_speed = local_player.find_field("movementSpeed")
    print(f"default speed: {movement_speed.value}")

    # 修改成员变量的值
    movement_speed.value = 20.0


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


-----

.. [1] 如果目标进程是以管理员权限启动的，那么请保证本框架运行在管理员权限下。即必要时，需要使用管理员权限运行 Python。