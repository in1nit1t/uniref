Mono
==================================

The Forest
------------

The Forest 是 Steam 平台的一款生存类游戏，
`示例代码1 <https://github.com/in1nit1t/uniref/blob/main/examples/windows/mono/The%20Forest.py>`_
中实现了如下几个功能：

- 将玩家初始血量调满

- 玩家拥有无限精力，跑步挥砍不消耗精力

- 修改玩家奔跑速度为原速的 5 倍

- 建筑物不需要材料直接完成建造


首先是修改玩家血量的实现，在 Assembly-CSharp 的 PlayerStats 类中有一个成员变量（以下简称属性）名为 ``Health``。
因为 ``Health`` 不是静态变量，所以需要先在内存中找到 PlayerStats
类的实例地址，这里我们通过同类下的另一个属性 ``Energy`` 的值来定位类实例。

因为每次游戏开局玩家的外圈精力条（精力上限）都是 10.0（float 类型），所以在通过
``guess_instance_address`` 方法取得所有可能的实例地址列表后，将它们逐一设置为 ``Energy``
属性的类实例，通过 ``.value`` 访问其值，借此筛选出满足条件的实例地址。

以上描述反映到如下代码：

.. code-block:: python
    :linenos:

    PlayerStats = ref.find_class_in_image("Assembly-CSharp", "PlayerStats")
    field_energy = PlayerStats.find_field("Energy")

    # 通过条件筛选出类实例
    found = False
    addresses = PlayerStats.guess_instance_address()
    for address in addresses:
        field_energy.instance = address
        if field_energy.value == 10.0:
            PlayerStats.instance = address
            found = True
    assert found, "Can't find PlayerStats instance"

在设置好 PlayerStats 类的实例后，通过 ``find_field`` 拿到 ``Health`` 属性，
它会自动继承所属类的实例地址，无需再去设置该属性的 instance 属性了，
直接通过 ``x.value = y`` 或 ``x.set_value(y)`` 就可以设置该属性的值。

.. code-block:: python
    :linenos:

    field_health = PlayerStats.find_field("Health")
    field_health.value = 100.0


然后是让玩家具有无限精力。基于事先的逆向分析，我们可以知道对以下三处进行 nop 可以达到精力值与精力上限不减的效果：

- FirstPersonCharacter 类 ``HandleRunningStaminaAndSpeed`` 方法偏移 0x112 处 8 字节
- PlayerStats 类 ``setStamina`` 方法偏移 0x2e 处 8 字节
- PlayerStats 类 ``Update`` 方法 0x382 处 6 字节

这些都可以通过 uniref 来完成：

.. code-block:: python
    :linenos:

    field_health = PlayerStats.find_field("Health")
    field_health.value = 100.0

    FirstPersonCharacter = ref.find_class_in_image("Assembly-CSharp", "FirstPersonCharacter")

    HandleRunningStaminaAndSpeed = FirstPersonCharacter.find_method("HandleRunningStaminaAndSpeed")
    patch1 = HandleRunningStaminaAndSpeed.native_nop(0x112, 8)

    PlayerStats = ref.find_class_in_image("Assembly-CSharp", "PlayerStats")

    setStamina = PlayerStats.find_method("setStamina")
    patch2 = setStamina.native_nop(0x2e, 8)

    Update = PlayerStats.find_method("Update")
    patch3 = Update.native_nop(0x382, 6)


修改奔跑速度部分的代码展示了如何在 uniref 中使用自己书写的汇编进行 patch：

.. code-block:: python
    :linenos:

    FirstPersonCharacter = ref.find_class_in_image("Assembly-CSharp", "FirstPersonCharacter")

    HandleRunningStaminaAndSpeed = FirstPersonCharacter.find_method("HandleRunningStaminaAndSpeed")
    new_run_speed = ref.injector.new_double(40.0)

    code = f"movsd xmm0, [{hex(new_run_speed.address)}]             \n" \
           f"jmp {hex(HandleRunningStaminaAndSpeed.address + 0x34e)}  "
    patch = HandleRunningStaminaAndSpeed.native_patch(0x167, code)


最后是超级建造功能的实现，写法同样是找到方法后对其中的代码进行 patch 和 nop：

.. code-block:: python
    :linenos:

    Craft_Structure = ref.find_class_in_image("Assembly-CSharp", "TheForest.Buildings.Creation.Craft_Structure")

    CheckNeeded = Craft_Structure.find_method("CheckNeeded")
    patch1 = CheckNeeded.native_patch(0xF, b"\xEB\x70")

    Initialize = Craft_Structure.find_method("Initialize")
    patch2 = Initialize.native_nop(0x183, 3)


SCTF2019 - Who is he
------------------------

一道比赛的赛题，部分 wp 参考：

- `SCTF2019 Writeup by De1ta <https://www.anquanke.com/post/id/181019#h3-15>`_
- `Who is he 题解 by mortal15 <https://blog.csdn.net/a5555678744/article/details/118371570>`_

`示例代码2 <https://github.com/in1nit1t/uniref/blob/main/examples/windows/mono/SCTF2019%20-%20Who%20is%20he.py>`_
展示了如何用 uniref 定位真实的 ``EncryptData`` 与 ``encryptKey`` 属性并获取它们的值。您可以通过如下代码来推测哪个实例地址才是正确的：


.. code-block:: python
    :linenos:

    ref = WinUniRef("Who is he.exe")
    clazz = ref.find_class_in_image("UnityEngine.UmbraModule", "UnityEngine.UmbraModule.Main")

    encrypt_data = clazz.find_field("EncryptData")
    addresses = clazz.guess_instance_address()
    for address in addresses:
        encrypt_data.set_instance(address)
        cipher = encrypt_data.value
        if isinstance(cipher, str):
            print(hex(address), cipher)


Mirror
------------

Mirror 是 Steam 平台的一款三消游戏，该应用进程为 32 位。
`示例代码3 <https://github.com/in1nit1t/uniref/blob/main/examples/windows/mono/Mirror.py>`_
的 ``same_name_function_sample`` 函数展示了如何区分同类下的同名、同参数个数方法，以及如何调用方法。

首先找到 Enemy 类实例：

.. code-block:: python
    :linenos:

    Enemy = ref.find_class_in_image("Assembly-CSharp", "Enemy")
    instances = Enemy.guess_instance_address()

    CurHP = Enemy.find_field("<CurHP>k__BackingField")
    for instance in instances:
        CurHP.instance = instance
        if CurHP.value == 4000:
            Enemy.instance = instance
            break

Enemy 类中的 ``BrokeCloth`` 方法有两个重载，且它们的参数个数都是 1。
我们可以列出该类中的所有方法，再通过方法签名来找到目标方法：

.. code-block:: python
    :linenos:

    methods = Enemy.list_methods()
    for method in methods:
        if method.name == "BrokeCloth" and method.signature == "System.Void (int level)":
            method.instance = instance

经过逆向分析，可以得知该函数需要一个 int 参数且函数调用约定类似 ``cdecl``，故可按如下方式调用::

    method(args=(1,), call_type=CALL_TYPE_CDECL)

注：只有 32 位的应用才需要指定函数调用约定


IL2CPP
==================================

Goose Goose Duck
------------------------

Goose Goose Duck 是 Steam 平台的一款狼人杀游戏，
`示例代码4 <https://github.com/in1nit1t/uniref/blob/main/examples/windows/il2cpp/Goose%20Goose%20Duck.py>`_
中的 ``show_my_position`` 函数展示了如何通过事先分析的多级指针找到类实例。

WinMonoInjector 中提供了 ``get_module_base`` 方法，用于获取目标进程中指定模块的基址，可以结合
``mem_read_multilevel_pointer`` 和偏移数组来读取类实例，代码如下：

.. code-block:: python
    :linenos:

    game_assembly_base = ref.injector.get_module_base("GameAssembly.dll")

    LocalPlayer = ref.find_class_in_image("Assembly-CSharp.dll", "Handlers.GameHandlers.PlayerHandlers.LocalPlayer")
    local_player_instance = ref.injector.mem_read_multilevel_pointer(game_assembly_base, [0x3BA7B38, 0xB8, 0])
    assert local_player_instance > 0, "Error multilevel pointer offsets due to game update"
    LocalPlayer.instance = local_player_instance


MRCTF2021 - EzGame
------------------------

一道比赛的赛题，部分 wp 参考：

- `MRCTF2021 Reverse官方wp <https://www.anquanke.com/post/id/237793#h2-1>`_
- `MRCTF2021逆向题解 by Bxb0 <https://bbs.kanxue.com/thread-267013.htm#msg_header_h3_3>`_

`示例代码5 <https://github.com/in1nit1t/uniref/blob/main/examples/windows/il2cpp/MRCTF2021%20-%20EzGame.py>`_
展示了如何用少量 Python 代码实现官方 wp 的解法。

在获取到关键类 GetFlag 后，直接通过 ``x.value = y`` 的形式来设置该类下的
``goHome``, ``findAlien``, ``eatCookie`` 三个静态变量：

.. code-block:: python
    :linenos:

    ref = WinUniRef("GameHack.exe")
    class_GetFlag = ref.find_class_in_image("Assembly-CSharp.dll", "Platformer.Flag.GetFlag")
    class_GetFlag.find_field("goHome").value = True
    class_GetFlag.find_field("findAlien").value = True
    class_GetFlag.find_field("eatCookie").value = True

再获取 ``EatTokenUpdateKey`` 静态方法并直接调用：

.. code-block:: python
    :linenos:

    method_EatTokenUpdateKey = class_GetFlag.find_method("EatTokenUpdateKey")
    for i in range(105):
        method_EatTokenUpdateKey()

您可以通过 ``field.is_static()`` 与 ``method.is_static()`` 来判断属性和方法是否是静态的。
对于静态的属性，无需设置类实例即可查看/修改值；对于静态方法，无需设置类实例即可调用。
