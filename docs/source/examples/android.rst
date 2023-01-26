Mono
==================================

test game
------------

该应用是 `Github <https://github.com/d4wu/unity3d-android-reverse-demo/blob/master/game.apk>`_ 上的一个测试应用。

`示例代码1 <https://github.com/in1nit1t/uniref/blob/main/examples/android/mono/test%20game.py>`_ 完成了类方法的 nop
以及修改类静态属性值。


IL2CPP
==================================

Temple Run 2
------------

Google Play 上的应用，您可以通过 `该链接 <https://1drv.ms/u/s!AsGvxndj5W9qhCyopSbnVuZ1iLuP?e=Vhx1de>`_ 进行下载。

`示例代码2 <https://github.com/in1nit1t/uniref/blob/main/examples/android/il2cpp/Temple%20Run%202.py>`_ 完成了类方法的 patch。


Dream Blast
------------

Google Play 上的应用，您可以通过 `这个链接 <https://1drv.ms/u/s!AsGvxndj5W9qhCo6QrWyMr-jrBFG?e=BxkFBl>`_ 进行下载。

`示例代码3 <https://github.com/in1nit1t/uniref/blob/main/examples/android/il2cpp/Dream%20Blast.py>`_ 展示了如何通过类名查找类所属 image：

.. code-block:: python
    :linenos:

    images = ref.list_images()
    for image in images:
        InventoryBase = ref.find_class_in_image(image.name, "DreamBlast.InventoryBase")
        if InventoryBase:
            print("Found class in " + image.name)
            break
