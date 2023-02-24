# uniref

[中文](https://github.com/in1nit1t/uniref/blob/main/README.md) | English

`uniref` is a framework to assist in analyzing Unity applications. It can help you obtain reflection information of classes, methods, fields, etc. in Unity applications, allowing you to view and manipulate them in real time.

You can use this framework to convert some of your analysis results into Python code, which is convenient for you to develop plug-ins for Unity applications.

## Features

- Support for obtaining reflection information through symbols
- Support real-time acquisition and modification of class attribute values
- Support real-time acquisition and modification of class method implementation and call class method
- Modifications are done in memory without modifying the source file
- Bypass some code protection mechanisms (compression, encryption, etc.) to avoid tedious reverse engineering
- Supports analysis of `Mono` and `IL2CPP` two scripting backends
- Supports profiling 32/64-bit Unity apps running on **Windows x86 64-bit** and **Android ARM** architecture

## Installation

uniref requires Windows Python 3.7+ (64-bit) operating environment, you can complete the installation through pip:

```bash
pip install -U uniref
```

## Example

A piece of code completed using the uniref framework is given below, which solves a reverse challenge of [MRCTF2021](https://uniref.readthedocs.io/en/latest/examples/windows.html#mrctf2021-ezgame).

```Python
from uniref import WinUniRef

ref = WinUniRef("GameHack.exe")
class_GetFlag = ref.find_class_in_image("Assembly-CSharp.dll", "Platformer.Flag.GetFlag")
class_GetFlag.find_field("goHome").value = True
class_GetFlag.find_field("findAlien").value = True
class_GetFlag.find_field("eatCookie").value = True

method_EatTokenUpdateKey = class_GetFlag.find_method("EatTokenUpdateKey")
for i in range(105):
    method_EatTokenUpdateKey()
```

[Documentation](https://uniref.readthedocs.io/en/latest/examples/index.html) also gives example code for analyzing *Sons Of The Forest*, *Goose Goose Duck*, *Dream Blast*, *Temple Run*, etc.

## Get Involved

If you have any suggestions or needs, please submit [Issues](https://github.com/in1nit1t/uniref/issues).

If you are interested in improving this framework together, you are welcome to submit [Pull requests](https://github.com/in1nit1t/uniref/pulls).

## License

[GNU Affero General Public License v3.0](https://github.com/in1nit1t/uniref/blob/main/LICENSE)
