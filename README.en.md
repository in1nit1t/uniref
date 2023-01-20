# uniref

`uniref` is a framework to assist in analyzing Unity applications. It can help you obtain reflection information of classes, methods, fields, etc. in Unity applications, allowing you to view and manipulate them in real time.

You can use this framework to convert some of your analysis results into Python code, which is convenient for you to develop plug-ins for Unity applications.

Uniref currently supports analyzing 32/64-bit Unity applications running on Windows x86 64-bit operating systems. Meanwhile, it supports both `Mono` and `IL2CPP` scripting backends.

## Installation

uniref requires Python 3.7+ (64-bit) environment, you can complete the installation through pip:

```bash
pip install -U uniref
```

## Example

Below is a piece of code completed using the uniref framework, which achieves the effect of modifying the movement speed of Goose Goose Duck game characters.

You can run this code [^1] in the tutorial of the game to experience `uniref`. **DO NOT use it in multiplayer mode**, it will affect the game experience of other players.

```Python
from uniref import WinUniRef

# Specify the process to be analyzed
ref = WinUniRef("Goose Goose Duck.exe")

# Find class
class_path = "Handlers.GameHandlers.PlayerHandlers.LocalPlayer"
local_player = ref.find_class_in_image("Assembly-CSharp.dll", class_path)

# Find the field in the class & print its value
movement_speed = local_player.find_field("movementSpeed")
print(f"default speed: {movement_speed.value}")

# Modify the field value
movement_speed.value = 20.0
```

For more information please refer to the [documentation](https://uniref.rtfd.io). 

## Next Step

Support Android platform

## Get Involved

If you have any suggestions or needs, please submit [Issues](https://github.com/in1nit1t/uniref/issues).

If you are interested in improving this framework together, you are welcome to submit [Pull requests](https://github.com/in1nit1t/uniref/pulls).

## License

[GNU Affero General Public License v3.0](https://github.com/in1nit1t/uniref/blob/main/LICENSE)


[^1]: If the target process is started with administrator privileges, please ensure that the framework runs under administrator privileges. That is, Python needs to be run with administrator privileges when necessary.
