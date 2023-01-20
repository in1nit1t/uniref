from uniref import WinUniRef

# Attachment: examples/bin/EzGame.zip
# 1. Run GameHack.exe
# 2. Press Esc and change to Tasks panel
# 3. Run this script
# 4. Click GetFlag button


def enable_get_flag():
    ref = WinUniRef("GameHack.exe")
    class_GetFlag = ref.find_class_in_image("Assembly-CSharp.dll", "Platformer.Flag.GetFlag")
    class_GetFlag.find_field("goHome").value = True
    class_GetFlag.find_field("findAlien").value = True
    class_GetFlag.find_field("eatCookie").value = True

    method_EatTokenUpdateKey = class_GetFlag.find_method("EatTokenUpdateKey")
    for i in range(105):
        method_EatTokenUpdateKey()


if __name__ == "__main__":
    enable_get_flag()
    print("Done.")
