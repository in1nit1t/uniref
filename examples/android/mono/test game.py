import sys
import time
from uniref import AndroidUniRef

# Attachment: examples/bin/test_game.apk
# 1. Run game
# 2. Run this script
# 3. Follow the prompts


def always_win(ref: AndroidUniRef):
    click1 = ref.find_class_in_image("Assembly-CSharp", "click1")
    Click = click1.find_method("Click")
    patch = Click.native_nop(0x4c, 4)

    print("Now you can win all the time, input \\n to cancel")

    sys.stdin.readline()
    patch.disable()


def another_way(ref: AndroidUniRef):
    info = ref.find_class_in_image("Assembly-CSharp", "info")
    monster_power = info.find_field("monster_power")
    assert monster_power.is_static()
    print("Now you can win all the time, input Ctrl+C to cancel")

    while True:
        try:
            monster_power.value = 1
            time.sleep(0.1)
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    ref = AndroidUniRef(package_name="com.aaa.test")

    print("Modifying victory condition...")
    always_win(ref)

    print("Modifying monster power...")
    another_way(ref)
