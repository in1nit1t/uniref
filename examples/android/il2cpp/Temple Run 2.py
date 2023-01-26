import sys
from uniref import AndroidUniRef

# A game on Google Play
# You can download it from https://1drv.ms/u/s!AsGvxndj5W9qhCyopSbnVuZ1iLuP?e=Vhx1de

# 1. Run game
# 2. Run this script
# 3. Collect the coins


def easy_energy():
    ref = AndroidUniRef(package_name="com.imangi.templerun2")

    BonusItem = ref.find_class_in_image("Assembly-CSharp.dll", "BonusItem")
    HitLeftMeter = BonusItem.find_method("HitLeftMeter")

    patch = HitLeftMeter.native_patch(0x60, "MOV R1, 50")

    print("Now you can collect energy easily, input \\n to cancel")

    # input '\n' to disable patch
    sys.stdin.readline()
    patch.disable()


if __name__ == "__main__":
    easy_energy()
