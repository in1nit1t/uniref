import sys
from uniref import AndroidUniRef

# A game on Google Play
# You can download it from https://1drv.ms/u/s!AsGvxndj5W9qhCo6QrWyMr-jrBFG?e=BxkFBl

# 1. Run game
# 2. Run this script
# 3. Click on your avatar to refresh the number of coins
# 4. Enter a level & input '\n' to modify moves amount


def modify_coins(ref: AndroidUniRef):
    images = ref.list_images()
    for image in images:
        InventoryBase = ref.find_class_in_image(image.name, "DreamBlast.InventoryBase")
        if InventoryBase:
            print("Found class in " + image.name)
            break

    GetCoins = InventoryBase.find_method("GetCoins")
    patch = GetCoins.native_patch(0x94, "MOV X0, 9999")

    print("Now you have unlimited coins, input \\n to cancel")

    # input '\n' to disable patch
    sys.stdin.readline()
    patch.disable()


def modify_moves_amount(ref: AndroidUniRef):
    LevelGoalsData = ref.find_class_in_image("OneTapCore.dll", "OneTapCore.LevelGoalsData")
    addresses = LevelGoalsData.guess_instance_address()
    movesAmount = LevelGoalsData.find_field("movesAmount")

    for address in addresses:
        movesAmount.set_instance(address)
        if movesAmount.value == 25:  # You may need to modify this
            print(f"Found instance at {hex(address)}")
            movesAmount.value = 99


if __name__ == "__main__":
    ref = AndroidUniRef(package_name="com.rovio.dream")

    print("Modifying coins amount...")
    modify_coins(ref)

    print("Modifying moves amount...")
    modify_moves_amount(ref)
