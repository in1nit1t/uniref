import os
from uniref import WinUniRef

# Attachment: examples/bin/simple-game-2.tar.gz
# 1. Run LineCTF.exe
# 2. Run this script
# 3. Type hack code to the game & get flag


ref = WinUniRef("LineCTF.exe")

player = ref.find_class_in_image("Assembly-CSharp", "Player")
jump_force = player.find_field("JUMP_FORCE")
current_char = player.find_field("currentChar")

addresses = player.guess_instance_address()
for address in addresses:
    jump_force.set_instance(address)
    if jump_force.value != 8.0:
        continue
    jump_force.set_value(20.0)

    while True:
        current_char.set_instance(address)
        print(f"Current hack code: {current_char.value}")
        os.system("cls")
