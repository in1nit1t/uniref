from uniref import WinUniRef

# A game on Steam
# WARNING: Due to the frequent updates of the game, the script may fail to run.

"""
To avoid EAC loading, you need to delete all files except Settings.json in the EasyAntiCheat folder
under the game root directory (please make a backup).
Then replace the contents of the file with the following.

{
	"title"											: "Goose Goose Duck",
	"executable"									: "Goose Goose Duck.exe",
	"productid"										: "75ae519171904d40b767b1547dd91c37f",
	"sandboxid"										: "a85f25c87846431a8adbe9246701f32df",
	"deploymentid"									: "d569cc9d3e0945e9b7e5bb508c3dbc73f",
	"requested_splash"								: "EasyAntiCheat/SplashScreen.png",
	"wait_for_game_process_exit"					: "true"
}
"""

# 1. Run game in steam & Start a tutorial
# 2. Run this script
# 3. Function modify_speed will give you a higher speed
# 4. Function show_my_position will print your (x, y, z) position


def modify_speed(ref: WinUniRef):
    LocalPlayer = ref.find_class_in_image("Assembly-CSharp.dll", "Handlers.GameHandlers.PlayerHandlers.LocalPlayer")
    movementSpeed = LocalPlayer.find_field("movementSpeed")
    static_field = ref.injector.mem_read_pointer(LocalPlayer.vtable + 0xB8)

    movementSpeed_address = static_field + movementSpeed.offset

    # fight against anti-cheating mechanisms
    # check https://github.com/Liuhaixv/Goose_Goose_Duck_Hack/pull/259 for more details
    ref.injector.mem_write_bool(movementSpeed_address + 0x14, False)
    ref.injector.mem_write_float(movementSpeed_address, 20.0)
    ref.injector.mem_write_uint32(movementSpeed_address + 4, 0)

    print("Now you cam move fast")


def show_my_position(ref: WinUniRef):
    LocalPlayer = ref.find_class_in_image("Assembly-CSharp.dll", "Handlers.GameHandlers.PlayerHandlers.LocalPlayer")
    LocalPlayer.instance = LocalPlayer.find_field("Instance").value

    PlayerController = ref.find_class_in_image("Assembly-CSharp.dll", "Handlers.GameHandlers.PlayerHandlers.PlayerController")
    PlayerController.instance = LocalPlayer.find_field("Player").value

    position = PlayerController.find_field_by_offset(0x2D8)
    assert position.type_name == "UnityEngine.Vector3", "Error field offset due to game update"

    pos_value = []
    for i in range(3):
        pos_value.append(ref.injector.mem_read_float(position.address + i * 4))
    x, y, z = pos_value
    print("Position: ", x, y, z)


if __name__ == "__main__":
    ref = WinUniRef("Goose Goose Duck.exe")

    modify_speed(ref)
    show_my_position(ref)
