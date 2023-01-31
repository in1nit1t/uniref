from uniref import WinUniRef

# A game on Steam
# WARNING: Due to the frequent updates of the game, the script may fail to run.

# 1. Run game & Start a tutorial
# 2. Run this script
# 3. Function modify_speed will give you a higher speed
# 4. Function show_my_position will print your (x, y, z) position


def modify_speed(ref: WinUniRef):
    LocalPlayer = ref.find_class_in_image("Assembly-CSharp.dll", "Handlers.GameHandlers.PlayerHandlers.LocalPlayer")
    movementSpeed = LocalPlayer.find_field("movementSpeed")
    static_field = ref.injector.mem_read_pointer(LocalPlayer.vtable + 0xB8)

    movementSpeed_address = static_field + movementSpeed.offset

    # fight against anti-cheating mechanisms
    ref.injector.mem_write_bool(movementSpeed_address + 0x14, False)
    ref.injector.mem_write_float(movementSpeed_address, 20.0)
    ref.injector.mem_write_uint32(movementSpeed_address + 4, 0)


def show_my_position(ref: WinUniRef):
    error_hint = "Error multilevel pointer offsets due to game update"
    game_assembly_base = ref.injector.get_module_base("GameAssembly.dll")

    LocalPlayer = ref.find_class_in_image("Assembly-CSharp.dll", "Handlers.GameHandlers.PlayerHandlers.LocalPlayer")
    try:
        local_player_instance = ref.injector.mem_read_multilevel_pointer(game_assembly_base, [0x3CDB720, 0xB8, 0])
    except:
        print(error_hint)
        exit(-1)
    assert local_player_instance > 0, error_hint
    LocalPlayer.instance = local_player_instance

    PlayerController = ref.find_class_in_image("Assembly-CSharp.dll", "Handlers.GameHandlers.PlayerHandlers.PlayerController")
    player_controller_instance = LocalPlayer.find_field("Player").value
    assert player_controller_instance > 0, error_hint
    PlayerController.instance = player_controller_instance

    position = PlayerController.find_field_by_offset(0x2D8)
    assert position.type_name == "UnityEngine.Vector3", "Error field offset due to game update"

    pos_value = []
    for i in range(3):
        pos_value.append(ref.injector.mem_read_float(position.address + i * 4))
    x, y, z = pos_value
    print("position: ", x, y, z)


if __name__ == "__main__":
    ref = WinUniRef("Goose Goose Duck.exe")

    modify_speed(ref)
    show_my_position(ref)
