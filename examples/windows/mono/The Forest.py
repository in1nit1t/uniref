import sys
from uniref import WinUniRef

# A game on Steam
# 1. Run game
# 2. Choose SINGLE PLAYER -> NEW GAME -> NORMAL & Skip animation
# 3. Run this script


def modify_stats(ref: WinUniRef):
    PlayerStats = ref.find_class_in_image("Assembly-CSharp", "PlayerStats")
    field_energy = PlayerStats.find_field("Energy")

    # filter class instance by condition
    found = False
    addresses = PlayerStats.guess_instance_address()
    for address in addresses:
        field_energy.instance = address
        if field_energy.value == 10.0:
            PlayerStats.instance = address
            found = True
    assert found, "Can't find PlayerStats instance"

    field_stamina = PlayerStats.find_field("Stamina")
    assert field_stamina.value == 10.0, "Wrong PlayerStats instance"

    field_health = PlayerStats.find_field("Health")
    field_health.value = 100.0
    print("Now your health should be full")


def unlimited_energy(ref: WinUniRef):
    FirstPersonCharacter = ref.find_class_in_image("Assembly-CSharp", "FirstPersonCharacter")

    HandleRunningStaminaAndSpeed = FirstPersonCharacter.find_method("HandleRunningStaminaAndSpeed")
    patch1 = HandleRunningStaminaAndSpeed.native_nop(0x112, 8)

    PlayerStats = ref.find_class_in_image("Assembly-CSharp", "PlayerStats")

    setStamina = PlayerStats.find_method("setStamina")
    patch2 = setStamina.native_nop(0x2e, 8)

    # if the game crashed, comment line 44, 45, and 53
    Update = PlayerStats.find_method("Update")
    patch3 = Update.native_nop(0x382, 6)

    print("Now you have unlimited energy, input \\n to cancel")

    # input '\n' to disable patch
    sys.stdin.readline()
    patch1.disable()
    patch2.disable()
    patch3.disable()


def modify_running_speed(ref: WinUniRef):
    FirstPersonCharacter = ref.find_class_in_image("Assembly-CSharp", "FirstPersonCharacter")

    HandleRunningStaminaAndSpeed = FirstPersonCharacter.find_method("HandleRunningStaminaAndSpeed")
    new_run_speed = ref.injector.new_double(40.0)

    code = f"movsd xmm0, [{hex(new_run_speed.address)}]             \n" \
           f"jmp {hex(HandleRunningStaminaAndSpeed.address + 0x34e)}  "
    patch = HandleRunningStaminaAndSpeed.native_patch(0x167, code)

    print("Now you can run faster, input \\n to cancel")

    # input '\n' to disable patch
    sys.stdin.readline()
    patch.disable()


def super_build(ref: WinUniRef):
    Craft_Structure = ref.find_class_in_image("Assembly-CSharp", "TheForest.Buildings.Creation.Craft_Structure")

    CheckNeeded = Craft_Structure.find_method("CheckNeeded")
    patch1 = CheckNeeded.native_patch(0xF, b"\xEB\x70")

    Initialize = Craft_Structure.find_method("Initialize")
    patch2 = Initialize.native_nop(0x183, 3)

    print("Now you can build things without materials, input \\n to cancel")

    # input '\n' to disable patch
    sys.stdin.readline()
    patch1.disable()
    patch2.disable()


if __name__ == "__main__":
    ref = WinUniRef("TheForest.exe")

    print("Modifying player stats...")
    modify_stats(ref)

    print("Modifying energy logic...")
    unlimited_energy(ref)

    print("Modifying running logic...")
    modify_running_speed(ref)

    print("Modifying build logic...")
    super_build(ref)
