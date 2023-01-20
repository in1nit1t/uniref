from uniref import *

# A game on Steam
# 1. Run game
# 2. Choose PLAY GAME -> NEW GAME -> Skip tutorial
# 3. Choose first boss to battle -> Enter the battle scene
# 4. Run this script


def modify_player_hp(ref: WinUniRef):
    """ Modify player's HP to 99999 """

    Player = ref.find_class_in_image("Assembly-CSharp", "Player")
    instances = Player.guess_instance_address()

    CurHP = Player.find_field("<CurHP>k__BackingField")
    for instance in instances:
        CurHP.instance = instance
        if CurHP.value == 1200:
            Player.instance = instance
            break

    MaxHP = Player.find_field("<MaxHP>k__BackingField")
    CurHP.value = 99999
    MaxHP.value = 99999


def same_name_function_sample(ref: WinUniRef):
    """ This example shows how to find functions with
    the same name and the same number of parameters """

    Enemy = ref.find_class_in_image("Assembly-CSharp", "Enemy")
    instances = Enemy.guess_instance_address()

    CurHP = Enemy.find_field("<CurHP>k__BackingField")
    for instance in instances:
        CurHP.instance = instance
        if CurHP.value == 4000:
            Enemy.instance = instance
            break

    methods = Enemy.list_methods()
    for method in methods:
        if method.name == "BrokeCloth" and method.signature == "System.Void (int level)":
            method.instance = instance
            method(args=(1,), call_type=CALL_TYPE_CDECL)


if __name__ == "__main__":
    ref = WinUniRef("game.exe")

    modify_player_hp(ref)
    same_name_function_sample(ref)

    print("Done.")
