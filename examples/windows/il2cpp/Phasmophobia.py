from os import system
from time import sleep
from uniref import WinUniRef

# A game on Steam. This script shows the ghost room & ghost type.

# 1. Run game
# 2. Choose a contract & Start
# 3. Run this script


# For Chinese
# ghost_type_str = ["魂魄", "魅影", "幻影", "骚灵", "女妖", "巨灵", "梦魇", "亡魂", "暗影", "恶魔", "幽灵", "赤鬼", "妖怪", "寒魔", "御灵", "鬼婴", "怨灵", "孪魂", "雷魂", "幻妖", "拟魂", "魔洛伊", "雾影", "刹耶"]
ghost_type_str = ["Spirit", "Wraith", "Phantom", "Poltergeist", "Banshee", "Jinn", "Mare", "Revenant", "Shade", "Demon", "Yurei", "Oni", "Yokai", "Hantu", "Goryo", "Myling", "Onryo", "TheTwins", "Raiju", "Obake", "Mimic", "Moroi", "Deogen", "Thaye"]


def get_room_str(level_room):
    for field in level_room.list_fields():
        if field.type_name == "System.String":
            return field.value


ref = WinUniRef("Phasmophobia.exe")

lc = ref.find_class_in_image("Assembly-CSharp.dll", "LevelController")
ai = ref.find_class_in_image("Assembly-CSharp.dll", "GhostAI")
info = ref.find_class_in_image("Assembly-CSharp.dll", "GhostInfo")
lr = ref.find_class_in_image("Assembly-CSharp.dll", "LevelRoom")
ls = ref.find_class_in_image("Assembly-CSharp.dll", "LevelStats")

lc.instance = lc.find_field_by_offset(0).value

for field in lc.list_fields():
    if field.type_name == "GhostAI":
        ai.instance = field.value

for field in ai.list_fields():
    if field.type_name == "GhostInfo":
        info.instance = field.value

ghost_type = info.find_field_by_offset(0x20)
ghost_type = ghost_type_str[ghost_type.value & 0xFF]

ls.instance = ls.find_field("_instance").value
bone_room = ls.find_field("boneRoom").value

my_room = lc.find_field_by_offset(0x28)
ghost_room = lc.find_field_by_offset(0x30)


try:
    while True:
        system("cls")

        lr.instance = ghost_room.value
        print("Ghost Room:", get_room_str(lr))

        print("Bone Room:", bone_room)

        print("Ghost Type:", ghost_type)

        lr.instance = my_room.value
        print("My Position:", get_room_str(lr))

        sleep(1)
except KeyboardInterrupt:
    exit(0)
