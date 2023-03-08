# -*- coding: utf-8 -*-
from uniref import WinUniRef

# A game on Steam. This script shows the ghost room & ghost type.

# 1. Run game
# 2. Choose a contract & Start
# 3. Run this script


# For Chinese
# ghost_type_str = ["魂魄", "魅影", "幻影", "骚灵", "女妖", "巨灵", "梦魇", "亡魂", "暗影", "恶魔", "幽灵", "赤鬼", "妖怪", "寒魔", "御灵", "鬼婴", "怨灵", "孪魂", "雷魂", "幻妖", "拟魂", "魔洛伊", "雾影", "刹耶"]
ghost_type_str = ["Spirit", "Wraith", "Phantom", "Poltergeist", "Banshee", "Jinn", "Mare", "Revenant", "Shade", "Demon", "Yurei", "Oni", "Yokai", "Hantu", "Goryo", "Myling", "Onryo", "TheTwins", "Raiju", "Obake", "Mimic", "Moroi", "Deogen", "Thaye"]


ref = WinUniRef("Phasmophobia.exe")

lc = ref.find_class_in_image("Assembly-CSharp.dll", "LevelController")
ai = ref.find_class_in_image("Assembly-CSharp.dll", "GhostAI")
info = ref.find_class_in_image("Assembly-CSharp.dll", "GhostInfo")
lr = ref.find_class_in_image("Assembly-CSharp.dll", "LevelRoom")

for field in lc.list_fields():
    if field.is_static() and field.offset == 0:
        lc.instance = field.value

for field in lc.list_fields():
    if field.type_name == "GhostAI":
        ai.instance = field.value

for field in ai.list_fields():
    if field.type_name == "GhostInfo":
        info.instance = field.value

for field in info.list_fields():
    if field.type_name == "LevelRoom":
        lr.instance = field.value

for field in lr.list_fields():
    if field.type_name == "System.String":
        print("Ghost Room:", field.value)

ghost_type = info.find_field_by_offset(0x20)
print("Ghost Type:", ghost_type_str[ghost_type.value & 0xFF])
