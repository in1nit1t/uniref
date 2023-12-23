from uniref import WinUniRef

# A game on Steam
# 1. Host an new online game
# 2. Run this script


ref = WinUniRef("Lethal Company.exe")

# Modify maximum number of players
manager = ref.find_class_in_image("Assembly-CSharp", "GameNetworkManager")
manager.instance = manager.find_field("<Instance>k__BackingField").value
manager.find_field("maxAllowedPlayers").value = 10

# Modify the initial amount of money
terminal = ref.find_class_in_image("Assembly-CSharp", "Terminal")
money = terminal.find_field("groupCredits")
for address in terminal.guess_instance_address():
    money.instance = address
    if money.value == 60:
        money.value = 999999999
