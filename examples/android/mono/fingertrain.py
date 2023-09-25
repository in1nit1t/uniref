from uniref import AndroidUniRef


ref = AndroidUniRef(package_name="com.blackshark.fingertrain")

game_data = ref.find_class_in_image("Assembly-CSharp", "GameData")
game_data.instance = game_data.find_field("instance").value

add_coins = game_data.find_method("addCoins")
add_gems = game_data.find_method("addGems")

add_coins(args=(9999999, 0, 0, 0))
add_gems(args=(9999999, 0, 0, 0))
