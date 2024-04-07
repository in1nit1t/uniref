from time import sleep
from uniref import WinUniRef

# A game on Steam
# Remember to rerun in a new scene


ref = WinUniRef("Content Warning.exe")
cls_player_data = ref.find_class_in_image("Assembly-CSharp", "Player+PlayerData")
cls_network_handler = ref.find_class_in_image("Assembly-CSharp", "SurfaceNetworkHandler")
cls_room_stats_holder = ref.find_class_in_image("Assembly-CSharp", "RoomStatsHolder")
method_set_money = cls_room_stats_holder.find_method("set_Money")

cls_player = ref.find_class_in_image("Assembly-CSharp", "Player")
field_local_player = cls_player.find_field("localPlayer")
field_player_data = cls_player.find_field("data")

field_health = cls_player_data.find_field("health")
field_stamina = cls_player_data.find_field("currentStamina")


def health_hack(new: float):
    field_player_data.set_instance(field_local_player.value)
    field_health.set_instance(field_player_data.value)
    field_health.value = new


def stamina_hack(new: float):
    field_player_data.set_instance(field_local_player.value)
    field_stamina.set_instance(field_player_data.value)
    field_stamina.value = new


def money_hack(new: int):
    method_set_money.set_instance(cls_network_handler.find_method("get_RoomStats")())
    method_set_money(args=(new,))


money_hack(100000)
try:
    while True:
        health_hack(100.0)
        stamina_hack(20.0)
        sleep(1)
except Exception as e:
    print(e)
