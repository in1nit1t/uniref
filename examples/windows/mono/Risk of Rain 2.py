from time import sleep
from uniref import WinUniRef

# A game on Steam
# Only useful on the server side, you can modify the client data.
# `idx` represents the player index in the game (starting from 0)


ref = WinUniRef("Risk of Rain 2.exe")

cls_stats = ref.find_class_in_image("RoR2", "RoR2.Stats.PlayerStatsComponent")
field_health = ref.find_class_in_image("RoR2", "RoR2.HealthComponent").find_field("health")
field_cls_health = ref.find_class_in_image("RoR2", "RoR2.CharacterBody").find_field("<healthComponent>k__BackingField")
field_cached = cls_stats.find_field("cachedCharacterBody")
field_cls_cm = cls_stats.find_field("<characterMaster>k__BackingField")
field_money = ref.find_class_in_image("RoR2", "RoR2.CharacterMaster").find_field("_money")

field_instances = cls_stats.find_field("instancesList")
players = ref.injector.mem_read_pointer(field_instances.value + 0x10)
count = ref.injector.mem_read_uint32(field_instances.value + 0x18)


def health_hack(idx, new, once=False):
    assert type(new) == float
    assert idx < count, "out of range"

    field_cached.instance = ref.injector.mem_read_pointer(players + 0x20 + idx * 8)
    field_cls_health.instance = field_cached.value
    field_health.instance = field_cls_health.value

    if once:
        field_health.value = new
        return
    while True:
        field_health.value = new
        sleep(0.1)


def money_hack(idx, new):
    assert type(new) == int
    assert idx < count, "out of range"

    field_cls_cm.instance = ref.injector.mem_read_pointer(players + 0x20 + idx * 8)
    field_money.instance = field_cls_cm.value
    field_money.value = new


money_hack(0, 10000)
health_hack(0, 5000.0)
