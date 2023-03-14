from time import sleep
from uniref import WinUniRef

# A game on Steam
# 1. Run game
# 2. Choose SINGLE PLAYER -> NORMAL & Skip animation
# 3. Run this script


ref = WinUniRef("SonsOfTheForest.exe")

local_player = ref.find_class_in_image("Sons.dll", "TheForest.Utils.LocalPlayer")
vitals_instance = local_player.find_field("<Vitals>k__BackingField").value
vitals = ref.find_class_in_image("Sons.dll", "Vitals")
vitals.set_instance(vitals_instance)


def energy_hack(toggle: bool):
    cheats = ref.find_class_in_image("Sons.dll", "Cheats")
    cheats.find_field("InfiniteEnergy").value = toggle
    print("Now you should have unlimited energy")


def speed_hack(toggle: bool):
    fpc_instance = local_player.find_field("<FpCharacter>k__BackingField").value
    fpc = ref.find_class_in_image("Sons.dll", "FirstPersonCharacter")
    fpc.set_instance(fpc_instance)

    speeds = ["_runSpeed", "_swimSpeed", "crouchSpeed"]
    for speed in speeds:
        speed_field = fpc.find_field(speed)
        origin_value = speed_field.value
        speed_field.value = origin_value * 5 if toggle else origin_value / 5

    fpc.find_field("_baseFallDamage").value = 0.0 if toggle else 20.0
    fpc.find_field("_fallDamagePower").value = 0.0 if toggle else 2.0
    fpc.find_field("_fallDamageVelocity").value = 1000.0 if toggle else 16.0

    print("You now run, crouch, and swim five times faster and are immune to fall damage.")


def strength_level_hack():
    vitals.find_field("_currentStrengthLevel").value = vitals.find_field("_maxStrengthLevel").value
    print("Now your strength level should be maxed out")


def stat_hack():
    health_instance = vitals.find_field("_health").value
    health_stat = ref.find_class_in_image("Sons.StatSystem.dll", "Sons.StatSystem.HealthStat")
    health_stat.set_instance(health_instance)
    health = health_stat.find_field("_currentValue")

    hydration_instance = vitals.find_field("_hydration").value
    hydration_stat = ref.find_class_in_image("Sons.StatSystem.dll", "Sons.StatSystem.HydrationStat")
    hydration_stat.set_instance(hydration_instance)
    hydration = hydration_stat.find_field("_currentValue")

    stamina_instance = vitals.find_field("_stamina").value
    stamina_stat = ref.find_class_in_image("Sons.StatSystem.dll", "Sons.StatSystem.StaminaStat")
    stamina_stat.set_instance(stamina_instance)
    stamina = stamina_stat.find_field("_currentValue")

    fullness_instance = vitals.find_field("_fullness").value
    fullness_stat = ref.find_class_in_image("Sons.StatSystem.dll", "Sons.StatSystem.FullnessStat")
    fullness_stat.set_instance(fullness_instance)
    fullness = fullness_stat.find_field("_currentValue")

    rested_instance = vitals.find_field("_rested").value
    rested_stat = ref.find_class_in_image("Sons.StatSystem.dll", "Sons.StatSystem.RestedStat")
    rested_stat.set_instance(rested_instance)
    rested = rested_stat.find_field("_currentValue")

    try:
        print("Now all your states are full. Press CTRL-C to exit")
        while True:
            health.value = 100.0
            hydration.value = 100.0
            stamina.value = 100.0
            fullness.value = 100.0
            rested.value = 100.0
            sleep(0.2)
    except KeyboardInterrupt:
        exit(0)


energy_hack(True)
speed_hack(True)
strength_level_hack()
stat_hack()
