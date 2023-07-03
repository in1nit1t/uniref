from uniref import WinUniRef

# A game on Steam
# 1. Run game
# 2. Start a mission & Skip animation
# 3. Run this script


ref = WinUniRef("GTFO.exe")

player_manager = ref.find_class_in_image("Modules-ASM.dll", "Player.PlayerManager")
player_manager.set_instance(player_manager.find_field("Current").value)
player_agent = ref.find_class_in_image("Modules-ASM.dll", "Player.PlayerAgent")
player_agent.set_instance(player_manager.find_field("m_localPlayerAgentInLevel").value)


def health_hack(toggle: bool = True):
    player_damage = ref.find_class_in_image("Modules-ASM.dll", "Dam_PlayerDamageBase")
    player_damage.set_instance(player_agent.find_field("Damage").value)

    health_max = player_damage.find_field("<HealthMax>k__BackingField")
    health_max.value = 10000.0 if toggle else 25.0

    health = player_damage.find_field("<Health>k__BackingField")
    health.value = 10000.0 if toggle else 25.0


def run_speed_hack(toggle: bool = True):
    player_data = ref.find_class_in_image("Modules-ASM.dll", "GameData.PlayerDataBlock")
    player_data.set_instance(player_agent.find_field("PlayerData").value)

    run_speed = player_data.find_field("<runMoveSpeed>k__BackingField")
    run_speed.value = 20.0 if toggle else 6.0


def ammo_hack(toggle: bool = True):
    code1 = b'\x90' * 6 if toggle else bytes.fromhex("FF 8B 90 02 00 00")
    code2 = b'\x90' * 5 if toggle else bytes.fromhex("F3 0F 11 73 18")

    bullet_weapon = ref.find_class_in_image("Modules-ASM.dll", "Gear.BulletWeapon")
    bullet_weapon_fire = bullet_weapon.find_method("Fire")
    bullet_weapon_fire.native_patch(0xed2, code1)

    shotgun = ref.find_class_in_image("Modules-ASM.dll", "Gear.Shotgun")
    shotgun_fire = shotgun.find_method("Fire")
    shotgun_fire.native_patch(0xec9, code1)

    ammo_storage = ref.find_class_in_image("Modules-ASM.dll", "Player.PlayerAmmoStorage")
    update_bullets = ammo_storage.find_method("UpdateBulletsInPack")
    update_bullets.native_patch(0xc9, code2)


health_hack()
run_speed_hack()
ammo_hack()
