import sys
from uniref import AndroidUniRef

# A game, You can download it from http://www.chillyroom.com/
# Just run this script to start the game automatically.
# Notice: It is recommended to start frida-server through adb wireless debugging


ref = AndroidUniRef(package_name="com.ChillyRoom.DungeonShooter")


def dump_cs():
    image = ref.find_image_by_name("System.Data.dll")
    image.dump_declaration("system_data_dump.cs", True)


def skill_cd_cheat():
    def on_message(msg, data):
        if msg["type"] == "send":
            print(msg["payload"])

    attr = ref.find_class_in_image("Assembly-CSharp.dll", "RoleAttributePlayer")
    get_skill_ready = attr.find_method("get_skill_ready")

    code = """
    Java.perform(function () {
        Interceptor.attach(ADDRESS, {
            onEnter: function(args) {
                send("function called.")
            },
            onLeave: function(retval) {
                retval.replace(1);
            }
        })
    });""".replace("ADDRESS", f"ptr({hex(get_skill_ready.address)})")
    return ref.execute_js(code, on_message)


if __name__ == "__main__":
    dump_cs()
    script = skill_cd_cheat()

    sys.stdin.readline()
    script.unload()
