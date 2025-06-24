import yara

try:
    rules = yara.compile(filepath="modbus_backdoor.yar")
    matches = rules.match(filepath="plc_project.xml")

    if matches:
        print("[✔] Threat Detected:", matches)
    else:
        print("[✘] No threat found.")
except yara.SyntaxError as e:
    print("[!] YARA Rule Error:", e)
except Exception as e:
    print("[!] Unexpected Error:", e)
