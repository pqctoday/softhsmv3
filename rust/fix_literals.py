import re

def insert_underscore(m):
    g1, g2 = m.groups()
    return f"0x{g1}_{g2}"

with open("src/constants.rs", "r") as f:
    text = f.read()

# Replace any 8-digit hex literal like 0x00000100 with 0x0000_0100
text = re.sub(r'0x([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})\b', insert_underscore, text)

with open("src/constants.rs", "w") as f:
    f.write(text)
