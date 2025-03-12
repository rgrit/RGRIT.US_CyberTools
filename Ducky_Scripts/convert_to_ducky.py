import os
import subprocess

# Paths
DUCKY_SCRIPTS_DIR = "/home/administrator/PycharmProjects/RGRIT.US/Ducky_Scripts"
DUCK_ENCODER_JAR = "/home/administrator/PycharmProjects/RGRIT.US/Ducky_Scripts/encoder.jar"

# Ensure the duckencoder.jar file exists
if not os.path.exists(DUCK_ENCODER_JAR):
    print(f"❌ Error: {DUCK_ENCODER_JAR} not found! Please download it.")
    exit(1)

# List all .txt files (Ducky Scripts) in the directory
ducky_scripts = [f for f in os.listdir(DUCKY_SCRIPTS_DIR) if f.endswith(".txt")]

if not ducky_scripts:
    print("⚠️ No Ducky script files found in the directory.")
    exit(1)

# Process each Ducky script file
for script in ducky_scripts:
    input_file = os.path.join(DUCKY_SCRIPTS_DIR, script)
    output_file = os.path.join(DUCKY_SCRIPTS_DIR, script.replace(".txt", ".bin"))

    # Encode the script into a binary payload
    cmd = ["java", "-jar", DUCK_ENCODER_JAR, "-i", input_file, "-o", output_file]

    try:
        subprocess.run(cmd, check=True)
        print(f"✅ Successfully converted {script} → {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error encoding {script}: {e}")

print("🎯 All scripts have been processed!")
