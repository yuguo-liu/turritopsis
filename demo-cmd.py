import subprocess
import time

cmd1 = ["bash", "boot-t.sh", "10", "9", "2", "1", "1000", "100", "1", "60"]
cmd2 = ["python3", "readLogT.py"]
cmd3 = ["bash", "boot-s.sh", "10", "9", "2", "1", "1000", "100", "1", "60"]
cmd4 = ["python3", "readLogS.py"]

print("Turritopsis - start...")
p1 = subprocess.Popen(cmd1)
time.sleep(0.5)
print("Parsing logs")
p2 = subprocess.Popen(cmd2)
p2.wait()
print("Turritopsis - finished...")

print("sDumbo - start...")
p3 = subprocess.Popen(cmd3)
time.sleep(0.5)
p4 = subprocess.Popen(cmd4)
p4.wait()
print("sDumbo - finished...")
