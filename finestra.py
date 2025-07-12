import subprocess
import platform

if platform.system() == "Windows":
    subprocess.Popen(["start", "cmd", "/k", "title CORS INSPECTOR && python3 cors.py"], shell=True)
else:
    subprocess.Popen(["gnome-terminal", "--title=CORS INSPECTOR","--", "python3", "cors.py"])