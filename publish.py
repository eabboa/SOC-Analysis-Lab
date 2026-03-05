import subprocess
import os
import sys

REPO_PATH = r"C:\Users\enesa\OneDrive\Belgeler\Github\SOC-Analysis-Lab"

def run(cmd):
    result = subprocess.run(cmd, cwd=REPO_PATH, capture_output=True, text=True, shell=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print("ERR:", result.stderr)
    return result

print("=== GENERATING README ===")
run("python generate_readme.py")

print("=== STAGING ALL FILES ===")
run("git add .")

print("=== COMMITTING ===")
run('git commit -m "auto: update docs"')

print("=== PUSHING TO GITHUB ===")
result = run("git push origin main")

if result.returncode == 0:
    print("\n✅ DONE. Now paste your GitHub link into LinkedIn.")
else:
    print("\n❌ Push failed. Check your internet or GitHub credentials.")

input("\nPress Enter to close...")