import subprocess
import sys

def run_shell_script(script_path):
    try:
        # تشغيل السكربت مع توجيه المخرجات إلى stdout و stderr
        result = subprocess.run(['bash', script_path], check=True)
        print(f"Script {script_path} executed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error running script: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    script_path = './final.sh'  # مسار السكربت
    run_shell_script(script_path)
