import subprocess, threading, time, shutil, os, sys

NUM_CPUS = 8

INPUT_DIR  = "testcases"
OUTPUT_DIR = "findings"

def do_work(cpu):
    master_arg = "-M"
    if cpu != 0:
        master_arg = "-S"

    # Restart if it dies, which happens on startup a bit
    while True:
        try:
            sp = subprocess.Popen([
                "taskset", "-c", "%d" % cpu,
                "afl-fuzz", "-m", "256", "-i", INPUT_DIR, "-o", OUTPUT_DIR,
                master_arg, "fuzzer%d" % cpu, "--",
                "../main", "@@"] + sys.argv[1:],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sp.wait()
        except:
            pass

        print("CPU %d afl-fuzz instance died" % cpu)

        # Some backoff if we fail to run
        time.sleep(1.0)

assert os.path.exists(INPUT_DIR), "Invalid input directory"

if os.path.exists(OUTPUT_DIR):
    print("Deleting old output directory")
    shutil.rmtree(OUTPUT_DIR)

print("Creating output directory")
os.mkdir(OUTPUT_DIR)

# Disable AFL affinity as we do it better
os.environ["AFL_NO_AFFINITY"] = "1"

for cpu in range(0, NUM_CPUS):
    threading.Timer(0.0, do_work, args=[cpu]).start()

    # Let master stabilize first
    if cpu == 0:
        time.sleep(1.0)

while threading.active_count() > 1:
    time.sleep(5.0)

    try:
        subprocess.check_call(["afl-whatsup", "-s", OUTPUT_DIR])
    except:
        pass
