import subprocess
import argparse
import os
import re
import json

SUBSCRIPTIONS = [50, 100, 500, 1000, 2000, 3500, 5500, 8000, 10000]
# SUBSCRIPTIONS = [1]

def execute(cmd, executable):
    dropped = 0
    processed = 0
    ingress = 0
    good = 0
    popen = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ''):
        print(stdout_line, end='') 
        if 'DROPPED' in stdout_line:
            num = re.findall('\d*\.*\d+\%', stdout_line)
            if not num: continue
            dropped = float(num[0].split('%')[0])
            print(f'Total DROPPED {dropped}%...')
        if 'AVERAGE' in stdout_line:
            num = re.findall('\d*\.\d+ bps', stdout_line)
            if not num: continue
            num = float(num[0].split('bps')[0])
            if 'Process' in stdout_line:
                processed = num
            elif 'Good' in stdout_line:
                good = num
            elif 'Ingress' in stdout_line:
                ingress = num

    print("Done running...")
    popen.stdout.close()
    popen.wait()
    return (processed, good, ingress, dropped)

def build_file(num_subscriptions, binary, http_only, non_overlapping): 
    cmd = "python3 examples/basic/filtergen.py " + str(num_subscriptions)
    if http_only: 
        cmd += " http_only"
    if non_overlapping:
        cmd += " non_overlapping"
    os.system(cmd)
    os.system("cargo build --bin " + binary + " --release")

def main(args):
    binary = args.binary
    executable = "./target/release/" + binary
    result = {}
    config_file = args.config
    for num_subscriptions in SUBSCRIPTIONS: 
        build_file(num_subscriptions, binary, args.http_only, args.non_overlapping)
        run_cmd = f'sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error {executable} -c {config_file}'
        processed, good, ingress, dropped = execute(run_cmd, executable)
        result[num_subscriptions] = { 'processed' : processed, 'good' : good, 'ingress' : ingress, 'dropped' : dropped }
    with open(args.outfile, 'w') as f: 
        json.dump(result, f)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--binary')
    parser.add_argument('-c', '--config')
    parser.add_argument('-o', '--outfile')
    parser.add_argument('--http_only', action="store_true")
    parser.add_argument('--non_overlapping', action="store_true")
    return parser.parse_args()

if __name__ == '__main__':
    main(parse_args())