import subprocess, re, os, toml, argparse

TERMINATE = 10 # Stop if drops > 10%
GRACE_PD = 5   # Grace period to allow for small/temporary spikes

def execute(cmd, executable):
    print(f"Starting {executable}")
    popen = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
    grace_pd = 0
    for stdout_line in iter(popen.stdout.readline, ''):
        print(stdout_line, end='')
        if 'SW Dropped' in stdout_line:
            num = re.findall('\d*\.*\d+\%', stdout_line)
            if not num:
                continue
            value = float(num[0].split('%')[0])
            if value > TERMINATE:
                grace_pd += 1
                if grace_pd < GRACE_PD:
                    continue
                print(f'{value}% dropped; terminating')
                pid = os.popen(f'pidof {executable}').read()
                os.system(f'sudo kill -INT {pid}')
                return True # Stop iterations

    return False # Continue

def main(args):
    # Config file (duration)
    config_file = args.config
    config = toml.load(config_file)
    config['online']['duration'] = int(args.duration)
    f = open(config_file, 'w')
    toml.dump(config, f)
    f.close()

    # Cmd
    executable = f'/home/tcr6/retina/target/release/{args.binary}'
    cmd = f'sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error {executable} --config {config_file}'
    print(cmd)

    outfiles = [f'{outdir}/{i}_{args.duration}s_{args.outfile}' for i in range(int(args.iterations))]

    iters = 0
    for outfile in outfiles:
        cmd_i = cmd + f' --outfile {outfile}'
        stop = execute(cmd_i, executable)
        iters += 1
        if stop:
            print(f"Terminated at {iters} iterations")
            break



def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--binary')
    parser.add_argument('-d', '--duration')
    parser.add_argument('-i', '--iterations')
    parser.add_argument('-c', '--config')
    parser.add_argument('-o', '--outfile')
    parser.add_argument('-d', '--outdir')
    return parser.parse_args()

if __name__ == '__main__':
    print("Start running program...")
    main(parse_args())