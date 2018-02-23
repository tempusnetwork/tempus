from pki import pubkey_to_addr, get_kp
import multiprocessing
import os


def vanity():
    found = False
    phrase = "tempus"
    length = len(phrase)
    while not found:
        keys = get_kp()
        pubk = keys[0]
        privk = keys[1]
        addr = pubkey_to_addr(pubk)
        if addr[:length].lower() == phrase:
            found = True
            result = {'pubk': pubk, 'privk': privk, 'addr': addr}
            print(result)


# Run on all cores minus one
if __name__ == "__main__" :
    count = multiprocessing.cpu_count()-1
    for process_idx in range(count):
        p = multiprocessing.Process(target=vanity)
        os.system("taskset -p -c %d %d" % (process_idx % count, os.getpid()))
        p.start()
