import hashlib
import random
from random import sample
import threading
import coloredlogs, logging
from queue import Queue
from statistics import stdev, mean
from math import log

nr_threads = 10
max_randint = 100000000000
nonce_max_jump = 1000
difficulty = 4
score_limit = 0.1
genesis_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
genesis_hash = genesis_hash[:-difficulty] + "0" * difficulty


def similar(a, b):
    sum = 0
    for i in range(64):
        sum += abs(int(a[i], 16)-int(b[i], 16))

    max = 15*64
    frac = sum/max
    sim = 1-frac

    return sim


def hash(content, times=1):
    if times > 1:  # Repeated hash for ping calculation
        return hash(hashlib.sha256(content.encode()).hexdigest(), times-1)
    elif times == 0:
        return content
    else:
        return hashlib.sha256(content.encode()).hexdigest()


# Return empty string if content is None
def xstr(s):
    return '' if s is None else str(s)


def mine(content=None):
    nonce = random.randrange(max_randint)
    while True:
        hashed = hash(xstr(content)+str(nonce))
        if hashed[-difficulty:] == "0" * difficulty:
            break
        nonce += random.randrange(nonce_max_jump)
    return hashed


def get_blockstring(last_block):
    return str(list(last_block.queue)[0])


def evaluate(curr_block, permuted):
    if len(permuted) < 2:
        return 0

    sims = []
    for idx, curr_hash in enumerate(permuted):
        similarity = similar(curr_hash, hash(curr_block, idx))
        sims.append(similarity)

    avg = mean(sims)
    spread = stdev(sims)

    # TODO: Find other solution than using log length of list - this incentivizes spam!!
    # TODO: YOu put it there temporarily because just avg*spread was higher for smaller lists, which is undesirable
    score = avg*spread*log(len(permuted))
    return score


# TODO: When two solutions found by 2 diff threads at the same time, the first one is overwritten by second..
# TODO: So you gotta figure out a consensus mechanism

# TODO: If a thread is putting a hash in an empty queue, which immediately matches difficulty, everyone solves block
# TODO: So you gotta find a way to prevent that somehow?
def verifier():
    put_own_ping = False

    while True:
        curr_block = get_blockstring(last_block)

        if not put_own_ping:
            hashed = mine()

            if curr_block == get_blockstring(last_block):
                q.put(str(hashed))
                logger.debug("Put hash " + str(hashed) + " making q size " + str(q.qsize()) + " for " + curr_block)
                put_own_ping = True
            else:
                logger.error("Got signalled it was found before me.. Wanted to put hash " + str(hashed)
                             + " but that was for " + curr_block + ", curr is actually: " + get_blockstring(last_block))

        else:
            ping_list = list(q.queue)
            if len(ping_list) == 0:
                put_own_ping = False
                logger.error("Got signalled it was found before me.. putting own hash again.. (via len pinglist)")
                continue

            permuted = sample(ping_list, len(ping_list))

            mined_candidate = str(mine(str(permuted)))

            # Reason we do this check over and over is that while this thread runs, there might have been an update
            # On what get_blockstring returns
            if curr_block != get_blockstring(last_block):  # Restart
                logger.error("Got signalled it was found before me.. putting own hash again.. (via currblock diff)")
                put_own_ping = False
                continue

            score = evaluate(curr_block, permuted)

            if score > score_limit:

                logger.debug("Solved block of size " + str(len(permuted)) + ", new hash is " + mined_candidate)

                # Mutex to ensure atomicity of execution
                with q.mutex: q.queue.clear()
                with last_block.mutex: last_block.queue.clear()

                last_block.put(mined_candidate)
                put_own_ping = False
                logger.error("Got signalled it was found BY me.. putting own hash again..")

            else:
                logger.warning("Only achieved " + str(score) + " score for " + curr_block + " using "
                               + str(len(ping_list)) + " pings")


def spawn(amount, worker):
    threads = []
    for i in range(amount):
        t = threading.Thread(name='verifier_' + str(i), target=worker)
        threads.append(t)

        t.start()
    return threads


logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', logger=logger, fmt='(%(threadName)-10s) %(message)s')

# Queue is used here as a thread-safe messaging structure between threads
q = Queue()
last_block = Queue()

# Threadsafe genesis block
last_block.put(genesis_hash)

verifier_threads = spawn(amount=nr_threads, worker=verifier)
