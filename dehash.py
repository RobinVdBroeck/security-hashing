import itertools
import hashlib
from time import time
from typing import Set, Dict, Iterator, Callable
from tqdm import tqdm


def read_hashes(path: str) -> Iterator[str]:
    with open(path, "r") as f:
        line = f.readline()
        while line:
            hash = line.split(":")[0]
            yield hash
            line = f.readline()


def read_dict(path: str) -> Iterator[str]:
    with open(path, "r") as f:
        line = f.readline()
        while line:
            yield line.rstrip()
            line = f.readline()


def md5(to_hash: str) -> str:
    return hashlib.md5(to_hash.encode("utf-8")).hexdigest()


def bruteforce_attack(hash_algorithm: Callable[[str], str], hashes: Set[str], alphabet: str, min_size: int = 0,
                      max_size: int = 10) -> Dict[str, str]:
    """Maps hashes to passwords using bruteforce"""
    found = dict()

    alphabet_size = len(alphabet)

    bruteforce_size = sum([pow(alphabet_size, i) for i in range(min_size, max_size + 1)])

    # Setup progress bar
    with tqdm(total=bruteforce_size) as progress:
        # Only print stats here to minimize chance for desync
        progress.write("Alphabet size: {}".format(alphabet_size))
        progress.write(
            "Bruteforce going to test {} password between {} and {} chars long".format(bruteforce_size, min_size,
                                                                                       max_size))

        for size in range(min_size, max_size + 1):
            progress.write("Bruteforcing passwords with size {}".format(size))
            for password_list in itertools.product(alphabet, repeat=size):
                password = "".join(password_list)
                hashed_password = hash_algorithm(password)

                if hashes.__contains__(hashed_password):
                    progress.write("Found password for hash {}".format(hashed_password))
                    found[hashed_password] = password
                    if len(hashes) == len(found):
                        return found
                progress.update()

    progress.write("Found {} passwords".format(len(found)))
    return found


def dictionary_attack(hash_algorithm: Callable[[str], str], hashes: Set[str], dictionary: Iterator[str],
                      print_found=False) -> Dict[
    str, str]:
    found = dict()

    for word in tqdm(dictionary):
        hashed_word = hash_algorithm(word)
        if hashes.__contains__(hashed_word):
            if print_found:
                tqdm.write("Found password for hash {}".format(hashed_word))
            found[hashed_word] = word

    return found


if __name__ == "__main__":
    hashes = set()

    for read_hash in read_hashes("large-md5.txt"):
        hashes.add(read_hash)

    # lowercase_chars = "abcdefghijklmnopqrstuvwxyz"
    # uppercase_chars = lowercase_chars.upper()
    # numbers = "1234567890"
    # special_chars = "!@#.,$?"
    # all_chars = lowercase_chars + uppercase_chars + numbers + special_chars

    # result = bruteforce(md5, hashes, all_chars, min_size=5, max_size=5)

    timer_start = time()
    result = dictionary_attack(md5, hashes, read_dict("dict.txt"))
    timer_end = time()
    timer = timer_end - timer_start

    amount_found = len(result)
    amount_total = len(hashes)

    print("========STATS========")
    print("Found: {}".format(amount_found))
    print("Total: {}".format(amount_total))
    print("Percentage: {}%".format((amount_found / amount_total) * 100))
    print("Time: {} seconds".format(timer))
    print("Found per second: {}".format(amount_found / timer))
