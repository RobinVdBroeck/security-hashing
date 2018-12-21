# Hashing

Tested using python 3.6

```bash
pip install -r requirements.txt
python dehash.py
```

## Notes

I tested this using md5 because it's very insecure for passwords. It's designed to check consistency of files, not to store passwords

Source: https://www.quora.com/In-cryptography-why-are-MD5-and-SHA1-called-broken-algorithms

## Bruteforce solution

### Paramaters

\# Hashes: 6.058.239 \
Alphabet: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#.,\$? \
Alphabet size: 69 \
Minimum password size: 1 \
Maximum password size: 4

### Result

| Key              | Value         |
| ---------------- | ------------- |
| Found            | 18.117        |
| Total            | 6.058.239     |
| Percentage       | 0,30%         |
| Time             | 41,06 seconds |
| Found per second | 441,28        |

## Dictionary attack:

### Paramaters

\# Hashes: 6.058.239 \
Dictionary used: 1.000.000 most used passwords from https://github.com/danielmiessler/SecLists

### Result

| Key              | Value        |
| ---------------- | ------------ |
| Found            | 215.534      |
| Total            | 6.058.239    |
| Percentage       | 3,56%        |
| Time             | 1,71 seconds |
| Found per second | 126053,34    |

## Conclusion

- The bruteforce algorithm is O(alphabet_size ^ password_length). So bruteforce can be countered by using long passwords with "special chars" like "[" or ",". \
  To calculate how many iterations are needed to bruteforce your password you can use this pseudocode:

  ```pseudocode
  n = 1
  sum = 0
  while n <= password_size:
    sum = sum + (alphabet_size power n)
    n = n + 1
  ```

  The great thing about bruteforce however is that we can get ALL passwords given enough time.

  Note: While it is true that given enough time we can get all passwords, it has to be noted however that if we have a
  very secure password like "SsCi#evx2gxcnl0EwJAt5zaOWQHKYyIm" and a good hashing algorithm like sha256 it would take
  longer than the universe exists. But bruteforcing is still an complete algorithm.

- Dictionary attack is very fast if you have a common password like "password". The algorithm is O(n) where n is the
  amount of passwords. However, this is not complete. Your password will not be found if it's not in the dictionary the attacker
  uses

- Use a good algorithm that takes long to counter bruteforce attacks. The slower the algorithm, the better.

## Extra notes

My hashing algorithm is VERY slow and can't handle that many iterations per second. You can do this alot faster using
specialized software that runs on GPUs.
