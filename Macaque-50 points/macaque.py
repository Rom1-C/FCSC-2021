#!/usr/bin/env python3
import os 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class Macaque():
    def __init__(self, k1, k2):
        self.k1 = k1
        self.k2 = k2
        self.bs = AES.block_size
        self.zero = b"\x00" * self.bs

    def tag(self, m):
        m = pad(m, self.bs)
        c1 = AES.new(self.k1, AES.MODE_CBC, iv = self.zero).encrypt(m)
        c2 = AES.new(self.k2, AES.MODE_CBC, iv = self.zero).encrypt(m)
        return c1[-self.bs:] + c2[-self.bs:]

    def verify(self, m, tag):
        return self.tag(m) == tag

def usage():
    print("Commands are:")
    print("|-> t: Authenticate a message")
    print("|-> v: Verify a couple (message, tag)")
    print("|-> q: Quit")

if __name__ == "__main__":

    S = set()
    singe = Macaque(os.urandom(16), os.urandom(16))

    while True:
        usage()
        cmd = input(">>> ")

        if not len(cmd):
            exit(1)

        if cmd not in ['t', 'v', 'q']:
            usage()
            continue

        if cmd == 'q':
            exit(0)

        if cmd == 't':
            if len(S) < 3:

                print("Message (hex):")
                message = bytes.fromhex(input(">>> "))
                if not len(message):
                    exit(1)

                tag = singe.tag(message)
                print(f"Tag (hex): {tag.hex()}")
                S.add(message)
            else:
                print("Error: you cannot use this command anymore.")

        elif cmd == 'v':
            print("Message (hex):")
            message = bytes.fromhex(input(">>> "))
            
            print("Tag (hex):")
            tag = bytes.fromhex(input(">>> "))
            
            check = singe.verify(message, tag)
            if check and message not in S:
                print(f"Congrats!! Here is the flag:")

            elif check and message in S:
                print("Valid!")

            else:
                print("Wrong tag. Try again.")


