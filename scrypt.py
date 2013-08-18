# Run "pip install scrypt" if you don't have scrypt library (http://www.tarsnap.com/scrypt.html) on your computer.
# Example usage:
#   python scrypto.py -e input_file.py output_file.enc mypassword1234
#   python scrypto.py -d encrypted.enc result.txt mypassword1234
#
# -*- coding: utf-8 -*-

import scrypt
import sys


def encrypt(inputfile, outputfile, password):
    with open(inputfile, "rb") as inp:
        data = inp.read()
        encrdata = scrypt.encrypt(data, password)
        with open(outputfile, "wb") as out:
            out.write(encrdata)


def decrypt(inputfile, outputfile, password):
    with open(inputfile, "rb") as inp:
        encdata = inp.read()
        data = scrypt.decrypt(encdata, password)
        with open(outputfile, "wb") as out:
            out.write(data)


def main():
    args = sys.argv[1:]

    if len(args) < 4:
        print "Usage: scrypto.py -[e|d] inputfile outputfile password"
        sys.exit(1)

    a = args.pop(0)

    if a == "-e":
        encrypt(args[0], args[1], args[2])
        print "File encrypted"
        sys.exit(0)
    elif a == "-d":
        decrypt(args[0], args[1], args[2])
        print "File decrypted"
        sys.exit(0)
    else:
        print "Invalid option: %s" % a
        print "Usage: scrypto.py -[e|d] inputfile outputfile password"
        sys.exit(1)


if __name__ == '__main__':
    main()
