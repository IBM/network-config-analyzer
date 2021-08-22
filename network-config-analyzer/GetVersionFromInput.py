import sys
import os

def main():
    confirmation = ''
    while confirmation != 'Y' and confirmation != 'y':
        version = input('Please enter the version number: ')
        print('The version number is:', version)
        while True:
            confirmation = input('Please confirm [Y/N]:')
            if confirmation == 'Y' or confirmation == 'y' or confirmation == 'N' or confirmation == 'n':
                break
    return version

if __name__ == "__main__":
    sys.stdout.write(main())
    sys.exit(0)
