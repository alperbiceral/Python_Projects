import random, sys, pyperclip

def main():
    try:
        length = int(sys.argv[1])
    except Exception as ex:
        print("ERROR...\nUSAGE for creating a password with 20 characters: python3 passgen.py 20")
        print("Exception:", ex)
        sys.exit(1)

    if length <= 0:
        print("ERROR...\nPASSWORD LENGTH MUST BE GREATER THAN 0")
        sys.exit(2)

    chars = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM!'^+%&/()=?_é<>£#${[]}\|~,.;:0123456789"

    pwd = ""
    for i in range(length):
        pwd += str(random.choice(chars))

    try:
        pyperclip.copy(pwd)
        print("Password is copied to the clipboard...")
    except Exception as ex:
        print("Password Cannot be Copied...\nException:", ex)
        sys.exit(3)

    return

if __name__ == "__main__":
    main()
