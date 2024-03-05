import re, argparse

def main():
    #python3 str_replace.py -f source_file -d delete_string -i insert_string

    try:
        parser = argparse.ArgumentParser(description="Replace all strings with a new string in a file", prefix_chars="-")
        parser.add_argument("-I", dest="Ignore_Case", action="store_const", const=re.IGNORECASE, default=re.VERBOSE, help="make the string case-insensitive. Default is case-sensitive")
        parser.add_argument("-f", "--file", dest="src_file", action="store", nargs="?", help="file that changes are made in")
        parser.add_argument("-d", "--delete", dest="delete_str", action="store", nargs="?", help="string to be deleted")
        parser.add_argument("-i", "--insert", dest="insert_str", action="store", nargs="?", help="string to be inserted")
        args = parser.parse_args()

        with open(args.src_file, "r") as source_file:
            src_text = source_file.read()
            
            str_regex = re.compile(args.delete_str, args.Ignore_Case)
            new_text = str_regex.sub(args.insert_str, src_text)

        with open(args.src_file, "w") as dest_file:
            dest_file.write(new_text)
    except Exception as ex:
        print("ERROR...\n", ex)

    return

if __name__ == "__main__":
    main()