import sys
import os
from pathlib import Path


MAX_PASSWORD_LENGTH = 31
ALPHABET = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
ADDR_EQUAL = "0x401d83"
ADDR_NOT_EQUAL = "0x401d89"
TRACE_TOOL_PATH = "/home/isl/pin-3.11-97998-g7ecce2dac-gcc-linux-master/source/tools/SGXTrace"
TMP_TRACES_FOLDER = Path("/home/isl/t2_2/traces")
TMP_TRACES_FOLDER.mkdir(parents=True, exist_ok=True)
TMP_TRACE_FILE_PATH = TMP_TRACES_FOLDER.joinpath("tmp_trace.txt")


def create_trace(guess):
    trace_program = f"../../../pin -t ./obj-intel64/SGXTrace.so -o {TMP_TRACE_FILE_PATH} -trace 1 -- /home/isl/t2_2/password_checker_2 {guess} >/dev/null 2>&1"
    os.system(trace_program)


def get_password_length():
    create_trace(ALPHABET[0] * MAX_PASSWORD_LENGTH)
    password_length = 0

    with open(TMP_TRACE_FILE_PATH, 'r') as trace:
        for line in trace:
            curr_line = line.split(":")
            addr = curr_line[1]
            if curr_line[0] == "E" and (ADDR_EQUAL.lower() == addr or ADDR_NOT_EQUAL.lower() == addr):
                password_length += 1

    return password_length


def hackerman():
    password_length = get_password_length()
    password_chars = dict()

    for letter in ALPHABET:
        i = 0
        create_trace(letter * password_length)

        with open(TMP_TRACE_FILE_PATH, 'r') as trace:
            for line in trace:
                curr_line = line.split(":")
                if curr_line[0] == "E":
                    addr = curr_line[1].lower()
                    if ADDR_NOT_EQUAL.lower() == addr:
                        i += 1
                    elif ADDR_EQUAL.lower() == addr:
                        password_chars[i] = letter
                        i += 1

    password = ""
    all_indices = password_chars.keys()
    for index in range(0, 1 + max(all_indices)):
        password += password_chars[index] if index in all_indices else "_"

    return password, ("_" not in password)


def main():
    if len(sys.argv) != 2:
        print("Not enough arguments: <id> required")
        exit()

    os.chdir(TRACE_TOOL_PATH)

    password, complete = hackerman()

    output_folder = Path("/home/isl/t2_2/output/")
    output_folder.mkdir(parents=True, exist_ok=True)
    output_file_path = output_folder.joinpath("oput_" + sys.argv[1])

    with open(output_file_path, "w") as output_file:
        output_file.write(password + (",complete" if complete else ",partial"))


if __name__ == "__main__":
    main()
