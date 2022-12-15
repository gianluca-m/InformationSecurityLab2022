from pathlib import Path
import sys


ADDR_DISTANCE_PLUS = "0x401286"
ADDR_DISTANCE_NEG = "0x40126F"
ADDR_EQUAL = "0x401211"
ADDR_SHIFT = "0x401292"

A_CODE = ord('a')
SHIFT_AMOUNT = 26


def hackerman(traces_folder):
    password_chars = dict()
    password_len = -1

    all_traces = Path(traces_folder).glob('*.txt')
    for trace_file_name in all_traces:
        i = 0
        distance = 0
        distance_negative = False
        current_guess = ''.join(Path(trace_file_name).name.split('.')[:-1])
        current_guess_len = len(current_guess)

        with open(trace_file_name, "r") as current_trace:
            for line in current_trace:
                current_line = line.lower()

                if ADDR_DISTANCE_PLUS.lower() in current_line:      # for (j = distance; j > 0; j--)
                    distance += 1

                if ADDR_DISTANCE_NEG.lower() in current_line:       # if (distance < 0)
                    distance_negative = True

                if ADDR_EQUAL.lower() in current_line:              # if (p[pos] == i[pos])
                    password_chars[i] = current_guess[i - 1]                

                if ADDR_SHIFT.lower() in current_line:              # ADD(p[pos], i[pos]);    
                    current_guess_char = current_guess[i - 1]
                    if distance > 0 and distance_negative:
                        password_chars[i] = chr(A_CODE + ((distance - A_CODE + ord(current_guess_char) - 1) % SHIFT_AMOUNT))
                    elif distance > 0 and not distance_negative:
                        password_chars[i] = chr(distance + ord(current_guess_char) - 1)

                    i += 1
                    distance_negative = False
                    distance = 0

            if i < current_guess_len:
                password_len = i - 1

    password = ""
    all_indices = password_chars.keys()
    for index in range(1, 1 + max(all_indices)):
        password += password_chars[index] if index in all_indices else "_"

    complete = False
    if 0 <= password_len:
        complete = True
    if "_" in password:
        complete = False

    return password, complete


def main():
    if len(sys.argv) != 3:
        print("Not enough arguments: <path_to_traces> and <id> required")
        exit()

    password, complete = hackerman(sys.argv[1])

    output_folder = Path("/home/isl/t2_1/output/")
    output_folder.mkdir(parents=True, exist_ok=True)
    output_file_path = output_folder.joinpath("oput_" + sys.argv[2])

    with open(output_file_path, "w") as output_file:
        output_file.write(password + (",copmlete" if complete else ",partial"))


if __name__ == "__main__":
    main()
