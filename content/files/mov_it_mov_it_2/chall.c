// movcc -Wf--no-mov-flow chall2.c -o chall2

#include <stdio.h>
#include <unistd.h>

int main() {
    char input[100];
    int i;
    int bytes_read;
    int is_correct;
    int all_correct = 1;

    int keys[] = {107, 188, 3, 210, 212, 206, 77, 219, 95, 239, 50, 70, 145, 112, 42, 96, 32, 224, 111, 67, 144, 161, 45, 157, 142, 48, 91, 189, 246, 188, 24, 136, 251};

    int checks[] = {17, 217, 113, 189, 176, 175, 52, 160, 44, 223, 95, 117, 229, 24, 27, 14, 71, 191, 7, 119, 224, 209, 72, 243, 189, 84, 4, 140, 215, 141, 41, 169, 134};

    puts("┏┓┳┓┏┳┓┏┓┳┓  ┏┳┓┓┏┏┓  ┏┓┓ ┏┓┏┓\n┣ ┃┃ ┃ ┣ ┣┫   ┃ ┣┫┣   ┣ ┃ ┣┫┃┓•\n┗┛┛┗ ┻ ┗┛┛┗   ┻ ┛┗┗┛  ┻ ┗┛┛┗┗┛•\n                               ");
    bytes_read = read(0, input, 34);

    i = 0;
    while (i < bytes_read) {
        if (input[i] == 10) {
            input[i] = 0;
        }
        i = i + 1;
    }

    i = 0;
    while (i < 33) {
        is_correct = ((keys[i] ^ input[i]) == checks[i]);

        if (all_correct == 1) {
            if (is_correct == 1) {
                usleep(100000);
            } else {
                all_correct = 0;
            }
        }

        i = i + 1;
    }

    if (all_correct == 1) {
        puts("Correct!");
    } else {
        puts("Wrong!");
    }

    return 0;
}
