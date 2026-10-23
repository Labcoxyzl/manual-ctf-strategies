#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        puts("usage: check_input WORD");
        return 2;
    }
    if (strcmp(argv[1], "harbor") == 0) {
        puts("accepted");
        return 0;
    }
    puts("rejected");
    return 1;
}
