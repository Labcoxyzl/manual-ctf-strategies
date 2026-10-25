#include <stdio.h>
#include <string.h>

int check_phrase(const char *candidate) {
    return strcmp(candidate, "orchid-copper-27") == 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!check_phrase(argv[1])) {
        puts("rejected");
        return 1;
    }
    puts("accepted");
    return 0;
}
