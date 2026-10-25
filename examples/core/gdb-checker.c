#include <stdio.h>
#include <string.h>
int check(const char *s) {
    char expected[] = {0x54, 0x52, 0x41, 0x43, 0x45, 0};
    for (int i=0; i<5; ++i) expected[i] ^= 0x20;
    return strcmp(s, expected) == 0;
}
int main(int argc, char **argv) {
    if (argc != 2) { puts("usage: checker WORD"); return 2; }
    if (check(argv[1])) { puts("accepted"); return 0; }
    puts("rejected"); return 1;
}
