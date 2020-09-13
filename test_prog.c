#include <stdio.h>

int main(int argc, char *argv[])
{
    printf("-----------------\n");
    printf("Test program. arg count: %d\n", argc);
    for (int i = 0; i < argc; i++)
    {
        printf("%s\n", argv[i]);
    }

    printf("-----------------\n");
    return 5;
}