#include <stdio.h>
#include <stdlib.h>
// declare
extern void rust_capitalize(char *);

int main()
{
    char str[] = "hello world";
    printf("%s\n", str);
    rust_capitalize(str);
    printf("%s\n", str);
    return 0;
}