#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char *timestamp()
{
    time_t t = time(&t);
    char *str = (char *)malloc(19 * sizeof(char)); // Not mallocing here results in a segmentation fault
    // sprintf is similar to formating a printf internally and then assigning that to our buffer
    sprintf(str, "%d-%02d-%02d %02d:%02d:%02d", localtime(&t)->tm_year + 1900, localtime(&t)->tm_mon + 1, localtime(&t)->tm_mday, localtime(&t)->tm_hour, localtime(&t)->tm_min, localtime(&t)->tm_sec);
    return str;
}