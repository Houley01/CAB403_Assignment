#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE_SIZE 256
#define MAX_ADDRESS_SIZE 13
#define MAX_FILE_LENGTH 64
#define TIMESTAMP_LENGTH 20

char *timestamp()
{
    time_t t = time(&t);
    char *str = (char *)malloc(TIMESTAMP_LENGTH * sizeof(char));
    sprintf(str, "%d-%02d-%02d %02d:%02d:%02d", localtime(&t)->tm_year + 1900, localtime(&t)->tm_mon + 1, localtime(&t)->tm_mday, localtime(&t)->tm_hour, localtime(&t)->tm_min, localtime(&t)->tm_sec);
    str[20] = '\0';
    return str;
}

int getProcMemoryInfo(int pid, char map[MAX_FILE_LENGTH])
{
    // Storing the line in here
    char line[MAX_LINE_SIZE];
    // Char buffers to store the memory addresses
    char addressOne[MAX_ADDRESS_SIZE];
    char addressTwo[MAX_ADDRESS_SIZE];
    int memoryTotal = 0;

    FILE *fp;
    // Example file
    fp = fopen(map, "r");
    // Counter for spaces until we reach the inode
    int spaces = 0;

    // Reads until end of line and stores into line
    while (EOF != fscanf(fp, "%[^\n]\n", line))
    {
        // Looping over line
        for (int i = 0; i < MAX_LINE_SIZE; i++)
        {
            char temp = line[i];
            if (temp == ' ')
            {
                spaces++;
            }
            // If we have reached the part in the line where the inode is, replace all further indexes to EOL char
            if (spaces == 4)
            {
                // This will be the second character after the first number in the inode
                line[i + 2] = '\0';

                // We get the line as up to the first number in the inode if it's not 0
                // Only interested in those which are inode 0
                if (line[i + 1] == '0')
                {
                    // Print the line as it stands
                    // printf("%s\n", line);

                    // Store the first listed address to address two
                    for (int j = 0; j < 12; j++)
                    {
                        addressTwo[j] = line[j];
                    }
                    // Store the second listed address to address one
                    for (int j = 0; j < 12; j++)
                    {
                        addressOne[j] = line[j + 13];
                    }

                    // Set the new line chars as we still need them even when converted to longs
                    addressOne[12] = '\0';
                    addressTwo[12] = '\0';

                    // Convert the strings into hex (base 16)
                    long addressOneLong = strtol(addressOne, NULL, 16);
                    long addressTwoLong = strtol(addressTwo, NULL, 16);

                    // We have finally gotten the memory difference!
                    long memoryUsed = (addressOneLong - addressTwoLong);
                    memoryTotal += memoryUsed;
                }
                // Reset counter for new line
                spaces = 0;
                // Break out and begin checking the next line if not EOF
                break;
            }
        }
    }
    fclose(fp);

    return memoryTotal;
}