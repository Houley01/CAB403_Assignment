#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    // Storing the line in here
    char line[1024];
    // Char buffers to store the memory addresses
    char addressOne[13];
    char addressTwo[13];
    int memoryTotal = 0;

    FILE *fp;
    // Example file
    fp = fopen("test", "r");
    // Counter for spaces until we reach the inode
    int counter = 0;

    // Reads until end of line and stores into line
    while (EOF != fscanf(fp, "%[^\n]\n", line))
    {
        // Looping over line
        for (int i = 0; i < 1024; i++)
        {
            char temp = line[i];
            if (temp == ' ')
            {
                counter++;
            }
            // If we have reached the part in the line where the inode is, replace all further indexes to EOL char
            if (counter == 4)
            {
                // This will be the second character after the first number in the inode
                line[i + 2] = '\0';

                // We get the line as up to the first number in the inode if it's not 0
                // Only interested in those which are inode 0
                if (line[i + 1] == '0')
                {
                    // Print the line as it stands
                    printf("%s\n", line);

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
                    long memoryUsed = (addressOneLong - addressTwoLong) / 1000;
                    memoryTotal += memoryUsed;

                    printf("Address One: %ld (hex)\n", addressOneLong);
                    printf("Address Two: %ld (hex)\n", addressTwoLong);
                    printf("Equals: %ldK\n\n", memoryUsed);
                }
                // Reset counter for new line
                counter = 0;
                break;
            }
        }
    }
    printf("This process is using %dK total memory\n", memoryTotal);
    fclose(fp);
    return 0;
}