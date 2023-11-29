//
// Created by rigon on 17.11.23.
//
#include <stdio.h>
#include <stdlib.h>

// Function to generate a random number within a specific range using a seed
int generateRandomNumber(int seed, int min, int max) {
    // Set the seed for the random number generator
    srand(seed);

    // Generate and return a random number within the specified range
    return min + rand() % (max - min + 1);
}

int main() {
    // Example of using the random number generator function with a seed and a specified range
    int seedValue = 57;  // You can change this seed value
    int minValue = 1;    // Minimum value of the range
    int maxValue = 3;  // Maximum value of the range


    // Use the function to generate a random number within the specified range
    int randomNumber = generateRandomNumber(seedValue, minValue, maxValue);

    // Display the result
    printf("The random Number to analyse Memcached with seed %d and range %d-%d is %d\n", seedValue, minValue, maxValue, randomNumber);

    return 0;
}
