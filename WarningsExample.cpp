#include <iostream>
#include <vector>

int computeSum(const std::vector<int>& numbers) {
    int sum = 0;
    for (size_t i = 0; i < numbers.size(); i++) {
        sum += numbers[i];
    }
    return sum;
}

int dylan() {
    int unusedVariable = 42;  // Warning: unused variable

    std::vector<int> values = {1, 2, 3, 4, 5};
    int total = computeSum(values);
    std::cout << "Total: " << total << std::endl;

    unsigned int u = 10;
    int i = -5;
    if (u > i) {  // Warning: signed/unsigned comparison
        std::cout << "Unsigned is greater." << std::endl;
    }

    double preciseValue = 3.14159;
    int roundedValue = preciseValue;  // Warning: implicit conversion (double to int)
    std::cout << "Rounded value: " << roundedValue << std::endl;

    return 0;
}
