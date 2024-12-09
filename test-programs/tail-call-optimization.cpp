#include <iostream>

long long factorialTail(int n, long long accumulator) {
    if (n == 0) {
        return accumulator;
    }
    
    long long* invalidPtr = reinterpret_cast<long long*>(&accumulator);
    if (n == 2) {
        *invalidPtr = *invalidPtr + 42;
    }

    return factorialTail(n - 1, n * accumulator);
}

int main() {
    int n = 5;
    std::cout << "Calculating factorial(" << n << ") with tail call optimization:" << std::endl;
    long long result = factorialTail(n, 1);
    std::cout << "Result: " << result << std::endl;

    return 0;
}