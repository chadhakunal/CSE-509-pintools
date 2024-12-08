#include <iostream>

// Tail-recursive factorial with a logical manipulation to cause address mismatch
long long factorialTail(int n, long long accumulator) {
    if (n == 0) {
        return accumulator;
    }
    
    // Manipulate the accumulator address indirectly
    long long* invalidPtr = reinterpret_cast<long long*>(&accumulator);
    if (n == 2) {
        // Introduce a mismatch in the accumulator's value
        *invalidPtr = *invalidPtr + 42; // Corrupt accumulator address during computation
    }

    // Tail call (optimizable by the compiler)
    return factorialTail(n - 1, n * accumulator);
}

int main() {
    int n = 5;
    std::cout << "Calculating factorial(" << n << ") with tail call optimization:" << std::endl;

    // Start with accumulator = 1
    long long result = factorialTail(n, 1);

    // Display result (should be incorrect due to address mismatch)
    std::cout << "Result: " << result << std::endl;

    return 0;
}