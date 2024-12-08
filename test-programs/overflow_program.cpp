#include <iostream>
#include <cstring>

void vulnerableFunction() {
    char buffer[16]; // Small buffer
    std::cout << "Enter some input: ";
    std::cin >> buffer;
    std::cout << "You entered: " << buffer << std::endl;
}

void secureFunction() {
    std::cout << "Secure function executed unexpectedly!" << std::endl;
}

int main() {
    std::cout << "Calling vulnerableFunction()" << std::endl;
    vulnerableFunction();
    std::cout << "Returned safely from vulnerableFunction()" << std::endl;
    return 0;
}