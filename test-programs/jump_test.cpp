#include <iostream>
#include <csetjmp>

jmp_buf buffer;

void functionA() {
    std::cout << "Entering functionA" << std::endl;
    longjmp(buffer, 1); // Jump back to the saved point
    std::cout << "This will not be printed." << std::endl;
}

void functionB() {
    std::cout << "Entering functionB" << std::endl;
    functionA();
    std::cout << "Exiting functionB" << std::endl;
}

int main() {
    if (setjmp(buffer) == 0) {
        std::cout << "Calling functionB()" << std::endl;
        functionB();
    } else {
        std::cout << "Back in main() after longjmp." << std::endl;
    }
    return 0;
}