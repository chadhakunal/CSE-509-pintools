#include <iostream>
#include <thread>  // Required for std::thread

using namespace std;

void threadFunction() {
    char buffer[16];  // Small buffer
    std::cout << "Enter some input: ";
    std::cin >> buffer;
    std::cout << "You entered: " << buffer << std::endl;
}

void vulnerableFunction() {
    threadFunction();
}

int main() {
    std::thread t1(vulnerableFunction);  // Create a thread
    t1.join();  // Wait for the thread to finish
    return 0;
}
