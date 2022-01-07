#include <iostream>

extern "C" void shellcode();

int main()
{
    shellcode();
}