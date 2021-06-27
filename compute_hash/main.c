#include "../dll/src/ReflectiveLoader.h"


int main() {
	printf("VirtualAlloc hash= %x\n", _hash("VirtualAlloc"));
	printf("VirtualProtect hash= %x\n", _hash("VirtualProtect"));
	printf(".text hash= %x\n", _hash(".text"));
}
