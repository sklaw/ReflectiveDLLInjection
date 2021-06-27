#include "../dll/src/ReflectiveLoader.h"


int main() {
	printf("VirtualAlloc's hash= %x\n", _hash("VirtualAlloc"));
	printf("VirtualProtect's hash= %x\n", _hash("VirtualProtect"));
}
