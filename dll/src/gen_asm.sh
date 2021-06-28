	i686-w64-mingw32-gcc-win32 -S -masm=intel ReflectiveLoader_orig.c -I ../../common/ -fverbose-asm -o ReflectiveLoader_orig_verbose.s -O
	i686-w64-mingw32-gcc-win32 -S -masm=intel ReflectiveLoader_orig.c -I ../../common/ -o ReflectiveLoader_orig.s -O
