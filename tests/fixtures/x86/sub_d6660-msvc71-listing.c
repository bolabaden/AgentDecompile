typedef unsigned char byte;
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned short ushort;
typedef unsigned char bool;
typedef int code();
typedef int BOOL;
typedef void *HANDLE;
typedef void *HWND;
typedef const char *LPCSTR;
typedef char *LPSTR;
#ifndef NULL
#define NULL ((void*)0)
#endif
extern char *PTR_sub_d6660_007465a4;

void sub_d6660(byte param_1)

{
  undefined4 *in_ECX;
  
  *in_ECX = &PTR_sub_d6660_007465a4;
  if ((void *)in_ECX[1] != (void *)0x0) {
    _free((void *)in_ECX[1]);
    in_ECX[1] = 0;
  }
  if ((void *)in_ECX[4] != (void *)0x0) {
    _free((void *)in_ECX[4]);
    in_ECX[4] = 0;
  }
  if ((param_1 & 1) != 0) {
    _free(in_ECX);
  }
  return;
}
