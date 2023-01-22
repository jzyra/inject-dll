# inject-dll
This tool allows you to inject a DLL into a running Windows process.
Normally, it bypass all static antivirus scans.
It is then possible to execute code in this process and set up hooks on the native functions of the Windows API.

# Build

For build this tool for Windows, you can use MinGW.

    gcc.exe -O2 main.c -o inject-dll.exe

# Usage

There are two mandatory arguments.

    inject-dll.exe DLL_PATH PID
    DLL_PATH : Path to the DLL file who must be injected.
    PID      : PID of the target Windows process.


# Example

    inject-dll.exe C:\hook.dll 16472
