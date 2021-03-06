// CodeCacheDetectionByCode.cpp : Defines the entry point for the console application.
//
// WinDBG
// pin.exe -- F:\Binarios\CodeCacheDetectionByCode.exe
// No x32dbg
// findallmem 01211000,90 90 50 58
// s - b 0 L ? 80000000 90 90 50 58

#include<stdlib.h>
#include "stdio.h"


// Origem: https://msdn.microsoft.com/pt-br/library/s58ftw19.aspx
#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION
#include <excpt.h>
#define _CRT_SECURE_NO_WARNINGS
#define UNINITIALIZED 0xFFFFFFFF

#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <vector>
#include <TlHelp32.h> //PROCESSENTRY
// #include "MemUpdateMapInformations.h" vs #include <MemUpdateMapInformations.h>
// http://stackoverflow.com/a/7790180
#include "MemUpdateMapInformations.h"

#include <string.h>

// De acordo com:
// https://www.blackhat.com/docs/asia-16/materials/asia-16-Sun-Break-Out-Of-The-Truman-Show-Active-Detection-And-Escape-Of-Dynamic-Binary-Instrumentation.pdf
// Signature can be certain code or data
#define padrao 1

void test()
{
	// Padrao default
	#ifndef padrao
	__asm {
		nop
		nop
		push eax
		pop eax
	}
	#endif
	// Padrao 1
	#ifdef padrao
	__asm {
		// Operacoes com o registrador EBX sao reescritas pelo PIN
		// mov ebx,0x12345678
		mov eax,0x12345678
	}
	#endif


	printf("\ntest() address: %x\n", &test);
	printf("\nExecutou instrucoes asm\n");
}

unsigned char* search(int startAddress, int endAddress)
{
	unsigned char* data;
	int sig_count = 0;
	int j = 0;

	int address = startAddress;
	data = (unsigned char*)address;
	// printf("0x%x\n",data);
	while(data < (unsigned char*)endAddress) {
		__try {		
			#ifndef padrao
			if (data[0] == 0x90 &&
				data[1] == 0x90 &&
				data[2] == 0x50 &&
				data[3] == 0x58)
			#endif
			#ifdef padrao
				// if (data[0] == 0xBB &&
				if (data[0] == 0xB8 &&
				data[1] == 0x78 &&
				data[2] == 0x56 &&
				data[3] == 0x34 &&
				data[4] == 0x12 )
			#endif
				 {
					printf("\nAchou padrao asm, @ 0x%x\n", data);
					sig_count++;
					return data;
					break;
				 }
			else {
				
				// http://stackoverflow.com/a/7319450
				#ifndef padrao
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x9090, endAddress - startAddress);
				#endif
				#ifdef padrao
					// 0x5678 Aparece invertido, ja que buscamos 0x7856
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x5678B8, endAddress - startAddress);
				#endif
			
				if (data_ == 0)
					return 0;
				else if(data == data_)
					return 0;
				else
					data = data_;
			}
		}
		//__except (filter(GetExceptionCode(), GetExceptionInformation())) {
		// Referencias: https://msdn.microsoft.com/pt-br/library/zazxh1a9.aspx
		// __except (puts("in filter"), EXCEPTION_EXECUTE_HANDLER) {
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return 0;
			continue;
		}
	// for 
	} 
	return 0;
}

unsigned char* search(int startAddress)
{
	unsigned char* data;
	int sig_count = 0;
	int j = 0;

	int address = startAddress;
	int endAddress = 0x80000000 ;

	data = (unsigned char*)address;

	while(data < (unsigned char*)endAddress) {
		__try {
			#ifndef padrao
			if (data[0] == 0x90 &&
				data[1] == 0x90 &&
				data[2] == 0x50 &&
				data[3] == 0x58)
			#endif
			#ifdef padrao
				//if (data[0] == 0xBB &&
				if (data[0] == 0xB8 &&
				data[1] == 0x78 &&
				data[2] == 0x56 &&
				data[3] == 0x34 &&
				data[4] == 0x12 )
			#endif
				 {
					printf("\nAchou padrao asm, @ 0x%x\n", data);
					sig_count++;
					return data;
				 }
			else {
			
				// http://stackoverflow.com/a/7319450
				#ifndef padrao
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x9090, endAddress - startAddress);
				#endif
				#ifdef padrao
					// 0x5678 Aparece invertido, ja que buscamos 0x7856
					unsigned char* data_ = (unsigned char*) memchr((const void*)(data + 1), 0x5678B8, endAddress - startAddress);
				#endif
				if (data_ == 0)
					return 0;
				else if(data == data_)
					return 0;
				else
					data = data_;
			}
		}
		//__except (filter(GetExceptionCode(), GetExceptionInformation())) {
		// Referencias: https://msdn.microsoft.com/pt-br/library/zazxh1a9.aspx
		// __except (puts("in filter"), EXCEPTION_EXECUTE_HANDLER) {
		__except (EXCEPTION_EXECUTE_HANDLER) {
			continue;
		}

	} // for
	return 0;
}

void printMemoryInformations (std::vector<MEMPAGE> pageVector, int pageCount)
{
	char curMod[MAX_MODULE_SIZE] = "";

	 for(int i = pageCount - 1; i > -1; i--)
    {
		auto & currentPage = pageVector.at(i);
        if(!currentPage.info[0]) //there is a module
            continue; //skip non-modules
		 strcpy(curMod, pageVector.at(i).info);
		 printf("Informacoes da pagina %d : %s\t", i, curMod);
		DWORD newAddress = DWORD(currentPage.mbi.BaseAddress) + currentPage.mbi.RegionSize;
		printf("Tamanho: 0x%x\t", currentPage.mbi.RegionSize);
		printf("End Address 0x%x\n", newAddress);
	}

	 system("pause");
}


// Padrao 0: 90 90 50 58 
// NOP 
// NOP 
// push   eax
// pop    eax

// Padrao 1: 78 56 34 12 
// mov ebx,0x12345678
int main(int argc, char** argv)
{
	unsigned char* primeiraOcorrenciaAddress = 0;
	unsigned char* segundaOcorrenciaAddress = 0;
	int (*ptTest)() = NULL;

	printf("Start ? \n\n");
	system("pause");

	test();
	ptTest = (int(*)())&test;

	printf("Executou test(); Continuar ? \n");
	system("pause");

	primeiraOcorrenciaAddress = search((int)ptTest);
	printf("Endereco primeira ocorrencia: %x\n", primeiraOcorrenciaAddress);
	system("pause");

	std::vector<MEMPAGE> pageVector = GetPageVector();
	// std::vector<MEMPAGE> pageVector = GetPageCodeCacheVector();

    int pagecount = (int)pageVector.size();
	printf("pagecount = %d\n", pagecount);
	
	// printMemoryInformations (pageVector, pagecount);
	// alteraPemissoesPaginas(pageVector, pagecount);

	 for(int i = 0; i < pagecount -1; i++)
    {
		auto & currentPage = pageVector.at(i);
        if(!currentPage.info[0]) //there is a module
            continue; //skip non-modules
		
		DWORD endAddress = DWORD(currentPage.mbi.BaseAddress) + currentPage.mbi.RegionSize;

		segundaOcorrenciaAddress = search((int)(currentPage.mbi.BaseAddress), (int)endAddress);

		if (segundaOcorrenciaAddress != 0 ) 
		{
			printf("Endereco segunda ocorrencia: %x\n", segundaOcorrenciaAddress);
			break;
		}
	}
	 if (segundaOcorrenciaAddress == 0 ) 
	 {
		 printf("\nSegunda ocorrencia nao foi localizada\n");
	 }

	system("pause");

	// Metodo lento
	/*segundaOcorrenciaAddress = search((int)(0x3000000 + primeiraOcorrenciaAddress));
	printf("Endereco segunda ocorrencia: %x\n", segundaOcorrenciaAddress);
	system("pause");*/

    return 0;
}


// LEGACY
//int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep) {
//	// puts("in filter.");
//	if (code == EXCEPTION_ACCESS_VIOLATION) {
//		// puts("caught AV as expected.");
//		return EXCEPTION_EXECUTE_HANDLER;
//	}
//	else {
//		// puts("didn't catch AV, unexpected.");
//		return EXCEPTION_CONTINUE_SEARCH;
//	};
//}
//
//unsigned char* search(int startAddress)
//{
//	unsigned char* data;
//	int sig_count = 0;
//	int j = 0;
//
//	int address = startAddress;
//	data = (unsigned char*)address;
//
//	// for (j = address; j < 0xfffffff; j++) {
//	for (j = address; j<0x80000000; j++) {
//		__try {
//			data = (unsigned char*)(j);
//			printf("\nTentando para, @ 0x%x\n", j);
//			printf("\nData: @ 0x%x%x%x%x\n", data[0], data[1], data[2], data[3]);
//		
//			/*if (data[0] == 0x90 &&
//				data[1] == 0x90 &&
//				data[2] == 0x50 &&
//				data[3] == 0x58)*/
//			#ifdef padrao
//				if (data[0] == 0xBB &&
//				data[1] == 0x78 &&
//				data[2] == 0x56 &&
//				data[3] == 0x34 &&
//				data[4] == 0x12 )
//			#endif
//			{
//				printf("\nAchou padrao asm, @ 0x%x\n", data);
//				sig_count++;
//				return data;
//				break;
//			}
//			else {
//				//address= address + j;
//				data = (unsigned char*)(address + j);
//			}
//		}
//		//__except (filter(GetExceptionCode(), GetExceptionInformation())) {
//		// Referencias: https://msdn.microsoft.com/pt-br/library/zazxh1a9.aspx
//		// __except (puts("in filter"), EXCEPTION_EXECUTE_HANDLER) {
//		__except (EXCEPTION_EXECUTE_HANDLER) {
//			continue;
//		}
//
//	} // for
//	return 0;
//}
//bool runVirtualProtect(MEMPAGE currentPage, DWORD * oldProtect)
//{
//	bool retorno = false;
//	__try {
//		retorno = VirtualProtect(currentPage.mbi.BaseAddress, currentPage.mbi.RegionSize, PAGE_EXECUTE_READ, oldProtect);
//	}
//	  __except (EXCEPTION_EXECUTE_HANDLER) {
//	// __except (EXCEPTION_CONTINUE_EXECUTION) {
//		//continue;
//		// runVirtualProtect(currentPage, oldProtect);
//		 // return retorno;
//	}
//
//	return retorno;
//}
//
//// VirtualProtect
//// https://msdn.microsoft.com/en-us/library/aa366898(VS.85).aspx
//void alteraPemissoesPaginas(std::vector<MEMPAGE> pageVector, int pageCount)
//{
//	 // for(int i = pageCount - 1; i > -1; i--)
//	for(int i = 0; i < pageCount - 1 -1; i++)
//	// for(int i = 0; i < 3; i++)
//	// for(int i = 0; i < 2; i++)
//    {
//		// unsigned long oldProtect
//		DWORD oldProtect = 0;
//		bool isOk = false;
//
//		char curMod[MAX_MODULE_SIZE] = "";
//
//		auto & currentPage = pageVector.at(i);
//        if(!currentPage.info[0]) //there is a module
//            continue; //skip non-modules
//		if (currentPage.mbi.RegionSize != 0x40000)
//			continue; //skip
//
//		strcpy(curMod, pageVector.at(i).info);
//		printf("Informacoes da pagina %d : %s\t", i, curMod);
//		DWORD newAddress = DWORD(currentPage.mbi.BaseAddress) + currentPage.mbi.RegionSize;
//		printf("Tamanho: 0x%x\t", currentPage.mbi.RegionSize);
//		printf("End Address 0x%x\n", newAddress);
//
//		// Chamada a Virtual Protect foi removida daqui pra evitar o bug descrito em:
//		// https://msdn.microsoft.com/en-us/library/xwtb73ad(v=vs.100).aspx
//		// isOk = VirtualProtect(currentPage.mbi.BaseAddress, currentPage.mbi.RegionSize, PAGE_EXECUTE_READ, &oldProtect);
//		isOk = runVirtualProtect(currentPage, &oldProtect);
//
//		if( !isOk ) {
//			printf("Falha ao chamar VirtualProtect\n");
//		}
//	}
//
//	 system("pause");
//}