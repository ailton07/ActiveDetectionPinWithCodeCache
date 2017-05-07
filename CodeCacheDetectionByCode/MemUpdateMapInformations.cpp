// MemUpdateMapInformations.cpp : Defines the entry point for the console application.
// https://github.com/x64dbg/x64dbg/blob/598fc65ea0a0ccf9dad1a880355718529730614a/src/dbg/memory.cpp
//

#include "MemUpdateMapInformations.h"

std::vector<MEMPAGE> GetPageVector()
{
	 std::vector<MEMPAGE> pageVector;
	 // Aloca um espaco previamente
	 pageVector.reserve(200); //TODO: provide a better estimate
    {
		SIZE_T numBytes = 0;
        DWORD pageStart = 0;
        DWORD allocationBase = 0;

		do
        {
			 // Query memory attributes
            MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(mbi));

			 // numBytes = VirtualQueryEx(fdProcessInfo->hProcess, (LPVOID)pageStart, &mbi, sizeof(mbi));
			numBytes = VirtualQuery((LPVOID)pageStart, &mbi, sizeof(mbi));
			  // Only allow pages that are committed/reserved (exclude free memory)
            if(mbi.State != MEM_FREE)
            {
				auto bReserved = mbi.State == MEM_RESERVE; //check if the current page is reserved.
				auto bPrivateType = mbi.Type == MEM_PRIVATE;

				auto bPrevReserved = pageVector.size() ? pageVector.back().mbi.State == MEM_RESERVE : false; //back if the previous page was reserved (meaning this one won't be so it has to be added to the map)
				// Only list allocation bases, unless if forced to list all
				// if(bListAllPages || bReserved || bPrevReserved || allocationBase != DWORD(mbi.AllocationBase))
				if(bReserved || bPrevReserved || allocationBase != DWORD(mbi.AllocationBase))
                {
					// Set the new allocation base page
                    allocationBase = DWORD(mbi.AllocationBase);
					
					MEMPAGE curPage;
                    memset(&curPage, 0, sizeof(MEMPAGE));
                    memcpy(&curPage.mbi, &mbi, sizeof(mbi));

					if(bPrivateType && (mbi.AllocationProtect == RWE))
                    {
                       /* if(DWORD(curPage.mbi.BaseAddress) != allocationBase)
                            sprintf_s(curPage.info, "DBG Reserved RWE (%p)", allocationBase);
                        else
                            sprintf_s(curPage.info, "DBG Reserved RWE");*/
						sprintf_s(curPage.info, "DBG Reserved (%p) (0x%x)", allocationBase, mbi.AllocationProtect);
                    }
					pageVector.push_back(curPage);
				}
			}

			// Calculate the next page start
            DWORD newAddress = DWORD(mbi.BaseAddress) + mbi.RegionSize;

            if(newAddress <= pageStart)
                break;

			pageStart = newAddress;

		} while(numBytes);
	}

	return pageVector;

}

std::vector<MEMPAGE> GetPageCodeCacheVector()
{
	 std::vector<MEMPAGE> pageVector;
	 // Aloca um espaco previamente
	 pageVector.reserve(200); //TODO: provide a better estimate
    {
		SIZE_T numBytes = 0;
        DWORD pageStart = 0;
        DWORD allocationBase = 0;

		do
        {
			 // Query memory attributes
            MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(mbi));

			 // numBytes = VirtualQueryEx(fdProcessInfo->hProcess, (LPVOID)pageStart, &mbi, sizeof(mbi));
			numBytes = VirtualQuery((LPVOID)pageStart, &mbi, sizeof(mbi));
			  // Only allow pages that are committed/reserved (exclude free memory)
            if(mbi.State != MEM_FREE)
            {
				auto bReserved = mbi.State == MEM_RESERVE; //check if the current page is reserved.
				auto bPrivateType = mbi.Type == MEM_PRIVATE;

				auto bPrevReserved = pageVector.size() ? pageVector.back().mbi.State == MEM_RESERVE : false; //back if the previous page was reserved (meaning this one won't be so it has to be added to the map)
				// Only list allocation bases, unless if forced to list all
				// if(bListAllPages || bReserved || bPrevReserved || allocationBase != DWORD(mbi.AllocationBase))
				if(bReserved || bPrevReserved || allocationBase != DWORD(mbi.AllocationBase))
                {
					// Set the new allocation base page
                    allocationBase = DWORD(mbi.AllocationBase);
					
					MEMPAGE curPage;
                    memset(&curPage, 0, sizeof(MEMPAGE));
                    memcpy(&curPage.mbi, &mbi, sizeof(mbi));

					if(bPrivateType && (mbi.AllocationProtect == RWE))
                    {
                       /* if(DWORD(curPage.mbi.BaseAddress) != allocationBase)
                            sprintf_s(curPage.info, "DBG Reserved RWE (%p)", allocationBase);
                        else
                            sprintf_s(curPage.info, "DBG Reserved RWE");*/
						sprintf_s(curPage.info, "DBG Reserved (%p) (0x%x)", allocationBase, mbi.AllocationProtect);
                    }
					if (curPage.mbi.RegionSize == 0x40000)
						pageVector.push_back(curPage);
				}
			}

			// Calculate the next page start
            DWORD newAddress = DWORD(mbi.BaseAddress) + mbi.RegionSize;

            if(newAddress <= pageStart)
                break;

			pageStart = newAddress;

		} while(numBytes);
	}

	return pageVector;

}

//void main(void)
//{
//	
//	std::vector<MEMPAGE> pageVector = GetPageVector();
//
//	 // Process file sections
//    int pagecount = (int)pageVector.size();
//	char curMod[MAX_MODULE_SIZE] = "";
//    for(int i = pagecount - 1; i > -1; i--)
//    {
//		auto & currentPage = pageVector.at(i);
//        if(!currentPage.info[0] || (scmp(curMod, currentPage.info) && !bListAllPages)) //there is a module
//            continue; //skip non-modules
//		strcpy(curMod, pageVector.at(i).info);
//		printf("Informacoes da pagina %d : %s\t", i, curMod);
//		
//		DWORD newAddress = DWORD(currentPage.mbi.BaseAddress) + currentPage.mbi.RegionSize;
//
//		printf("End Address 0x%x\n", newAddress);
//	}
//
//	 system("PAUSE");
//}