#include <iostream>
#include <cstring>
#include <math.h>
#include <sstream>
#include <iomanip>
#include "/pepac/pelib/include/pelib/PeLib.h" // Thanks to adjust the path of PeLib.h relatively to its location and perhaps with the CMakeList.txt
#include <csignal>

/* This program, till now, and in the context of detection and classification of packed malware, extracts 119 features from the PE under analysis, all mentionnned just below :

Feature 1 : the DLLs characteristics 1
Feature 2 : the DLLs characteristics 2
Feature 3 : the DLLs characteristics 3
Feature 4 : the DLLs characteristics 4
Feature 5 : the DLLs characteristics 5
Feature 6 : the DLLs characteristics 6
Feature 7 : the DLLs characteristics 7
Feature 8 : the DLLs characteristics 8
Feature 9 : the Checksum
Feature 10 : the Image Base
Feature 11 : the Base of Code
Feature 12 : the OS Major version
Feature 13 : the OS Minor version
Feature 14 : the Size of Image
Feature 15 : the Size of Code
Feature 16 : the Headers
Feature 17 : the Size Of InitializedData
Feature 18 : the Size Of UninitializedData
Feature 19 : the Size Of StackReserve
Feature 20 : the Size of Stack Commit
Feature 21 : the Section Alignment
Feature 22 : the number of standards sections the PE holds
Feature 23 : the number of non-standards sections the PE holds
Feature 24 : the ratio between the number of standards sections found and the number of all sections found in the PE under analysis
Feature 25 : the number of Executable sections the PE holds
Feature 26 : the number of Writable sections the PE holds
Feature 27 : the number of Writable and Executable sections the PE holds
Feature 28 : the number of readable and executable sections
Feature 29 : the number of readable and writable sections
Feature 30 : the number of Writable and Readable and Executable sections the PE holds
Feature 31 : the code section is not executable
Feature 32 : the executable section is not a code section
Feature 33 : the code section is not present in the PE under analysis
Feature 34 : the EP is not in the code section
Feature 35 : the EP is not in a standard section
Feature 36 : the EP is not in an executable section
Feature 37 : the EP ratio between raw data and virtual size for the section of entry point
Feature 38 : the number of sections having their physical size =0 (size on disk)
Feature 39 : the number of sections having their virtual size greater than their raw data size
Feature 40 : the maximum ratio raw data per virtual size among all the sections
Feature 41 : the minimum ratio raw data per virtual size among all the sections
Feature 42 : the address pointing to raw data on disk is not conforming with the file alignement
Feature 43 : the entropy of Code/text sections
Feature 44 : the entropy of data section
Feature 45 : the entropy of resource section
Feature 46 : the entropy of PE header
Feature 47 : the entropy of the entire PE file
Feature 48 : the entropy of section holding the Entry point (EP) of the PE under analysis
Feature 49 - 112 : 64 bytes following the EP, each byte for 1 feature position
Feature 113 : the number of DLLs imported
Feature 114 : the number of functions imported found in the import table directory (IDT)
Feature 115 : the number of malicious APIs imported
Feature 116 : the ratio between the number of malicious APIs imported to the number of all functions imported by the PE
Feature 117 : the number of addresses (corresponds to functions) found in the import address table (IAT)
Feature 118 : the debug directory is present or not
Feature 119 : the number of resources the PE holds
*/

// The PeLib developped by the anti-virus Avast is used in this program
/* Most of the features are taken from Xabier Ugarte-Pedrero (2014+2011) + Mohaddeseh Zakeri 2015 */

#define HEADER 0
#define SECTION 1
#define ENTROPY 2
#define EP_64_BYTES 3
#define IMP_FUNC 4
#define OTHERS 5

#define max_num_cat 6
std::vector<bool>cat_opts(max_num_cat,false); // vector that holds the categories arguments
std::string FV1, FV2, FV3, FV4, FV5; // global variables representing sub-parts of the final features(characteristics) vector that will represent each PE analysed
std::string FV1_HEAD, FV1_SEC, FV1_ENTROPY, FV1_EP_64; // sub-parts of FV1
std::string FV; // // global variable representing the final features(characteristics) vector that will represent the PE analysed
std::ostringstream OutPutVector1, OutPutVector2, OutPutVector3, OutPutVector4, OutPutVector5; // global temporal variables
std::ostringstream OutPutVector1_HEAD, OutPutVector1_SEC, OutPutVector1_ENTROPY, OutPutVector1_EP_64; // sub-parts of OutPutVector1

template<typename T>
std::string convert(T x) // template function converting the input to hex format
{
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << x;
    return ss.str();
}

// ShannonEntropy function for measuring the randomness of data
float _ShannonEntropyV(std::vector<unsigned char> vector)
{
    int count[256] = {0}, i;
    float entropy = 0.0;

    if (vector.size() == 0)
        return 0.0;

    for(i=0; i<vector.size(); i++) count[vector[i]]++;
    for(i=0; i<255; i++) if(count[i] > 0) entropy = entropy + ((-1.0*count[i])/vector.size())*log2f((1.0*count[i])/vector.size());
    return entropy;
}

std::string FixFileName(const std::string& s) // function fixing the separator problem(in a relative path for example ../) in the filename
{
    char sep = '/';

#ifdef _WIN32
    sep = '\\';
#endif

    size_t sep_found = s.rfind(sep, s.length());
    if (sep_found != std::string::npos)
    {
        std::string text = s.substr(sep_found+1, s.length() - sep_found);
        std::replace(text.begin(), text.end(), ' ', '_');
        return(text);
    }

    return(s);
}

// dumps the header of the PE under analysis and extracts from it XX features (the number is variable)
template<int bits>
void dumpPeHeader(PeLib::PeFile& pef)
{
    const PeLib::PeHeaderT <bits> &peh = static_cast<PeLib::PeFileT <bits> &>(pef).peHeader();
    std::ifstream ifFile(pef.getFileName());

    std::vector<std::string> Std_Sec_names = {".bss",".cormeta", ".data", ".debug$F", ".debug$P", ".debug$S", ".debug$T", ".drective", ".edata", ".idata", ".idlsym", ".pdata", ".rdata", ".reloc", ".rsrc", ".sbss", ".sdata", ".srdata", ".sxdata", ".text", ".tls", ".tls$", ".vsdata", ".xdata"};// standards names of sections in accordance with Windows Portable Executable specification
    int numSec = 0; // the number of sections that contains the PE under analysis
    int numStdSec = 0; //number of standard sections that contains the PE under analysis
    int numExecSec = 0; //number of executable sections that contains the PE under analysis
    int numWriteSec = 0; // number of writable sections
    int numWriteExecSec = 0; // number of writable/Executable sections
    int numReadExecSec = 0; // number of readable/executable sections
    int numReadWriteSec = 0; // number of readable/writale sections
    int numReadWriteExecSec = 0; //number of Readable&Writable&Executable sections that contains the PE under analysis
    int numSecZeroRawSize = 0; // number of setions which have size=0 on disk
    int numVirtSecSizeBigger = 0; // number of sections having their virtual size greater than their physical one
    int data_sec_id = -1, text_sec_id = -1, rsrc_sec_id = -1, EP_Sec_Id = -1; // sections identifiers
    int EP_Rva = -1; // relative virtual address of the entry point
    float sectionRatio = -1; // the ratio between number of standards sections found and number of all sections found
    float eData = -1.0, eCode = -1.0, eRsrc = -1.0, eEPsec = -1.0, eHeader = -1.0, eFile = -1.0;  // entropy of data_section, code_section, ressources_section, and Entry_Point section
    float MinSecSizeRatio = 1e+6;
    float MaxSecSizeRatio = -1 ;
    float EP_SizeRatio = -1; // the ratio between raw data and virtual size for the section of entry point
    bool PtrRawDataNotMulFileAlignment = false; // the address pointed on raw data is not a multiple of file alignement
    bool CodeSecNotExec = false; // the code(.text) section is not executable
    bool ExecutableSecNotcode = false; // the section i is executable but doesn't belong to .text section
    bool NoCodeSec = true; // there is no code section in the PE
    bool No_EP_in_CodeSec = false, No_EP_in_StdSec = false, No_EP_in_ExecSec = false;
    std::string BytesAfterEP; //string to stock the 64 bytes following the entry point
    PeLib::dword prd; //pointer on raw data (on disk)
    PeLib::dword srd; // size of raw data (on disk)
    PeLib::dword characteristic; // this variable will hold the characteristic of section i

    if(cat_opts[HEADER]==true) // if the category of header features was specified by the user
    {
        bool IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = false, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = false,
                IMAGE_DLLCHARACTERISTICS_NX_COMPAT = false, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = false,
                IMAGE_DLLCHARACTERISTICS_NO_SEH = false, IMAGE_DLLCHARACTERISTICS_NO_BIND = false,
                IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = false , IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = false;

        PeLib::word  DLLs_charac = peh.getDllCharacteristics(); //gets the characteristics of DLLs from the PE header
        if (DLLs_charac & 0x0040)
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = true;
        if (DLLs_charac & 0x0080)
            IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = true;
        if (DLLs_charac & 0x0100)
            IMAGE_DLLCHARACTERISTICS_NX_COMPAT = true;
        if (DLLs_charac & 0x0200)
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = true;
        if (DLLs_charac & 0x0400)
            IMAGE_DLLCHARACTERISTICS_NO_SEH = true;
        if (DLLs_charac & 0x0800)
            IMAGE_DLLCHARACTERISTICS_NO_BIND = true;
        if (DLLs_charac & 0x2000)
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = true;
        if (DLLs_charac & 0x8000)
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = true;
        OutPutVector1_HEAD << IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE << "," << IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY << "," <<IMAGE_DLLCHARACTERISTICS_NX_COMPAT << ","
                           << IMAGE_DLLCHARACTERISTICS_NO_ISOLATION << "," << IMAGE_DLLCHARACTERISTICS_NO_SEH << "," << IMAGE_DLLCHARACTERISTICS_NO_BIND << ","
                           << IMAGE_DLLCHARACTERISTICS_WDM_DRIVER << "," << IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE << ",";
        PeLib::dword Checksum = peh.getCheckSum();//gets the checksum from ...
        OutPutVector1_HEAD << Checksum << ",";
        unsigned int ImageBase = peh.getImageBase();
        OutPutVector1_HEAD << ImageBase << ",";
        PeLib::dword CodeBase = peh.getBaseOfCode();
        OutPutVector1_HEAD << CodeBase << ",";
        PeLib::word  Major_0S_Version = peh.getMajorOperatingSystemVersion();
        OutPutVector1_HEAD << Major_0S_Version << ",";
        PeLib::word  Minor_0S_Version = peh.getMinorOperatingSystemVersion();
        OutPutVector1_HEAD << Minor_0S_Version << ",";
        PeLib::dword SizeOfImage  = peh.getSizeOfImage();
        OutPutVector1_HEAD << SizeOfImage << ",";
        PeLib::dword SizeOfCode   = peh.getSizeOfCode();
        OutPutVector1_HEAD << SizeOfCode << ",";
        PeLib::dword SizeOfHeaders= peh.getSizeOfHeaders();
        OutPutVector1_HEAD << SizeOfHeaders << ",";
        PeLib::dword SizeOfInitializedData = peh.getSizeOfInitializedData();
        OutPutVector1_HEAD << SizeOfInitializedData << ",";
        PeLib::dword SizeOfUninitializedData = peh.getSizeOfUninitializedData();
        OutPutVector1_HEAD << SizeOfUninitializedData << ",";
        unsigned int SizeOfStackReserve = peh.getSizeOfStackReserve();
        OutPutVector1_HEAD << SizeOfStackReserve << ",";
        unsigned int SizeOfStackCommit  = peh.getSizeOfStackCommit();
        OutPutVector1_HEAD << SizeOfStackCommit << ",";
        PeLib::dword SectionAlignment = peh.getSectionAlignment();
        OutPutVector1_HEAD << SectionAlignment<<",";
        //PeLib::dword IAT_RVA = peh.getIddIatRva();
        //PeLib::dword ExportSize = peh.getIddExportSize();
        //PeLib::dword DebugSize

        FV1_HEAD = OutPutVector1_HEAD.str();
    }

    if (cat_opts[SECTION]==true)
    {
        for (int i = 0; i < peh.calcNumberOfSections(); i++)
        {
            numSec++;
            bool flag, write = false, read = false, exec = false; // flags marking read/write/execute permissions in sections
            bool found = false;

            std::string Sec_Name = peh.getSectionName(i); //gets the name of the section i;

            for (int index = 0; index < Std_Sec_names.size() && found == false; index++) // check whether the name of the section i is conforming to Windows Portable Executable specification regarding sections names
            {
                if (Std_Sec_names[index].compare(Sec_Name) == 0) {
                    found = true;
                    numStdSec++;
                }
            }
            characteristic = peh.getCharacteristics(i); // gets the characteristics of the section i

            if (characteristic &
                0x80000000) // see Windows Portable Executable specification : https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms680547(v=vs.85).aspx
            {
                write = true;
                numWriteSec++;
            }

            if (characteristic & 0x40000000)
                read = true;

            if (characteristic & 0x20000000) {
                exec = true;
                numExecSec++;
                if (Sec_Name.compare(".text") != 0 && Sec_Name.compare("tls") !=
                                                      0) // tls section is added as a possible executable section (multithreading)
                    ExecutableSecNotcode = true;
            }

            if (write && read && exec)
                numReadWriteExecSec++; // the sections i has the three permissions flags Read/Write/Execute (possibility of presence of a decryption/decompressor function of the packer)

            if (write && exec)
                numWriteExecSec++; // the section i has write/exec permissions flag (possibility of presence of a decryption/decompressor function of the packer)

            if (read && exec)
                numReadExecSec++;  // ...

            if (read && write)
                numReadWriteSec++; // ...

            srd = peh.getSizeOfRawData(i); // get the physical size of the section i
            prd = peh.getPointerToRawData(i); // get the physical address of the section i

            if (srd == 0)
                numSecZeroRawSize++; // number of sections with zero raw size (suspescious sections !)

            if (prd % peh.getFileAlignment() != 0)
                PtrRawDataNotMulFileAlignment = true; // at least one address on disk is not conforming to file alignement (suspicious !)

            if (peh.getVirtualSize(i) != 0 &
                ((1.0 * srd) / peh.getVirtualSize(i)) > MaxSecSizeRatio) // Check the max each time
                MaxSecSizeRatio = (1.0 * srd) / peh.getVirtualSize(i);

            if (peh.getVirtualSize(i) != 0 &
                ((1.0 * srd) / peh.getVirtualSize(i)) < MinSecSizeRatio) // Check the min each time
                MinSecSizeRatio = (1.0 * srd) / peh.getVirtualSize(i);

            if (peh.getVirtualSize(i) != 0 &
                ((1.0 * srd) / peh.getVirtualSize(i)) < 1) // Check if virtual size is greater than the physical one
                numVirtSecSizeBigger++;

            if (Sec_Name.compare(".text") == 0) {
                NoCodeSec = false;
                if (exec == false) // the code section is not executable
                    CodeSecNotExec = true;
            }
        }

        if (MinSecSizeRatio ==
            1e+6) // It could not change for different possible reasons : virtualSize=0 for all sections ...
            MinSecSizeRatio = -1;

        if (numSec == 0)
        {
            //std::cout << "Will fix this situation later, for now it's an Invalid PE";
            //getchar();
            //sectionRatio = 0.5;
            exit(3);
        }
        else
            sectionRatio = (1.0 * numStdSec) / numSec;

        // Checks the anomalies related to the EntryPoint : EP not in the code section, EP with non-standard section name, EP not in executable sections
        EP_Rva = peh.getAddressOfEntryPoint();
        if (EP_Rva >= peh.calcStartOfCode() & EP_Rva <= peh.getSizeOfImage()) // Checks that the EP is really valid
        {
            EP_Sec_Id = peh.getSectionWithRva(EP_Rva);
            std::string EP_SecName = peh.getSectionName(EP_Sec_Id);
            PeLib::dword EP_characteristic = peh.getCharacteristics(EP_Sec_Id);

            if (EP_SecName.compare(".text") != 0) // EP is not in the code section
                No_EP_in_CodeSec = true;

            bool found = false;
            for (int index = 0; index < Std_Sec_names.size() && found == false; index++) // check whether the EP has non-standard section name
            {
                if (Std_Sec_names[index].compare(EP_SecName) == 0)
                    found = true;
            }
            if (found == false)
                No_EP_in_StdSec = true;

            if (!(EP_characteristic & 0x20000000))
                No_EP_in_ExecSec = true;        // the EP is not in a executable section

            // Computes the ratio between raw data and virtual size for the section of entry point
            srd = peh.getSizeOfRawData(EP_Sec_Id);
            if (peh.getVirtualSize(EP_Sec_Id) != 0)
                EP_SizeRatio = (1.0 * srd) / peh.getVirtualSize(EP_Sec_Id);
        }
        else //Make assumptions
        {
            No_EP_in_CodeSec = true;
            No_EP_in_StdSec = true;
            No_EP_in_ExecSec = true; // the EP is not in a executable section
        }

        OutPutVector1_SEC << numStdSec << "," << numSec - numStdSec << "," << std::setprecision(3) << std::fixed << sectionRatio << "," << numExecSec << ","
                          << numWriteSec << "," << numWriteExecSec  << "," << numReadExecSec << "," << numReadWriteSec << ","
                          << numReadWriteExecSec << "," << CodeSecNotExec << "," << ExecutableSecNotcode << "," << NoCodeSec << "," << No_EP_in_CodeSec << "," << No_EP_in_StdSec << ","
                          << No_EP_in_ExecSec << "," << std::setprecision(3) << std::fixed << EP_SizeRatio << "," << numSecZeroRawSize
                          << "," << numVirtSecSizeBigger << "," << std::setprecision(3)<< std::fixed << MaxSecSizeRatio << "," << std::setprecision(3) << std::fixed << MinSecSizeRatio << ","
                          << PtrRawDataNotMulFileAlignment<<",";

        FV1_SEC = OutPutVector1_SEC.str();
    }

    if (cat_opts[ENTROPY]==true)
    {
        // Computes the entropy of entry point section
        EP_Rva = peh.getAddressOfEntryPoint();
        if (EP_Rva >= peh.calcStartOfCode() & EP_Rva <= peh.getSizeOfImage()) // Checks that the EP is really valid
        {
            EP_Sec_Id = peh.getSectionWithRva(EP_Rva);
            prd = peh.getPointerToRawData(EP_Sec_Id);
            srd = peh.getSizeOfRawData(EP_Sec_Id);
            ifFile.clear();
            ifFile.seekg(prd, std::ios_base::beg);
            std::vector<unsigned char> vBuffer(srd);
            ifFile.read(reinterpret_cast<char *>(&vBuffer[0]), static_cast<std::streamsize>(vBuffer.size()));
            eEPsec = _ShannonEntropyV(vBuffer);
        }

        // Get the indexes of text,data and ressources sections in just one loop
        int i = 0;
        bool all_sec_found = false;
        while (i < peh.calcNumberOfSections() && all_sec_found == false)
        {
            std::string Sec_Name = peh.getSectionName(i); //gets the name of the section i;
            if (Sec_Name.compare(".data") == 0)
                data_sec_id = i;
            if (Sec_Name.compare(".text") == 0)
                text_sec_id = i;
            if (Sec_Name.compare(".rsrc") == 0)
                rsrc_sec_id = i;
            if ((data_sec_id != -1) && (text_sec_id != -1) && (rsrc_sec_id != -1))
                all_sec_found = true;
            i++;
        }

        // Computes the entropy of data section
        if (data_sec_id != -1)
        {
            prd = peh.getPointerToRawData(data_sec_id); // gets the address on disk of the begining of section i
            srd = peh.getSizeOfRawData(data_sec_id);    // gets the size on disk of the section i
            ifFile.clear();
            ifFile.seekg(prd, std::ios_base::beg);
            std::vector<unsigned char> vBuffer(srd);
            ifFile.read(reinterpret_cast<char *>(&vBuffer[0]),
                        static_cast<std::streamsize>(vBuffer.size())); //reads the data from disk and puts them in a buffer
            eData = _ShannonEntropyV(vBuffer); // Computes the entropy of data_section
        }

        // Computes the entropy of text section
        if (text_sec_id != -1) {
            prd = peh.getPointerToRawData(text_sec_id); // gets the address on disk of the begining of section i
            srd = peh.getSizeOfRawData(text_sec_id);    // gets the size on disk of the section i
            ifFile.clear();
            ifFile.seekg(prd, std::ios_base::beg);
            std::vector<unsigned char> vBuffer(srd);
            ifFile.read(reinterpret_cast<char *>(&vBuffer[0]),
                        static_cast<std::streamsize>(vBuffer.size())); //reads the data from disk and puts them in a buffer
            eCode = _ShannonEntropyV(vBuffer); // Computes the entropy of text_section
        }

        // Computes the entropy of resources section
        if (rsrc_sec_id != -1) {
            prd = peh.getPointerToRawData(rsrc_sec_id); // gets the address on disk of the begining of section i
            srd = peh.getSizeOfRawData(rsrc_sec_id);    // gets the size on disk of the section i
            ifFile.clear();
            ifFile.seekg(prd, std::ios_base::beg);
            std::vector<unsigned char> vBuffer(srd);
            ifFile.read(reinterpret_cast<char *>(&vBuffer[0]),
                        static_cast<std::streamsize>(vBuffer.size())); //reads the data from disk and puts them in a buffer
            eRsrc = _ShannonEntropyV(vBuffer); // Computes the entropy of ressources_section
        }

        // Computes the entropy of PE header
        prd = 0;
        srd = peh.size();
        ifFile.clear();
        ifFile.seekg(prd, std::ios_base::beg);
        std::vector<unsigned char> vBuffer1(srd);
        ifFile.read(reinterpret_cast<char *>(&vBuffer1[0]), static_cast<std::streamsize>(vBuffer1.size()));
        eHeader = _ShannonEntropyV(vBuffer1);

        // Computes the entropy of the entire file
        prd = 0;
        srd = peh.calcSizeOfImage();
        ifFile.clear();
        ifFile.seekg(0);
        std::vector<unsigned char> vBuffer2(srd);
        ifFile.read(reinterpret_cast<char *>(&vBuffer2[0]), static_cast<std::streamsize>(vBuffer2.size()));
        eFile = _ShannonEntropyV(vBuffer2);

        OutPutVector1_ENTROPY << std::setprecision(3)<< std::fixed << eCode << "," << std::setprecision(3) << std::fixed << eData << ","
                              << std::setprecision(3)<< std::fixed << eRsrc << "," << std::setprecision(3) << std::fixed << eHeader << ","
                              << std::setprecision(3)<< std::fixed << eFile << "," << std::setprecision(3)<< std::fixed << eEPsec << ",";
        FV1_ENTROPY = OutPutVector1_ENTROPY.str();
    }

    if (cat_opts[EP_64_BYTES]==true)
    {
        // Extracts the 64 bytes following the EP
        EP_Rva = peh.getAddressOfEntryPoint();
        if (EP_Rva >= peh.calcStartOfCode() & EP_Rva <= peh.getSizeOfImage()) // Checks the EP is really valid
        {
            ifFile.clear();
            ifFile.seekg(peh.rvaToOffset(peh.getAddressOfEntryPoint()), std::ios_base::beg);
            std::vector<unsigned char> vBuffer(64);
            ifFile.read(reinterpret_cast<char *>(&vBuffer[0]), static_cast<std::streamsize>(vBuffer.size()));
            std::ostringstream temp;
            for (int k = 0; k < 64; k++)
            {
                temp << (unsigned short int) vBuffer[k] << ",";
                BytesAfterEP += temp.str();
                temp.str("");
                temp.clear();
            }

        }
        else
        {
            std::ostringstream temp;
            for (int k = 0; k < 64; k++)
            {
                temp << -1 << ",";
                BytesAfterEP += temp.str();
                temp.str("");
                temp.clear();
            }
        }
        //Don't need to OutPutVector1_EP_64 here
        FV1_EP_64 = BytesAfterEP;
    }

    // Print the XX features of the PE header
    FV1 = FV1_HEAD + FV1_SEC + FV1_ENTROPY + FV1_EP_64;
}

//PeLib::dword IAT_RVA = peh.getIddIatRva();
//PeLib::dword ExportSize = peh.getIddExportSize();

// dumps the import table directory of the PE file under analysis and extracts from it XX features (the number is variable)
template<int bits>
void dumpImportDirectory(PeLib::PeFile& pef)
{
    int numImpDLLsIDT = -1; // variable representing the number of imported DLLs found in the import directory table
    int numOfImpFuncIDT = -1; // variable representing the number of imported functions found in the import directory table
    int numOfMaliciousApis = -1; // variable representing the number of malicious APIs imported by the PE
    float RatioMaliciousApis = -1; // variable representing the ratio between malicous APIs and all functions imported by the PE

    // the list of the most frequent malicious APIs that could a packed_malware/malware import
    std::vector<std::string> malicious_api = {"GetProcAddress", "LoadLibraryA", "LoadLibrary", "ExitProcess", "GetModuleHandleA", "VirtualAlloc", "VirtualFree", "GetModuleFileNameA", "CreateFileA", "RegQueryValueExA", "MessageBoxA", "GetCommandLineA", "VirtualProtect", "GetStartupInfoA", "GetStdHandle", "RegOpenKeyExA"};

    if (pef.readImportDirectory()) // check whether it can read the structure import table directory or not
    {
        // as it fails to read the IDT then the most probably reason is that the packer destroyed it
        // since the IDT is not found then the number of DLLs imported, the functions imported, the number of malicious APIs found and the ratio of malicious APIs, are missed, they remain as initialised to -1
        OutPutVector2 << numImpDLLsIDT << "," << numOfImpFuncIDT << "," << numOfMaliciousApis << "," << RatioMaliciousApis << ","; //write the sub-part features before leaving
        FV2 = OutPutVector2.str(); //write the sub-part features before leaving
        return;
    }

    const PeLib::ImportDirectory<bits>& imp = static_cast<PeLib::PeFileT<bits>&>(pef).impDir();

    numImpDLLsIDT = imp.getNumberOfFiles(PeLib::OLDDIR); //gets the number of all DLLs imported by the PE, do it before a SIGABRT might occur
    numOfMaliciousApis = 0;

    for(unsigned int index = 0; index<numImpDLLsIDT; index++)
        numOfImpFuncIDT+= imp.getNumberOfFunctions(index, PeLib::OLDDIR);// gets the number of all the functions imported by the PE found in its IDT, do it before a SIGABRT might occur

    for (unsigned int i=0;i<imp.getNumberOfFiles(PeLib::OLDDIR);i++)
    {
        for (unsigned int j=0;j<imp.getNumberOfFunctions(i, PeLib::OLDDIR);j++)
        {
            bool found = false;
            for(unsigned int index=0; index<malicious_api.size() && found==false; index++)
            {
                if(malicious_api[index].compare(imp.getFunctionName(i, j, PeLib::OLDDIR)) == 0) // Check the presence of Malicious APIs
                {
                    found=true;
                    numOfMaliciousApis++;
                }
            }
        }
    }

    if (numOfImpFuncIDT == 0) // the number could be 0, as modern packers bypass the conventional methods of loading APIs, then the number of entries in the non-destroyed IDT would be 0
        RatioMaliciousApis = 0;
        //numOfMaliciousApis = 16; //Make assumptions, but I have to rethink about ...
    else
        RatioMaliciousApis = (1.0 * numOfMaliciousApis) / numOfImpFuncIDT; // The ratio between ...

    OutPutVector2 << numImpDLLsIDT << "," << numOfImpFuncIDT << "," << numOfMaliciousApis << "," << std::setprecision(3) << std::fixed << RatioMaliciousApis << ",";
    FV2 = OutPutVector2.str();
}


// dumps the import address table of the PE under analysis and extracts from it XX features (the number is variable)
template<int bits>
void dumpIatDirectory(PeLib::PeFile& pef)
{
    int numOfImpFuncIAT = -1; // variable representing the number of imported functions (number of addresses)found in the import address table

    if (pef.readIatDirectory()) // check whether it can read the structure import address table or not
    {   // as it fails to read it then the most probably reason is that the packer destroyed it
        // since the IAT is not found then the number of addresses entries is missed, it remains like initialised to -1
        OutPutVector3 << numOfImpFuncIAT << ",";
        FV3 = OutPutVector3.str();
        return;
    }
    const PeLib::IatDirectoryT<bits>& iat = static_cast<PeLib::PeFileT<bits>&>(pef).iatDir();

    numOfImpFuncIAT = iat.calcNumberOfAddresses(); //gets the number of entries adresses in the IAT

    OutPutVector3 << numOfImpFuncIAT << ",";
    FV3 = OutPutVector3.str();
}


// dumps the debug directory of the PE under analysis and extracts from it XX features (the number is variable)
template<int bits>
void dumpDbgDirectory(PeLib::PeFile& pef)
{
    bool NoDebugDir = false; // No debug directoy

    if (pef.readDebugDirectory()) // check whether it can read the Debug Directory or not
    {   // as it fails to read it then there is no Debug directory in the PE, or it's damaged
        NoDebugDir = true;
        OutPutVector4 << NoDebugDir << ",";
        FV4 = OutPutVector4.str();
        return;
    }
    const PeLib::DebugDirectoryT<bits>& dbg = static_cast<PeLib::PeFileT<bits>&>(pef).debugDir();

    OutPutVector4 << NoDebugDir << ",";
    FV4 = OutPutVector4.str();
}


// dumps the resources directory of the PE under analysis and extracts from it XX features (the number is variable)
template<int bits>
void dumpRscDirectory(PeLib::PeFile& pef)
{
    int numRes = -1; // variable representing the number of resources that contains the PE

    if (pef.readResourceDirectory()) // check whether it can read the Resource Directory or not
    {   // as it fails to read it then there is no Resource directory in the PE, or it's damaged
        OutPutVector5 << numRes << ","; // the number of ressources remains like it was initialised to -1
        FV5 = OutPutVector5.str();
        return;
    }
    const PeLib::ResourceDirectoryT<bits>& res = static_cast<PeLib::PeFileT<bits>&>(pef).resDir();

    numRes = res.getOccupiedAddresses().size();

    OutPutVector5 << numRes << ",";
    FV5 = OutPutVector5.str();
}


class DumpPeHeaderVisitor : public PeLib::PeFileVisitor // inheritance from PeFileVisitor class under PeLib namespace
{
public:
    virtual void callback(PeLib::PeFile32 &file) {dumpPeHeader<32>(file);}
    virtual void callback(PeLib::PeFile64 &file) {dumpPeHeader<64>(file);}
};

class DumpImpDirVisitor : public PeLib::PeFileVisitor
{
public:
    virtual void callback(PeLib::PeFile32 &file) {dumpImportDirectory<32>(file);}
    virtual void callback(PeLib::PeFile64 &file) {dumpImportDirectory<64>(file);}
};

class DumpIatDirVisitor : public PeLib::PeFileVisitor // inheritance from PeFileVisitor class under PeLib namespace
{
public:
    virtual void callback(PeLib::PeFile32 &file) {dumpIatDirectory<32>(file);}
    virtual void callback(PeLib::PeFile64 &file) {dumpIatDirectory<64>(file);}
};

class DumpDbgDirVisitor : public PeLib::PeFileVisitor // inheritance from PeFileVisitor class under PeLib namespace
{
public:
    virtual void callback(PeLib::PeFile32 &file) {dumpDbgDirectory<32>(file);}
    virtual void callback(PeLib::PeFile64 &file) {dumpDbgDirectory<64>(file);}
};

class DumpRscDirVisitor : public PeLib::PeFileVisitor // inheritance from PeFileVisitor class under PeLib namespace
{
public:
    virtual void callback(PeLib::PeFile32 &file) {dumpRscDirectory<32>(file);}
    virtual void callback(PeLib::PeFile64 &file) {dumpRscDirectory<64>(file);}
};


int main(int argc, char* argv[])
{
    std::string Help_message = "Usage: pefeats <filename> -cat cat1 cat2 ... cat6 \nPossible categories with their exact syntax are : header section entropy ep64 imp_func other";
    if (argc < 2)
    {
        std::cout << Help_message << std::endl;
        return 1;
    }

    std::string filename = argv[1];
    PeLib::PeFile *pef = PeLib::openPeFile(filename); //Opens the PE file, the return type is either PeFile32 or PeFile64 object

    if (argc == 2) // corresponds to ./peafeats <filename>
        std::fill(cat_opts.begin(), cat_opts.end(), true); // extracts all the categories
    else if (argc == 3)
    {
        std::cout << Help_message<< std::endl;
        return 1;
    }
    else
    {
        std::string cat;
        cat = argv[2];
        if (cat.compare("-cat") != 0)
        {
            std::cout << Help_message << std::endl;
            return 1;
        }
        else
        {
            for (int cmd_arg = 3; cmd_arg < argc; cmd_arg++)
            {
                std::string opt = argv[cmd_arg];
                if (opt.compare("header") == 0)
                    cat_opts[HEADER] = true;
                else if (opt.compare("section") == 0)
                    cat_opts[SECTION] = true;
                else if (opt.compare("entropy") == 0)
                    cat_opts[ENTROPY] = true;
                else if (opt.compare("ep64") == 0)
                    cat_opts[EP_64_BYTES] = true;
                else if (opt.compare("imp_func") == 0)
                    cat_opts[IMP_FUNC] = true;
                else if (opt.compare("other") == 0)
                    cat_opts[OTHERS] = true;
                else
                {
                    std::cout << Help_message << std::endl;
                    return 1;
                }
            }
        }
    }

    if (!pef)
    {
        std::cout << "Unable to open " << filename << ": Invalid PE File" <<std::endl; //<< std::endl;
        return 2;
    }

    try {
        pef->readMzHeader(); // Reads the MZ header of the current file from disc
        pef->readPeHeader(); // Reads the PE header of the current file from disc
    }
    catch (...)
    {
        std::cout << "An error occured while reading the file. Maybe the file is not a valid PE file." << std::endl;
        delete pef; // frees occupied space in memory
        return 3;
    }

    if (cat_opts[HEADER]==true or cat_opts[SECTION]==true or cat_opts[ENTROPY]==true or cat_opts[EP_64_BYTES]==true)
    {
        DumpPeHeaderVisitor v1; //dumps the PE header
        pef->visit(v1);
    }

    if (cat_opts[IMP_FUNC]==true)
    {
        DumpImpDirVisitor v2; //dumps the import directory table
        pef->visit(v2);

        DumpIatDirVisitor v3; //dumps the import directory table
        pef->visit(v3);
    }

    if (cat_opts[OTHERS]==true)
    {
        DumpDbgDirVisitor v4; //dumps the Debug directory
        pef->visit(v4);

        DumpRscDirVisitor v5; //dumps the Resource directory
        pef->visit(v5);
    }

    FV = FixFileName(pef->getFileName())+","+FV1+FV2+FV3+FV4+FV5;
    FV.erase(FV.size()-1); // delete the last comma

    std::cout<< FV << std::endl;

    delete pef; // frees occupied space in memory
    return 0;
}
