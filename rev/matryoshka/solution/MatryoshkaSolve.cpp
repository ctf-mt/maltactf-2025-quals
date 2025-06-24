#include <stdio.h>
#include <Windows.h>
#include <vector>
#include <string>
#include <chrono>


enum ResourceLoadError {
    SUCCESS = 0,
    ERROR_INVALID_PARAM = 1,
    ERROR_FIND_RESOURCE = 2,
    ERROR_LOAD_RESOURCE = 3,
    ERROR_LOCK_RESOURCE = 4,
    ERROR_SIZE_RESOURCE = 5
};

int LoadMatryoshkaResource(HMODULE hModule, const void** pDataOut, DWORD* pSizeOut)
{
    if (!hModule || !pDataOut || !pSizeOut)
        return ERROR_INVALID_PARAM;

    *pDataOut = nullptr;
    *pSizeOut = 0;

    HRSRC hRes = FindResource(hModule, TEXT("MATRYOSHKA"), RT_RCDATA);
    if (!hRes)
        return ERROR_FIND_RESOURCE;

    HGLOBAL hResLoad = LoadResource(hModule, hRes);
    if (!hResLoad)
        return ERROR_LOAD_RESOURCE;

    void* pResData = LockResource(hResLoad);
    if (!pResData)
        return ERROR_LOCK_RESOURCE;

    DWORD resSize = SizeofResource(hModule, hRes);
    if (resSize == 0)
        return ERROR_SIZE_RESOURCE;

    *pDataOut = pResData;
    *pSizeOut = resSize;

    return SUCCESS;
}

uint32_t HashString(char* str)
{
    uint32_t result = 0x811c9dc5;
    uint8_t* s = (uint8_t*)str;

    while (*s)
    {
        result ^= (uint32_t)*s; // NOTE: make this toupper(*s) or tolower(*s) if you want case-insensitive hashes
        result *= (uint32_t)0x01000193; // 32 bit magic FNV-1a prime
        s++;
    }

    return result;
}

void RC4(unsigned char* data, long dataLen, unsigned char* key, long keyLen, unsigned char* result)
/* Function to encrypt data represented in array of char "data" with length represented in dataLen using key which is represented in "Key" with length represented in keyLen, and result will be stored in result */
{
    unsigned char T[256];
    unsigned char S[256];
    unsigned char  tmp; // to be used in swaping
    int j = 0, t = 0, i = 0;


    /* S & K initialization */
    for (int i = 0; i < 256; i++)
    {
        S[i] = i;
        T[i] = key[i % keyLen];
    }
    /* State Permutation */
    for (int i = 0; i < 256; i++)
    {
        j = (j + S[i] + T[i]) % 256;

        //Swap S[i] & S[j]
        tmp = S[j];
        S[j] = S[i];
        S[i] = tmp;
    }
    j = 0; // reintializing j to reuse it
    for (int x = 0; x < dataLen; x++)
    {
        i = (i + 1) % 256; // using %256 to avoid exceed the array limit
        j = (j + S[i]) % 256; // using %256 to avoid exceed the array limit

        //Swap S[i] & S[j]
        tmp = S[j];
        S[j] = S[i];
        S[i] = tmp;

        t = (S[i] + S[j]) % 256;

        result[x] = data[x] ^ S[t]; // XOR generated S[t] with Byte from the plaintext / cipher and append each Encrypted/Decrypted byte to result array
    }
}

#define MAX_THREADS 8

typedef struct {
    DWORD start;
    DWORD end;
    BYTE sampleEncrypted[16];
} ThreadData;

DWORD g_FoundValue = 0xFFFFFFFF;

DWORD WINAPI BruteForceThread(LPVOID param) 
{
    ThreadData* data = (ThreadData*)param;
    BYTE sampleEncrypted[16];
    BYTE sampleDecrypted[16] = { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00 };

    // printf("0x%X - 0x%X\n", data->start, data->end);
    // return 0;

    for (DWORD brute = data->start; brute <= data->end; brute++) 
    {
        memcpy(sampleEncrypted, data->sampleEncrypted, sizeof(sampleEncrypted));
        RC4(sampleEncrypted, sizeof(sampleEncrypted), (unsigned char*)&brute, sizeof(brute), sampleEncrypted);
        if (memcmp(sampleEncrypted, sampleDecrypted, sizeof(sampleEncrypted)) == 0)
        {
            g_FoundValue = brute;
            break;
        }
        if (g_FoundValue != 0xFFFFFFFF)
            break;
    }

    return 0;
}

DWORD BruteHash(const BYTE* pData, DWORD size)
{
    DWORD startValue = 0;
    DWORD endValue = 0xFFFFFFFE;

    g_FoundValue = 0xFFFFFFFF;

    // Divide the work between multiple threads
    DWORD rangePerThread = (endValue - startValue + 1) / MAX_THREADS;

    // Create an array of thread handles
    HANDLE threads[MAX_THREADS] = { 0 };
    ThreadData threadData[MAX_THREADS] = { 0 };


    // Create threads
    for (int i = 0; i < MAX_THREADS; i++) 
    {
        threadData[i].start = startValue + i * rangePerThread;
        threadData[i].end = (i == MAX_THREADS - 1) ? endValue : (startValue + (i + 1) * rangePerThread - 1);
        memcpy(threadData[i].sampleEncrypted, pData, 16);

        threads[i] = CreateThread(NULL, NULL, BruteForceThread, &threadData[i], 0, NULL);

        if (threads[i] == NULL) 
        {
            printf("Failed to create thread %d\n", i);
            return 1;
        }
    }

    // Wait for all threads to finish
    WaitForMultipleObjects(MAX_THREADS, threads, TRUE, INFINITE);

    // Close thread handles
    for (int i = 0; i < MAX_THREADS; i++) 
    {
        CloseHandle(threads[i]);
    }

    return g_FoundValue;
}

BOOL WriteBufferToFile(const char* filePath, BYTE* buffer, DWORD bufferSize)
{
    // Open or create the file for writing, overwrite if file exists
    HANDLE hFile = CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    // Check if the file was created successfully
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Error creating file. Error code: %d\n", GetLastError());
        return FALSE; // Return FALSE if the file could not be created
    }

    DWORD bytesWritten = 0;

    // Write the buffer to the file
    if (!WriteFile(hFile, buffer, bufferSize, &bytesWritten, NULL))
    {
        printf("Error writing to file. Error code: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE; // Return FALSE if writing failed
    }

    // Verify if the correct number of bytes were written
    if (bytesWritten != bufferSize)
    {
        printf("Not all bytes were written to the file.\n");
        CloseHandle(hFile);
        return FALSE; // Return FALSE if not all bytes were written
    }

    // Successfully wrote the buffer to the file
    printf("Buffer written to file successfully!\n");

    // Close the file handle
    CloseHandle(hFile);

    return TRUE; // Return TRUE on successful write
}

void PrintVectorHex(const std::vector<DWORD>& vec)
{
    for (size_t i = 0; i < vec.size(); ++i)
    {
        printf("Item [%zu]: 0x%08X\n", i, vec[i]);
    }
}

std::string BrutePassword(std::vector<DWORD> vec_key)
{
    std::string password = "";

    for (int i = static_cast<int>(vec_key.size()) - 1; i >= 0; --i)
    {
        char tmp[3];
        bool found = false;
        for (char c0 = 0x20; c0 < 0x7f; c0++)
        {
            tmp[0] = c0;
            for (char c1 = 0x20; c1 < 0x7f; c1++)
            {
                tmp[1] = c1;
                tmp[2] = 0;
                std::string brute = tmp + password;
                if (HashString((char*)brute.c_str()) == vec_key[i])
                {
                    password = brute;
                    found = true;
                    break;
                }
            }
            if (found)
                break;
        }
    }

    return password;
}

int main()
{
    auto start = std::chrono::high_resolution_clock::now();

    std::vector<DWORD> vec_key;

    while (true)
    {
        HMODULE hDll = LoadLibraryA("MatryoshkaCopy.dll");
        if (!hDll)
        {
            printf("Failed to load dll.\n");
            return 1;
        }


        const void* pData = nullptr;
        DWORD size = 0;

        if (LoadMatryoshkaResource(hDll, &pData, &size) != SUCCESS)
        {
            printf("LoadMatryoshkaResource failed. Maybe last layer\n");
            break;
        }

        DWORD key = BruteHash((const BYTE*)pData, size);
        printf("Found key 0x%X\n", key);
        vec_key.push_back(key);

        BYTE* decryptedBin = (BYTE*)malloc(size);
        RC4((unsigned char*)pData, size, (unsigned char*)&key, sizeof(key), decryptedBin);

        FreeLibrary(hDll);

        WriteBufferToFile("MatryoshkaCopy.dll", decryptedBin, size);
        free(decryptedBin);

    }

    PrintVectorHex(vec_key);

    std::string password = BrutePassword(vec_key);

    printf("Found password %s\n", password.c_str());

    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> duration = end - start;
    printf("Execution time: %.3f ms\n", duration.count());

    return 0;
}
