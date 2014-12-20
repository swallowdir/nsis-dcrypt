#include <windows.h>
#include "nsis/pluginapi.h"
#include "marc4.h"
#include "md5.h"

// this may not work if /NODEFAULTLIB is used
#ifdef _MSC_VER
#  pragma comment(lib, "nsis/pluginapi-x86-unicode.lib")
#endif

//#undef EXDLL_INIT

//#define EXDLL_INIT() {  \
//        g_stringsize=string_size; \
//        g_stacktop=stacktop; }

#define NSISFunc(name) extern "C" void __declspec(dllexport) name(HWND hwndParent, int string_size, wchar_t *variables, stack_t **stacktop)

// open file enums
enum
{
    _INPUT_,   // mode for open files (read mode)
    _OUTPUT_   //     "     "         (write mode)
};

// source->dest enums
enum
{
    FileFile = 0,
    FileStr,
    StrFile,
    StrStr
};

// define the main vars as globals
         unsigned char g_key[1025];
         wchar_t g_key_filename[1024];
         wchar_t g_inkey[1024];
         wchar_t g_instr[1024];
         wchar_t g_in_filename[1024];
         wchar_t g_out_filename[1024];

unsigned int keylen;

// function to "clean" the stack, i,e. pops stack (expecting "--End--"), if gets REAL stack end (1), returns false,
// if gets a value that is NOT  "--End--", pushes back the value and returns false, if it gets the expected
// "--End--" it eats (discards) the "--End" and now that its happy it returns true
bool clean_stack()
{
    wchar_t garb[1024];
    FillMemory( (void *) garb, 1024, '\0');

    if ( popstring(garb) != 0)
        return false;

    if (lstrcmp(garb, L"--End--") != 0)
    {
        pushstring(garb);
        return false;
    }

    return true;
}

// function to "get" parm, pops from stack with error checking: returns false if hits REAL stack end or
// prematurely encounters "--End--", returns true if gets a non "--End--" string
bool get_parm(wchar_t *parm)
{
    if ( popstring(parm) != 0)
        return false;

    if (lstrcmp(parm, L"--End--") == 0)
        return false;

    return true;
}

// open file attempts to open file filename for processing mode (i.e. input or output)
HANDLE open_file(wchar_t *filename, int mode)
{
    HANDLE hFile;

    switch (mode)
    {
        case _INPUT_:
            hFile = CreateFile( filename,              // open input file
                                GENERIC_READ,          // open for reading
                                0,                     // dont share
                                NULL,                  // no security
                                OPEN_EXISTING,         // existing file only
                                FILE_ATTRIBUTE_NORMAL, // normal file
                                NULL);                 // no attr. template
            break;

        case _OUTPUT_:
            hFile = CreateFile( filename,               // open output file
                                GENERIC_WRITE,          // open for writing
                                0,                      // do not share
                                NULL,                   // no security
                                CREATE_ALWAYS,          // overwrite existing
                                FILE_ATTRIBUTE_NORMAL | // normal file with
                                FILE_FLAG_WRITE_THROUGH,// no lazy flushing
                                NULL);                  // no attr. template

            break;

        default:
            return(INVALID_HANDLE_VALUE);
    }

    return hFile;
}

// DoCipher Decrypts (Encrypts) g_instr using key string in g_key
bool DoCipher()
{
    // generate decryptor (encryptor)
    mrc4_ctx arc4;
    mrc4_keysetup(&arc4, g_key, keylen);

    int slen = (int) lstrlen( (LPCWSTR) g_instr);

    // decrypt (encrypt) the string
    mrc4_crypt(&arc4, (unsigned char *)g_instr, (unsigned char *)g_instr, slen);

    return true;
}

// DoFFCipher Decrypts (Encrypts) file g_in_filename to file g_out_filename using KEY in g_key
bool DoFFCipher()
{
    // try to open the input file for reading
    HANDLE hInFile = open_file(g_in_filename, _INPUT_);
    // push error if could not open and return
    if (hInFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open In_File Failed!");   // process error
        return false;
    }

    // try to open the output file for writing
    HANDLE hOutFile = open_file(g_out_filename, _OUTPUT_);
    // push error &  close in file if could not open and return
    if (hOutFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open Out_File Failed!");   // process error
        CloseHandle(hInFile); // close the input file
        return false;
    }

    // get Input File size
    unsigned int InFileSize = GetFileSize(hInFile, NULL);
    // if an error occurred bail
    if ( InFileSize == 0xFFFFFFFF)
    {
        pushstring(L"ERROR: GetFileSize Failed!"); // push error onto stack
        CloseHandle(hInFile);     // close the input file
        CloseHandle(hOutFile);    // close the output file
        DeleteFile(g_out_filename); // delete the file since it will NOT be complete
        return false;
    }

    // generate decryptor (encryptor)
    mrc4_ctx arc4;
    mrc4_keysetup(&arc4, g_key, keylen);

    // process the file in 4k chunks
    unsigned char buffer[4096];
    unsigned long  bytesRead, bytesWritten;

    do
    {
        if ( !ReadFile(hInFile, buffer, 4096, &bytesRead, NULL) )
        {
            // if an error,  push error, close the files, delete the incomplete out file and return false
            pushstring(L"ERROR: Reading File");
            CloseHandle(hInFile);
            CloseHandle(hOutFile);
            DeleteFile(g_out_filename); // delete the file since it will NOT be complete
            return false;
        }
        else
        {
            // read okay decrypt (encrypt) the buffer
            mrc4_crypt(&arc4, buffer, buffer, bytesRead);
            // write the block to the output file
            if ( !WriteFile(hOutFile, buffer, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead)
            {
                // if an error,  push error, close the files, delete the incomplete out file and return false
                pushstring(L"ERROR: writing File");
                CloseHandle(hInFile);
                CloseHandle(hOutFile);
                DeleteFile(g_out_filename); // delete the file since it will NOT be complete
                return false;
            }
        }
    } while (bytesRead == 4096);

    // Close the files.
    CloseHandle(hInFile);
    CloseHandle(hOutFile);

    // return true
    return true;
}

// DoFSCipher Decrypts (Encrypts) file g_in_filename to string g_instr using KEY in g_key
bool DoFSCipher(int *byte_len)
{
    // try to open the input file for reading
    HANDLE hInFile = open_file(g_in_filename, _INPUT_);
    // push error if could not open and return
    if (hInFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open In_File Failed!");   // process error
        return false;
    }

    FillMemory( (void *) g_instr, 1024, '\0');

    // get Input File size
    unsigned int InFileSize = GetFileSize(hInFile, NULL);
    // if an error occurred bail
    if ( InFileSize == 0xFFFFFFFF)
    {
        pushstring(L"ERROR: GetFileSize Failed!"); // push error onto stack
        CloseHandle(hInFile);     // close the input file
        return false;
    }

    // check file size (decrypted string usually a hex encoded key: must fit in NSIS string and expecting even length)
    if (InFileSize > 1022)
    {
        pushstring(L"ERROR: FileSize too big!"); // push error onto stack
        CloseHandle(hInFile);     // close the input file
        return false;
    }
    // generate decryptor (encryptor)
    mrc4_ctx arc4;
    mrc4_keysetup(&arc4, g_key, keylen);

    // process the file in a single chunk
    unsigned char buffer[1022];
    unsigned long  bytesRead;

    if ( !ReadFile(hInFile, buffer, 1022, &bytesRead, NULL) )
    {
        // if an error,  push error, close the files, delete the incomplete out file and return false
        pushstring(L"ERROR: Reading File");
        CloseHandle(hInFile);
        return false;
    }

    // read okay decrypt (encrypt) the buffer
    mrc4_crypt(&arc4, buffer, buffer, bytesRead);

    // copy decrypted (encrypted) buffer to g_instr
    for (int i = 0; i < (int) bytesRead; i++)
        g_instr[i] = (char) buffer[i];

    // Close the file
    CloseHandle(hInFile);

    *byte_len = (int) bytesRead;

    // return true
    return true;
}

// Decrypts (Encrypts) g_instr using g_key and write it to g_out_filename
bool DoSFCipher()
{
    // try to open the output file for writing
    HANDLE hOutFile = open_file(g_out_filename, _OUTPUT_); ;
    // print error &  close in file if could not open and return
    if (hOutFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open Out_File Failed!");   // process error
        return false;
    }

    // generate encryptor/decryptor
    mrc4_ctx arc4;
    mrc4_keysetup(&arc4, g_key, keylen);

    // encrypt (decrypt) the string
    int slen = lstrlen( (LPCWSTR) g_instr);
    mrc4_crypt(&arc4, (unsigned char *)g_instr, (unsigned char *)g_instr, slen);

    // write the block to the output file
    unsigned long  bytesWritten;
    if ( !WriteFile(hOutFile, g_instr, slen, &bytesWritten, NULL) || (int) bytesWritten != slen)
    {
        // if an error,  print error, close the files, delete useles out file, bail
        pushstring(L"ERROR: Writing File!");   // process error
        CloseHandle(hOutFile);
        DeleteFile(g_out_filename); // delete the file since it will NOT be complete
        return false;
    }

    // Close the file.
    CloseHandle(hOutFile);

    // return true (success)
    return true;
}

// get input file filename from stack, pushes error msg and returns false on error
bool GetInFileName()
{
    // get the Input (encrypted) filename
    FillMemory( (void *) g_in_filename, 1024, '\0');
    if ( !get_parm(g_in_filename) )
    {
        pushstring(L"ERROR: wrong # parms, Input FileName expected!");
        return false;
    }

    return true;
}

// get input string from stack, pushes error msg and returns false on error
bool GetInString()
{
    FillMemory( (void *) g_instr, 1024, '\0');
    if ( !get_parm(g_instr) )
    {
        pushstring(L"ERROR: wrong # parms, String expected!");
        return false;
    }

    return true;
}

// get output file filename from stack, pushes error msg and returns false on error
bool GetOutFileName()
{
    FillMemory( (void *) g_out_filename, 1024, '\0');
    if ( !get_parm(g_out_filename) )
    {
        pushstring(L"ERROR: wrong # parms, Output FileName expected!");
        return false;
    }

    return true;
}

// decodes (to wchar_t) the hex encoded string in hex_string, in place
bool HexDecode(unsigned char *hex_string, int slen)
{
    if ( slen < 2 || slen % 2 != 0)
    {
        pushstring(L"ERROR: HexDecode: hex encoded string length NOT even!");
        return false;
    }

    int           i, j;
    unsigned char c, newchar, hex_sub1, hex_sub2;
    hex_sub1 = wchar_t ('A' - 10);
    hex_sub2 = wchar_t ('a' - 10);

    for (i = 0, j = 0; i < slen; i++)
    {
        // get character and make sure a valid hex encoded character
        c = hex_string[i];
        if ( ! ( (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') ) )
        {
            pushstring(L"ERROR: HexDecode: invalid (non hex) character in string!");
            return false;
        }
        // valid hex char, convert to binary value
        if (c >= '0' && c <= '9')
            c -= (wchar_t) '0';
        else
        if (c >= 'A' && c <= 'F')
            c = (wchar_t) (c - hex_sub1);
        else
            c = (wchar_t) (c - hex_sub2);

        // now see if 1st or second byte of 2 byte group
        if (i % 2 == 0)
            newchar = (wchar_t) (c << 4); // 1st byte of group (0 based: 0 is 1st, 1 is 2nd, 2 is 1st, 3 is 2nd, etc)
        else
        {
            // 2nd byte push together into single wchar_t byte
            newchar = (wchar_t) (newchar | c);    // low nibble of newchar = 0000, high nibble of c is 0000 so bitwise OR
            hex_string[j++] = newchar;// can overwrite hex_string as j < i so already processed
        }
    }

    // done decoding, value of j is 1/2 slen, 0 out hex_string from j to end;
    while (j < slen)
    {
        hex_string[j++] = 0;
    }

    // all done
    return true;
}

// hex encodes in place the string in in_string, in_string MUST be big enough to hold 2 * slen chars
bool HexEncode(unsigned char *in_string, int slen)
{
    int           i, j;
    int           hchar1, hchar2;
    wchar_t c;

    if ( slen < 1)
    {
        pushstring(L"ERROR: HexEncode: string length == 0!");
        return false;
    }

    // since doing in place and encoded string will be TWICE size of input string must process from end
    for (i = slen - 1, j = (slen - 1) * 2; i >= 0; i--, j -= 2)
    {
        // get character and make sure a valid hex encoded character
        c = in_string[i];

        // process "high" nibble
        hchar1 = c >> 4;
        if (hchar1 < 10)
            hchar1 += (int) '0';
        else
            hchar1 = (hchar1 - 10) + (int) 'A';

        // process "low" nibble"
        hchar2 = c & 0x0f;
        if (hchar2 < 10)
            hchar2 += (int) '0';
        else
            hchar2 = (hchar2 - 10) + (int) 'A';

        // put hchar1 and hchar2 back into appropriate place in in_string
        in_string[j] = (unsigned char) hchar1;
        in_string[j + 1] = (unsigned char)hchar2;
    }

    // all done
    return true;
}

// ParseKey "parses" g_inkey for Hex Encoded chars, skips all NON Hex Encoded Chars,
// copies the hex encoded characters to global var key,  returns length of resulting key
int ParseToKey()
{
    int i, j, k = 0;
    wchar_t c;

    FillMemory( (void *) g_key, 1025, '\0');

    i = lstrlen(g_inkey);
    for (j = 0; j < i; j++)
    {
        c = g_inkey[j];
        if ( (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') )
        {
            if (k > 1023)
            {
                pushstring(L"ERROR: Key String too big!");
                return(-1);
            }
            // add to key_buffer if a Hex Encoded value
            g_key[k++] = (unsigned char)c;
        }
    }

    return(k);
}

// function to calc MD5Hash of contents of input file
bool HashFile(unsigned char *digest)
{
    // try to open the input file for reading
    HANDLE hInFile = open_file(g_in_filename, _INPUT_);

    // push error if could not open and return
    if (hInFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open In_File Failed!");   // process error
        return false;
    }

    // get Input File size
    unsigned int InFileSize = GetFileSize(hInFile, NULL);
    // if an error occurred bail
    if ( InFileSize == 0xFFFFFFFF)
    {
        pushstring(L"ERROR: GetFileSize Failed!"); // push error onto stack
        CloseHandle(hInFile);     // close the input file
        return false;
    }

    // create and initialize MD5 hash context
    MD5Context    md5c;
    MD5Init(&md5c);

    // expect most often doing MD5 hashes of KEY files which will be small, no sense wasting too much buffer,
    // process file in 256 byte chunks
    unsigned char buffer[256];
    unsigned long bytesRead;

    do
    {
        if ( !ReadFile(hInFile, buffer, 256, &bytesRead, NULL) )
        {
            // if an error,  print error, close the files, delete useless out file and bail
            pushstring(L"ERROR: Reading File!"); // push error onto stack
            CloseHandle(hInFile);
            return false;
        }
        else
        {
            // read okay update the MD5 hash context
            MD5Update(&md5c, buffer, (unsigned int) bytesRead);
        }
    } while (bytesRead == 256);

    // Close the input file
    CloseHandle(hInFile);

    // Finalize MD5 calc
    FillMemory( (void *) digest, 33, '\0');
    MD5Final(digest, &md5c);

    // now Hex Encode the hash
    if ( !HexEncode(digest, 16) )
        return false;

    return true;
}

// function to calc MD5Hash of contents of input file
bool HashStr(unsigned char *digest)
{
    // make sure have a string
    int strSize = (int) lstrlen( (LPCWSTR) g_instr);
    if (strSize < 1)
    {
        pushstring(L"ERROR: MD5 Hash: No String!"); // push error onto stack
    }

    // create and initialize MD5 hash context
    MD5Context    md5c;
    MD5Init(&md5c);

    // update the MD5 hash context
    MD5Update(&md5c, (unsigned char *) g_instr, (unsigned int) strSize);

    // Finalize MD5 calc
    FillMemory( (void *) digest, 33, '\0');
    MD5Final(digest, &md5c);

    // now Hex Encode the hash
    if ( !HexEncode(digest, 16) )
        return false;

    return true;
}

// function Hex Decode contents of input file to output file
bool HexDFileFile()
{
    // try to open the input file for reading
    HANDLE hInFile = open_file(g_in_filename, _INPUT_);
    // push error if could not open and return
    if (hInFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open In_File Failed!");   // process error
        return false;
    }

    // get Input File size
    unsigned int InFileSize = GetFileSize(hInFile, NULL);
    // if an error occurred bail
    if ( InFileSize == 0xFFFFFFFF)
    {
        pushstring(L"ERROR: GetFileSize Failed!"); // push error onto stack
        CloseHandle(hInFile);     // close the input file
        return false;
    }

    // Verify size > 0 and is an Even number
    if (InFileSize < 2 || InFileSize % 2 != 0)
    {
        pushstring(L"ERROR: HexDecodeFile: Invalid file size!");
        return false;
    }

    // try to open the output file for writing
    HANDLE hOutFile = open_file(g_out_filename, _OUTPUT_);
    // push error &  close in file if could not open and return
    if (hOutFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open Out_File Failed!");   // process error
        CloseHandle(hInFile); // close the input file
        return false;
    }

    // Do the Decoding in 256 byte chunks (which will be 128 bytes after decoding) as don't expect will be hex encoding
    // large files
    unsigned char buffer[256];
    unsigned long  bytesRead, bytesWritten;

    do
    {
        if ( !ReadFile(hInFile, buffer, 256, &bytesRead, NULL) )
        {
            // if an error,  push error, close the files, delete the incomplete out file and return false
            pushstring(L"ERROR: Reading File");
            CloseHandle(hInFile);
            CloseHandle(hOutFile);
            DeleteFile(g_out_filename); // delete the file since it will NOT be complete
            return false;
        }
        else
        {
            // make sure got even number of bytes
            if ( bytesRead % 2 != 0)
            {
                pushstring(L"ERROR: Input buffer length NOT EVEN, unexpected!");
                CloseHandle(hInFile);
                CloseHandle(hOutFile);
                DeleteFile(g_out_filename); // delete the file since it will NOT be complete
                return false;
            }

            // hex decode input string
            if ( !HexDecode(buffer, (int) bytesRead) )
            {
                CloseHandle(hInFile);
                CloseHandle(hOutFile);
                DeleteFile(g_out_filename); // delete the file since it will NOT be complete
                return false;
            }

            // write the hex decoded block to the output file (bytes written will be 1/2 bytes read
            if ( !WriteFile(hOutFile, buffer, bytesRead / 2, &bytesWritten, NULL) || bytesWritten != (bytesRead /2) )
            {
                // if an error,  push error, close the files, delete the incomplete out file and return false
                pushstring(L"ERROR: writing File");
                CloseHandle(hInFile);
                CloseHandle(hOutFile);
                DeleteFile(g_out_filename); // delete the file since it will NOT be complete
                return false;
            }
        }
    } while (bytesRead == 256);

    // Close the files.
    CloseHandle(hInFile);
    CloseHandle(hOutFile);

    return true;
}

// function Hex Decode contents of input file to a string,
// note if decoded string contains embeded binary (non "string") data it may be useless
bool HexDFileStr()
{
    // try to open the input file for reading
    HANDLE hInFile = open_file(g_in_filename, _INPUT_);

    // push error if could not open and return
    if (hInFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open In_File Failed!");   // process error
        return false;
    }

    // get Input File size
    unsigned int InFileSize = GetFileSize(hInFile, NULL);
    // if an error occurred bail
    if ( InFileSize == 0xFFFFFFFF)
    {
        pushstring(L"ERROR: GetFileSize Failed!"); // push error onto stack
        CloseHandle(hInFile);     // close the input file
        return false;
    }

    // Verify size > 0 and is an Even number, and is NOT > 2046 so decoded size will be < 1024
    if (InFileSize < 2 || InFileSize > 2046 || InFileSize % 2 != 0)
    {
        pushstring(L"ERROR: HexDecodeFile: Invalid file size!");
        return false;
    }

    // Do the Decoding in a single chunk
    // large files
    unsigned char buffer[2046];
    unsigned long  bytesRead;

    if ( !ReadFile(hInFile, buffer, 2046, &bytesRead, NULL) )
    {
        // if an error,  push error, close the files, delete the incomplete out file and return false
        pushstring(L"ERROR: Reading File");
        CloseHandle(hInFile);
        return false;
    }

    // make sure got even number of bytes
    if ( bytesRead % 2 != 0)
    {
        pushstring(L"ERROR: Input buffer length NOT EVEN, unexpected!");
        CloseHandle(hInFile);
        return false;
    }

    // Close the file.
    CloseHandle(hInFile);

    // hex decode input string
    if ( !HexDecode(buffer, (int) bytesRead) )
        return false;

    // copy the hex decoded block to the instr var (zero filling 1st)
    FillMemory(g_instr, 1024, '\0');
    for (int i = 0; i < (int) bytesRead / 2; i++)
        g_instr[i] = (char) buffer[i];

    return true;
}

// function Hex Decode contents of input string to output file
bool HexDStrFile()
{
    // check size of input string to make sure is > 1 and an EVEN number
    int strSize = (int) lstrlen( (LPCWSTR) g_instr);

    // if an error occurred bail
    if (strSize < 2 || strSize % 2 != 0)
    {
        pushstring(L"ERROR: HexDecodeStr: Invalid string size!");
        return false;
    }

    // try to open the output file for writing
    HANDLE hOutFile = open_file(g_out_filename, _OUTPUT_);
    // push error &  close in file if could not open and return
    if (hOutFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open Out_File Failed!");   // process error
        CloseHandle(hOutFile); // close the input file
        return false;
    }

    // hex decode input string (decodes in place)
    if ( !HexDecode((unsigned char *) g_instr, strSize) )
    {
        CloseHandle(hOutFile);
        DeleteFile(g_out_filename); // delete the file since it will NOT be complete
        return false;
    }

    unsigned long  bytesWritten;
    // write the hex decoded block to the output file (bytes written will be 1/2 bytes read
    if ( !WriteFile(hOutFile, (wchar_t *) g_instr, strSize / 2, &bytesWritten, NULL) ||
          (int) bytesWritten != (strSize / 2) )
    {
        // if an error,  push error, close the files, delete the incomplete out file and return false
        pushstring(L"ERROR: writing File");
        CloseHandle(hOutFile);
        DeleteFile(g_out_filename); // delete the file since it will NOT be complete
        return false;
    }

    // close the file
    CloseHandle(hOutFile);
    return true;
}

// function to Hex Decode contents of input string to a string
// note if decoded string contains embeded binary (non "string") data it may be useless
bool HexDStrStr()
{
    // check size of input string to make sure is > 1 and an EVEN number
    int strSize = (int) lstrlen( (LPCWSTR) g_instr);

    // if an error occurred bail
    if (strSize < 2 || strSize % 2 != 0)
    {
        pushstring(L"ERROR: HexDecodeStr: Invalid string size!");
        return false;
    }

    // hex decode input string in place
    if ( !HexDecode( (unsigned char *) g_instr, strSize) )
        return false;

    return true;
}

// function Hex Encode contents of input file to output file
bool HexEFileFile()
{
    // try to open the input file for reading
    HANDLE hInFile = open_file(g_in_filename, _INPUT_);

    // push error if could not open and return
    if (hInFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open In_File Failed!");   // process error
        return false;
    }

    // get Input File size
    unsigned int InFileSize = GetFileSize(hInFile, NULL);
    // if an error occurred bail
    if ( InFileSize == 0xFFFFFFFF)
    {
        pushstring(L"ERROR: GetFileSize Failed!"); // push error onto stack
        CloseHandle(hInFile);     // close the input file
        return false;
    }

    // Verify size > 0
    if (InFileSize < 1)
    {
        pushstring(L"ERROR: HexEncodeFile: Invalid file size!");
        return false;
    }

    // try to open the output file for writing
    HANDLE hOutFile = open_file(g_out_filename, _OUTPUT_);
    // push error &  close in file if could not open and return
    if (hOutFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open Out_File Failed!");   // process error
        CloseHandle(hInFile); // close the input file
        return false;
    }

    // Do the Encoding in 128 byte chunks (which will be 256 bytes after encoding) as don't expect will be hex encoding
    // large files
    unsigned char buffer[256];
    unsigned long  bytesRead, bytesWritten;

    do
    {
        if ( !ReadFile(hInFile, buffer, 128, &bytesRead, NULL) )
        {
            // if an error,  push error, close the files, delete the incomplete out file and return false
            pushstring(L"ERROR: Reading File");
            CloseHandle(hInFile);
            CloseHandle(hOutFile);
            DeleteFile(g_out_filename); // delete the file since it will NOT be complete
            return false;
        }

        // hex encode input string
        if ( !HexEncode(buffer, (int) bytesRead) )
        {
            CloseHandle(hInFile);
            CloseHandle(hOutFile);
            DeleteFile(g_out_filename); // delete the file since it will NOT be complete
            return false;
        }

        // write the hex encoded block to the output file (bytes written will be twice bytes read)
        if ( !WriteFile(hOutFile, buffer, bytesRead * 2, &bytesWritten, NULL) || bytesWritten != (bytesRead * 2) )
        {
            // if an error,  push error, close the files, delete the incomplete out file and return false
            pushstring(L"ERROR: writing File");
            CloseHandle(hInFile);
            CloseHandle(hOutFile);
            DeleteFile(g_out_filename); // delete the file since it will NOT be complete
            return false;
        }
    } while (bytesRead == 128);

    // Close the files.
    CloseHandle(hInFile);
    CloseHandle(hOutFile);

    return true;
}

// function Hex Encode contents of input file to a string passed back on stack, input must be < 512 bytes
bool HexEFileStr()
{
    // try to open the input file for reading
    HANDLE hInFile = open_file(g_in_filename, _INPUT_);

    // push error if could not open and return
    if (hInFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open In_File Failed!");   // process error
        return false;
    }

    // get Input File size
    unsigned int InFileSize = GetFileSize(hInFile, NULL);
    // if an error occurred bail
    if ( InFileSize == 0xFFFFFFFF)
    {
        pushstring(L"ERROR: GetFileSize Failed!"); // push error onto stack
        CloseHandle(hInFile);     // close the input file
        return false;
    }

    // Verify size > 0 and is NOT > 511 so enccoded size will be < 1024
    if (InFileSize < 1 || InFileSize > 511)
    {
        pushstring(L"ERROR: HexEncodeFile: Invalid file size!");
        return false;
    }

    // Do the Encoding in a single chuck
    unsigned long  bytesRead;
    unsigned char buffer[1022];
    if ( !ReadFile(hInFile, buffer, 511, &bytesRead, NULL) )
    {
        // if an error,  push error, close the files, delete the incomplete out file and return false
        pushstring(L"ERROR: Reading File");
        CloseHandle(hInFile);
        return false;
    }

    // Close the file.
    CloseHandle(hInFile);

    // hex encode buffer in place
    if ( !HexEncode(buffer, (int) bytesRead) )
        return false;

    // copy the hex encoded block to the instr var (zero filling 1st)
    FillMemory(g_instr, 1024, '\0');
    for (int i = 0; i < (int) bytesRead * 2; i++)
        g_instr[i] = (char) buffer[i];

    return true;
}

// function Hex Encode contents of input string to output file
bool HexEStrFile()
{
    // get size of input string to make sure is > 1
    int strSize = (int) lstrlen( (LPCWSTR) g_instr);

    // if an error occurred bail
    if (strSize < 1)
    {
        pushstring(L"ERROR: HexEncodeStr: Invalid string size!");
        return false;
    }

    // try to open the output file for writing
    HANDLE hOutFile = open_file(g_out_filename, _OUTPUT_);

    // push error &  close in file if could not open and return
    if (hOutFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open Out_File Failed!");   // process error
        CloseHandle(hOutFile); // close the input file
        return false;
    }

    // hex encode input string (encodes in place)
    if ( !HexEncode( (unsigned char *) g_instr, strSize) )
    {
        CloseHandle(hOutFile);
        DeleteFile(g_out_filename); // delete the file since it will NOT be complete
        return false;
    }

    unsigned long  bytesWritten;
    // write the hex encoded block to the output file (bytes written will be twice bytes read)
    if ( !WriteFile(hOutFile, (wchar_t *) g_instr, strSize * 2, &bytesWritten, NULL) ||
          (int) bytesWritten != (strSize * 2) )
    {
        // if an error,  push error, close the files, delete the incomplete out file and return false
        pushstring(L"ERROR: writing File");
        CloseHandle(hOutFile);
        DeleteFile(g_out_filename); // delete the file since it will NOT be complete
        return false;
    }

    // Close the file.
    CloseHandle(hOutFile);
    return true;
}

// function Hex Encode contents of input string to a string passed back on stack, input must be < 512 bytes
bool HexEStrStr()
{
    // check size of input string to make sure is > 1 and < 512
    int strSize = (int) lstrlen( (LPCWSTR) g_instr);

    // if an error occurred bail
    if (strSize < 1 || strSize > 511)
    {
        pushstring(L"ERROR: HexEnccodeStr: Invalid string size!");
        return false;
    }

    // hex encode input string in place
    if ( !HexEncode( (unsigned char *) g_instr, strSize) )
        return false;

    return true;
}

// KeyFromFile reads Hex Encoded KeyString from g_key_filename into global var key, L"parses" string contained in file,
// skipping all NON Hex Encoded Chars, pushes error message and returns false on error
bool KeyFromFile()
{
    // Get the KeyString File Name
    FillMemory( (void *) g_key_filename, 1024, '\0');
    if ( !get_parm(g_key_filename) )
    {
        pushstring(L"ERROR: wrong # parms, KEY expected!");
        return false;
    }

    // try to open the input key file for reading
    HANDLE hKeyFile = open_file(g_key_filename, _INPUT_);
    // print error if could not open and return
    if (hKeyFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open Key_File Failed!");   // process error
        return false;
    }

    // get Input File size
    unsigned int keyFileSize = GetFileSize(hKeyFile, NULL);
    // if an error occurred print message and bail
    if ( keyFileSize == 0xFFFFFFFF)
    {
        pushstring(L"ERROR: GetFileSize of KeyFile Failed!");   // process error
        CloseHandle(hKeyFile);     // close the input file
        return false;
    }

    // max key size = 1024, but allow /r/n and '-' or other seperators in key, so allow
    // larger size with SKIP of values outside range of '0' <--> '9' and 'A' <--> 'F'
    // (or 'a' - 'f'), process file using buffer of 256
    unsigned char buffer[256];
    unsigned long bytesRead;

    int j, k = 0;
    unsigned char c;
    // read key file
    do
    {
        if ( !ReadFile(hKeyFile, buffer, 256, &bytesRead, NULL) )
        {
            // if an error,  print error, close the file, and bail
            pushstring(L"ERROR: Reading Key File!");   // process error
            CloseHandle(hKeyFile);
            return false;
        }

        // process buffer skipping non Hex Encoded Characters (bail is key size exceeds 1024)
        for (j = 0; j < (int) bytesRead; j++)
        {
            c = buffer[j];
            if ( (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') )
            {
                if (k > 1023)
                {
                    pushstring(L"ERROR: Processing Key File, key too big!");   // process error
                    CloseHandle(hKeyFile);
                    return false;
                }
                // add to key_buffer if a Hex Encoded value
                g_key[k++] = c;
            }
        }
    } while (bytesRead == 256);

    // close the keyfile
    CloseHandle(hKeyFile);

    // make sure length okay
    if ( k  < 16)
    {
        wchar_t aaa[200];
        wsprintf(aaa, L"Key Length too SMALL! (%d)", k);
        //pushstring(L"Key Length too SMALL!");
        pushstring(aaa);
        return(false);
    }

    if (k % 2 != 0 )
    {
        pushstring(L"Key Length not EVEN!");
        return(false);
    }

    // now decode the hex encoded key
    if ( !HexDecode(g_key, k) )
        return false;

    // set global var keylen for actual decryption / encryption
    keylen = k / 2;

    // key okay and decoded, return true
    return true;
}

// KeyFromStr pops Hex Encoded KeyString from stack into global var key, L"parses" key string,
// skipping all NON Hex Encoded Chars, pushes error message and returns false on error
bool KeyFromStr()
{
    // Get the KeyString
    FillMemory( (void *) g_inkey, 1024, '\0');
    if ( !get_parm(g_inkey) )
    {
        pushstring(L"ERROR: wrong # parms, KEY expected!");
        return false;
    }

    // need wchar_t version of key for hexdecoder, parse wchar_t input keystring to wchar_t global var key
    int i = ParseToKey();
    if (i < 0)
        return false; // error occurred in ParseToKey, already pushed so just return

    if (i % 2 != 0)
    {
        pushstring(L"ERROR: bad keysize, length MUST be even!");
        return false;
    }

    // now decode the hex encode key
    if ( !HexDecode(g_key, i) )
        return false;

    // set global var keylen for actual decryption / encryption
    keylen = i / 2;

    return true;
}

bool WriteMD5Hash(unsigned char *digest)
{
    // try to open the output file for writing
    HANDLE hOutFile = open_file(g_out_filename, _OUTPUT_);
    // print error &  close in file if could not open and return
    if (hOutFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open Out_File Failed!"); // push error onto stack
        return false;
    }

    unsigned long bytesWritten;
    // write the hex encoded MD5 hash to the output file
    if ( !WriteFile(hOutFile, digest, 32, &bytesWritten, NULL) || bytesWritten != 32 )
    {
        // if an error,  print error, close the files, delete useles out file, bail
        pushstring(L"ERROR: Writing File!"); // push error onto stack
        CloseHandle(hOutFile);
        DeleteFile(g_out_filename); // delete the file since it will NOT be complete
        return false;
    }

    // all done, close file and return true
    CloseHandle(hOutFile);
    return true;
}

// Decrypt function
NSISFunc(Decrypt)
{
    // initialize DLL
    EXDLL_INIT();

    wchar_t parm1[1024];
    // Get and validate the 1st parm
    if ( !get_parm(parm1) )
    {
        pushstring(L"ERROR: wrong # parms: Decrypt function expected!");
        return;
    }

    // test for valid function
    if (  lstrlen(parm1) != 3 ||
         (lstrcmp(parm1, L"FFF") != 0 && lstrcmp(parm1, L"FFH") != 0 && lstrcmp(parm1, L"FFS") != 0 &&
          lstrcmp(parm1, L"FSF") != 0 && lstrcmp(parm1, L"FSH") != 0 && lstrcmp(parm1, L"FSS") != 0 &&
          lstrcmp(parm1, L"SFF") != 0 && lstrcmp(parm1, L"SFH") != 0 && lstrcmp(parm1, L"SFS") != 0 &&
          lstrcmp(parm1, L"SSF") != 0 && lstrcmp(parm1, L"SSH") != 0 && lstrcmp(parm1, L"SSS") != 0
         )
        )
    {
        pushstring(L"ERROR: invalid parm: Decrypt function expected!");
        return;
    }

    // if valid "function" determine key source and process key
    if ( parm1[0] == 'F')
    {
        // get key from file, if errors, messages already pushed, just exit
        if ( !KeyFromFile() )
            return;
    }
    else
    {
        // get key from string, if errors, messages already pushed, just exit
        if ( !KeyFromStr() )
            return;
    }

    // determine data (to decrypt) source and process parm
    if ( parm1[1] == 'F')
    {
        // get the Input (encrypted) filename, if errors, messages already pushed just exit
        if ( !GetInFileName() )
            return;
    }
    else
    {
        // Get the String to Decrypt (EnCrypt), if errors messages already pushed, just exit
        if ( !GetInString() )
            return;
    }

    // determine data (to decrypt) sink and process parm
    if ( parm1[2] == 'F')
    {
        // Get the Output filename, if errors messages already pushed, just exit
        if ( !GetOutFileName() )
            return;
    }
    // no parm when sink (output) is a string (will just get pushed to stack)

    // correct # parms, clean "--End--" from stack
    if ( !clean_stack() )
    {
        pushstring(L"ERROR: --End-- missing");
        return;
    }

    // determine DoXXXCipher routine to call:
    int func_to_call = -1;
    if ( lstrcmp( &parm1[1], L"FF") == 0 )
    {
        func_to_call = FileFile;
    }
    else
    {
        if ( lstrcmp( &parm1[1], L"FS") == 0 || lstrcmp( &parm1[1], L"FH") == 0)
        {
            func_to_call = FileStr;
        }
        else
        {
            if ( lstrcmp( &parm1[1], L"SF") == 0 )
            {
                func_to_call = StrFile;
            }
            else
            {
                func_to_call = StrStr;
            }
        }
    }

    // now do the decrypt function
    int byte_len = 0;
    switch (func_to_call)
    {
        case FileFile:
            // File to File: DoFFCipher
            // Do the decryption (or encryption since using symmetric stream cipher ARC4)
            // if an error occurred, will already be pushed on stack, if no errors: push OK onto stack
            if ( DoFFCipher() )
                pushstring(L"OK");
            break;

        case FileStr:
            // File to String: DoFSCipher (return on stack)
            // Do the decryption (or encryption since using symmetric stream cipher ARC4)
            // if an error occurred, will already be pushed on stack, if no errors: push decrypted (encrypted) var g_instr
            // onto stack, then push OK status message
            if ( DoFSCipher( &byte_len) )
            {
                if ( parm1[2] == 'H')
                {
                    if (byte_len > 511)
                    {
                        pushstring(L"ERROR: string too large to Hex Encode!");
                        return;
                    }

                    // now hex encode the string (if errors, already pushed return)
                    if ( !HexEncode((unsigned char *) g_instr, byte_len) )
                        return;
                }

                pushstring(g_instr);
                pushstring(L"OK");
            }
            break;

        case StrFile:
            // Str to File: DoSFCipher
            // Do the decryption (or encryption since using symmetric stream cipher ARC4)
            // if an error occurred, will already be pushed on stack, if no errors: push OK onto stack and delete the input file
            // as output file should be the one we want
            if ( DoSFCipher() )
                pushstring(L"OK");
            break;

        case StrStr:
            // must be Str to Str: DoCipher  (return on stack)
            // Do the decryption (or encryption since using symmetric stream cipher ARC4)
            // if an error occurred, will already be pushed on stack, if no errors: push Decrypted (Encrypte) string
            // onto stack then push OK onto stack
            if ( DoCipher() )
            {
                if ( parm1[2] == 'H')
                {
                    int i = lstrlen(g_instr);
                    if (i > 511)
                    {
                        pushstring(L"ERROR: string too large to Hex Encode!");
                        return;
                    }

                    // now hex encode the string (if errors, already pushed return)
                    if ( !HexEncode((unsigned char *) g_instr, i) )
                        return;
                }

                pushstring(g_instr);
                pushstring(L"OK");
            }
            break;
    }

    // everything should be handled, return
    return;
}

// Hex Decoder function
NSISFunc(HexDecoder)
{
    // initialize DLL
    EXDLL_INIT();

    wchar_t parm1[1024];
    // Get and validate the 1st parm
    if ( !get_parm(parm1) )
    {
        pushstring(L"ERROR: wrong # parms: HexDecoder function expected!");
        return;
    }

    // test for valid function
    if (  lstrlen(parm1) != 2 ||
         (lstrcmp(parm1, L"FF") != 0 && lstrcmp(parm1, L"FS") != 0 &&
          lstrcmp(parm1, L"SF") != 0 && lstrcmp(parm1, L"SS") != 0
         )
        )
    {
        pushstring(L"ERROR: invalid parm: HexDecoder function expected!");
        return;
    }

    // if valid "function" determine data source and process parm
    if ( parm1[0] == 'F')
    {
        // get the Input ilename, if errors, messages already pushed just exit
        if ( !GetInFileName() )
            return;
    }
    else
    {
        // Get the Input String, if errors messages already pushed, just exit
        if ( !GetInString() )
            return;
    }

    // determine data sink and process parm
    if ( parm1[1] == 'F')
    {
        // Get the Output filename, if errors messages already pushed, just exit
        if ( !GetOutFileName() )
            return;
    }
    // no parm when sink (output) is a string (will just get pushed to stack)

    // correct # parms, clean "--End--" from stack
    if ( !clean_stack() )
    {
        pushstring(L"ERROR: --End-- missing");
        return;
    }

    // determine HexDecoder routine to call:
    int func_to_call = -1;
    if ( lstrcmp( parm1, L"FF") == 0 )
    {
        func_to_call = FileFile;
    }
    else
    {
        if ( lstrcmp( parm1, L"FS") == 0 )
        {
            func_to_call = FileStr;
        }
        else
        {
            if ( lstrcmp( parm1, L"SF") == 0 )
            {
                func_to_call = StrFile;
            }
            else
            {
                func_to_call = StrStr;
            }
        }
    }

    // now do the hex decoder function
    switch (func_to_call)
    {
        case FileFile:
            // File to File: HexDFileFile
            // if an error occurred, will already be pushed on stack, if no errors: push OK onto stack
            if ( HexDFileFile() )
                pushstring(L"OK");
            break;

        case FileStr:
            // File to String: HexDFileStr
            // if an error occurred, will already be pushed on stack, if no errors: push string and status
            if ( HexDFileStr() )
            {
                pushstring(g_instr);
                pushstring(L"OK");
            }
            break;

        case StrFile:
            // Str to File: HexDStrFile
            // if an error occurred, will already be pushed on stack, if no errors: push OK onto stack
            if ( HexDStrFile() )
                pushstring(L"OK");
            break;

        case StrStr:
            // must be Str to Str: HexDStrStr
            // if an error occurred, will already be pushed on stack, if no errors: push string and status
            if ( HexDStrStr() )
            {
                pushstring(g_instr);
                pushstring(L"OK");
            }
            break;
    }

    return;
}

// Hex Encoder function
NSISFunc(HexEncoder)
{
    // initialize DLL
    EXDLL_INIT();

    wchar_t parm1[1024];
    // Get and validate the 1st parm
    if ( !get_parm(parm1) )
    {
        pushstring(L"ERROR: wrong # parms: HexEncoder function expected!");
        return;
    }

    // test for valid function
    if (  lstrlen(parm1) != 2 ||
         (lstrcmp(parm1, L"FF") != 0 && lstrcmp(parm1, L"FS") != 0 &&
          lstrcmp(parm1, L"SF") != 0 && lstrcmp(parm1, L"SS") != 0
         )
        )
    {
        pushstring(L"ERROR: invalid parm: HexEncoder function expected!");
        return;
    }

    // if valid "function" determine data source and process parm
    if ( parm1[0] == 'F')
    {
        // get the Input ilename, if errors, messages already pushed just exit
        if ( !GetInFileName() )
            return;
    }
    else
    {
        // Get the Input String, if errors messages already pushed, just exit
        if ( !GetInString() )
            return;
    }

    // determine data sink and process parm
    if ( parm1[1] == 'F')
    {
        // Get the Output filename, if errors messages already pushed, just exit
        if ( !GetOutFileName() )
            return;
    }
    // no parm when sink (output) is a string (will just get pushed to stack)

    // correct # parms, clean "--End--" from stack
    if ( !clean_stack() )
    {
        pushstring(L"ERROR: --End-- missing");
        return;
    }

    // determine HexDecoder routine to call:
    int func_to_call = -1;
    if ( lstrcmp( parm1, L"FF") == 0 )
    {
        func_to_call = FileFile;
    }
    else
    {
        if ( lstrcmp( parm1, L"FS") == 0 )
        {
            func_to_call = FileStr;
        }
        else
        {
            if ( lstrcmp( parm1, L"SF") == 0 )
            {
                func_to_call = StrFile;
            }
            else
            {
                func_to_call = StrStr;
            }
        }
    }

    // now do the hex encoder function
    switch (func_to_call)
    {
        case FileFile:
            // File to File: HexEFileFile
            // if an error occurred, will already be pushed on stack, if no errors: push OK onto stack
            if ( HexEFileFile() )
                pushstring(L"OK");
            break;

        case FileStr:
            // File to String: HexEFileStr
            // if an error occurred, will already be pushed on stack, if no errors: push string and status
            if ( HexEFileStr() )
            {
                pushstring(g_instr);
                pushstring(L"OK");
            }
            break;

        case StrFile:
            // Str to File: HexEStrFile
            // if an error occurred, will already be pushed on stack, if no errors: push OK onto stack
            if ( HexEStrFile() )
                pushstring(L"OK");
            break;

        case StrStr:
            // must be Str to Str: HexEStrStr
            // if an error occurred, will already be pushed on stack, if no errors: push string and status
            if ( HexEStrStr() )
            {
                pushstring(g_instr);
                pushstring(L"OK");
            }
            break;
    }
    return;
}

// function to load String (passed back on stack) from File
NSISFunc(LoadStr)
{
    // initialize DLL
    EXDLL_INIT();

    // get the Input ilename, if errors, messages already pushed just exit
    if ( !GetInFileName() )
        return;

    // correct # parms, clean "--End--" from stack
    if ( !clean_stack() )
    {
        pushstring(L"ERROR: --End-- missing");
        return;
    }

    // try to open the input file for reading
    HANDLE hInFile = open_file(g_in_filename, _INPUT_);

    // push error if could not open and return
    if (hInFile == INVALID_HANDLE_VALUE)
    {
        pushstring(L"ERROR: Open In_File Failed!");   // process error
        return;
    }

    // get Input File size
    unsigned int InFileSize = GetFileSize(hInFile, NULL);
    // if an error occurred bail
    if ( InFileSize == 0xFFFFFFFF)
    {
        pushstring(L"ERROR: GetFileSize Failed!"); // push error onto stack
        CloseHandle(hInFile);     // close the input file
        return;
    }

    // Verify size > 0 && < 1024
    if (InFileSize < 1 || InFileSize > 1023)
    {
        pushstring(L"ERROR: LoadStr: Invalid file size!");
        return;
    }

    wchar_t buffer[1024];
    FillMemory(buffer, 1024, '\0');

    unsigned long  bytesRead;
    // read file in one chunk
    if ( !ReadFile(hInFile, (wchar_t *) buffer, 1023, &bytesRead, NULL) )
    {
        // if an error,  push error, close the files, delete the incomplete out file and return false
        pushstring(L"ERROR: Reading File");
        CloseHandle(hInFile);
        return;
    }

    // Close the file.
    CloseHandle(hInFile);

    // push the string
    pushstring(buffer);
    // push status
    pushstring(L"OK");

    return;
}

// function to calc MD5Hash of contents of input file and return as hex encoded string
NSISFunc(MD5Hash)
{
    // initialize DLL
    EXDLL_INIT();

    wchar_t parm1[1024];
    // Get and validate the 1st parm
    if ( !get_parm(parm1) )
    {
        pushstring(L"ERROR: wrong # parms: MD5Hash function expected!");
        return;
    }

    // test for valid function
    if (  lstrlen(parm1) != 2 ||
         (lstrcmp(parm1, L"FF") != 0 && lstrcmp(parm1, L"FS") != 0 &&
          lstrcmp(parm1, L"SF") != 0 && lstrcmp(parm1, L"SS") != 0
         )
        )
    {
        pushstring(L"ERROR: invalid parm: MD5Hash function expected!");
        return;
    }

    // if valid "function" determine data source and process parm
    if ( parm1[0] == 'F')
    {
        // get the Input ilename, if errors, messages already pushed just exit
        if ( !GetInFileName() )
            return;
    }
    else
    {
        // Get the Input String, if errors messages already pushed, just exit
        if ( !GetInString() )
            return;
    }

    // determine data sink and process parm
    if ( parm1[1] == 'F')
    {
        // Get the Output filename, if errors messages already pushed, just exit
        if ( !GetOutFileName() )
            return;
    }
    // no parm when sink (output) is a string (will just get pushed to stack)

    // correct # parms, clean "--End--" from stack
    if ( !clean_stack() )
    {
        pushstring(L"ERROR: --End-- missing");
        return;
    }

    // var for wchar_t hex encoded MD5 digest (2 * 16) + 1 for NUL
    unsigned char MD5Digest[33];

    // determine source hash routine to call:
    if ( parm1[0] == 'F')
    {
        // hashing file : if errors, messages already pushed just return
        if ( !HashFile(MD5Digest) )
            return;
    }
    else
    {
        // hashing string: if errors, messages already pushed just return
        if ( !HashStr(MD5Digest) )
            return;
    }

    // determine sink routine to call:
    if ( parm1[1] == 'F')
    {
        // output hex encoded to file: if errors, messages already pushed just return
        if ( !WriteMD5Hash(MD5Digest) )
            return;
    }
    else
    {
        // sink is just the stack
        pushstring( (wchar_t *) MD5Digest);
    }

    pushstring(L"OK");
    return;

}

bool WINAPI DllMain(HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
    return true;
}
