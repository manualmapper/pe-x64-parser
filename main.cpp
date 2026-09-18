// language: C++, file: main.cpp
// *reads a PE file and prints headers, sections, imports, exports*
// haven't tested this yet, wrote it on my phone
// made for fun
// if something's broken dm me or open an issue
// should work on x64, uses only winapi

#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <vector>

// using CreateFile/ReadFile instead of fstream because the Windows headers
// are already pulled in and mixing the two feels stupid

static std::vector<BYTE> read_file(const char* path) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart == 0) {
        CloseHandle(h);
        return {};
    }

    std::vector<BYTE> buf((size_t)size.QuadPart);
    DWORD got = 0;
    BOOL ok = ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr);
    CloseHandle(h);

    if (!ok || got != buf.size()) return {};
    return buf;
}

// rva != file offset. every rva needs to be resolved through the section
// table, otherwise you're reading garbage. this trips people up constantly.
static DWORD rva_to_offset(const std::vector<BYTE>& buf, DWORD rva) {
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) return 0;
    auto dos = (const IMAGE_DOS_HEADER*)buf.data();
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > buf.size())
        return 0;

    auto nt = (const IMAGE_NT_HEADERS64*)(buf.data() + dos->e_lfanew);

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD start = sec->VirtualAddress;
        DWORD end   = start + sec->Misc.VirtualSize;
        if (rva >= start && rva < end) {
            return rva - start + sec->PointerToRawData;
        }
    }
    return 0;
}

static const char* machine_name(WORD m) {
    switch (m) {
        case IMAGE_FILE_MACHINE_I386:  return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x64";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        default: return "unknown";
    }
}

static void print_sections(const std::vector<BYTE>& buf, const IMAGE_NT_HEADERS64* nt) {
    printf("\nSections (%u)\n", nt->FileHeader.NumberOfSections);

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        char name[9]{};
        memcpy(name, sec->Name, 8);

        // lowercase r/w/x string because that's how every other tool prints it
        char flags[4] = "---";
        if (sec->Characteristics & IMAGE_SCN_MEM_READ)    flags[0] = 'r';
        if (sec->Characteristics & IMAGE_SCN_MEM_WRITE)   flags[1] = 'w';
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) flags[2] = 'x';

        printf("  %-8s va=0x%06X size=0x%06X raw=0x%06X %s\n",
               name, sec->VirtualAddress, sec->Misc.VirtualSize,
               sec->PointerToRawData, flags);
    }
}

static void print_imports(const std::vector<BYTE>& buf, const IMAGE_NT_HEADERS64* nt) {
    DWORD imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!imp_rva) {
        printf("\nImports: none\n");
        return;
    }

    DWORD off = rva_to_offset(buf, imp_rva);
    if (!off) {
        printf("\nImports: failed to resolve rva\n");
        return;
    }

    printf("\nImports\n");
    auto desc = (const IMAGE_IMPORT_DESCRIPTOR*)(buf.data() + off);

    // descriptors are terminated by an all-zero entry
    while (desc->Name) {
        DWORD name_off = rva_to_offset(buf, desc->Name);
        if (!name_off) { desc++; continue; }
        const char* dll = (const char*)(buf.data() + name_off);
        printf("  %s\n", dll);

        // OriginalFirstThunk is the ILT (names). FirstThunk is the IAT (addresses).
        // some binaries have OriginalFirstThunk zeroed out and only FirstThunk - handle both.
        DWORD thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        DWORD thunk_off = rva_to_offset(buf, thunk_rva);
        if (!thunk_off) { desc++; continue; }

        auto thunk = (const IMAGE_THUNK_DATA64*)(buf.data() + thunk_off);
        int count = 0;
        while (thunk->u1.AddressOfData && count < 8) {
            // ordinal import has the high bit set, no name string to read
            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                DWORD hint_off = rva_to_offset(buf, (DWORD)thunk->u1.AddressOfData);
                if (hint_off) {
                    auto hint = (const IMAGE_IMPORT_BY_NAME*)(buf.data() + hint_off);
                    printf("    %s\n", hint->Name);
                }
            }
            thunk++;
            count++;
        }
        if (count == 8) printf("    ...\n");

        desc++;
    }
}

static void print_exports(const std::vector<BYTE>& buf, const IMAGE_NT_HEADERS64* nt) {
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) {
        printf("\nExports: none\n");
        return;
    }

    DWORD off = rva_to_offset(buf, exp_rva);
    if (!off) { printf("\nExports: bad rva\n"); return; }

    auto exp = (const IMAGE_EXPORT_DIRECTORY*)(buf.data() + off);
    printf("\nExports (%u)\n", exp->NumberOfNames);

    DWORD names_off = rva_to_offset(buf, exp->AddressOfNames);
    if (!names_off) { printf("  <bad names rva>\n"); return; }

    auto names = (const DWORD*)(buf.data() + names_off);
    for (DWORD i = 0; i < exp->NumberOfNames && i < 16; i++) {
        DWORD n_off = rva_to_offset(buf, names[i]);
        if (!n_off) continue;
        const char* n = (const char*)(buf.data() + n_off);
        printf("  %s\n", n);
    }
    if (exp->NumberOfNames > 16) printf("  ...\n");
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("usage: %s <path-to-exe-or-dll>\n", argv[0]);
        return 1;
    }

    auto buf = read_file(argv[1]);
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) {
        printf("failed to read file (or too small)\n");
        return 1;
    }

    auto dos = (const IMAGE_DOS_HEADER*)buf.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("not a PE file (missing MZ)\n");
        return 1;
    }

    // apparently some exes have e_lfanew pointing past the file. guard against it.
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > buf.size()) {
        printf("bad e_lfanew\n");
        return 1;
    }

    auto nt = (const IMAGE_NT_HEADERS64*)(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("not a PE file (missing PE signature)\n");
        return 1;
    }

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        // 32-bit file. could handle but not worth it for this
        printf("32-bit PE not supported, needs x64\n");
        return 1;
    }

    printf("File: %s\n", argv[1]);
    printf("\nNT Headers\n");
    printf("  machine:  %s\n", machine_name(nt->FileHeader.Machine));
    printf("  sections: %u\n", nt->FileHeader.NumberOfSections);
    printf("  timestamp: 0x%08X\n", nt->FileHeader.TimeDateStamp);

    printf("\nOptional Header\n");
    printf("  entrypoint: 0x%08X\n", nt->OptionalHeader.AddressOfEntryPoint);
    printf("  imagebase:  0x%016llX\n", nt->OptionalHeader.ImageBase);
    printf("  sizeofimage: 0x%08X\n", nt->OptionalHeader.SizeOfImage);
    printf("  subsystem:  %u\n", nt->OptionalHeader.Subsystem);

    print_sections(buf, nt);
    print_imports(buf, nt);
    print_exports(buf, nt);

    // TODO: relocations, TLS, resources. keep this small for now.
    return 0;
}
