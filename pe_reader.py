from enum import IntEnum

sections_rva = []
sections_foa = []
sections_names = []


class PESize(IntEnum):
    BYTE = 1
    WORD = 2
    DWORD = 4
    QWORD = 8


def get_bytes(b: bytes, i: int, j: int) -> bytes:
    if i < 0 or j >= len(b):
        raise IndexError
    return b[i:j]


def get_str2(b: bytes, i: int) -> str:
    j = i
    ret = ""
    while True:
        if get_int(b, j, j + 1) == 0:
            break
        ret += chr(b[j])
        j += 1
    return ret


def get_str(b: bytes, i: int, j: int, code='utf-8') -> str:
    if i < 0 or j >= len(b):
        raise IndexError
    return b[i:j].decode(code)


def get_int(b: bytes, i: int, j: int) -> int:
    if i < 0 or j >= len(b):
        raise IndexError
    return int.from_bytes(b[i:j], byteorder='little')


def rva_find_foa(rva: int) -> int:
    if rva < sections_rva[0]:
        print("ERROR: You should use add ImageBase to origin rva")
        return 0
    for i in range(0, len(sections_rva)):
        if i == len(sections_rva) - 1 and rva >= sections_rva[-1]:
            return sections_foa[-1] + (rva - sections_rva[-1])
        if sections_rva[i] <= rva < sections_rva[i + 1]:
            return sections_foa[i] + (rva - sections_rva[i])


file_path = input("Select PE file: ")
with open(file_path, 'rb') as file:
    print("reading ....")
    buf = file.read()
    print("file size: " + str(len(buf)) + "bytes.")

# check pe file
# file_pe_mz = buf[0x0:0x2].decode('utf-8')
file_pe_mz = get_str(buf, 0, 0x2)
# NT header pointer
file_pe_nthp = 0
# PE magic
file_pe_signature = ""
if 'MZ' == file_pe_mz:
    print(file_pe_mz + " ===> found")
else:
    print("cannot find mz")
    exit(-1)
# file_pe_nthp = int.from_bytes(buf[0x3C:0x40], byteorder='little')
file_pe_nthp = get_int(buf, 0x3C, 0x40)
# print(file_pe_nthp)
# file_pe_magic = buf[file_pe_nthp:file_pe_nthp + 2].decode('utf-8')
file_pe_signature = get_str(buf, file_pe_nthp, file_pe_nthp + 2)
# print(file_pe_magic)
if "PE" == file_pe_signature:
    print(file_pe_signature + " Magic ===> found")
else:
    print("cannot find pe magic")
    exit(-1)
print("Read Successfully")
##################################################
nth_offset_list = [0]
nth_size_list = [
    PESize.DWORD,  # 'PE' 0
    #####################################
    PESize.WORD,  # Machine 1
    PESize.WORD,  # NumberOfSections 2
    PESize.DWORD,  # TimeDateStamp 3
    PESize.DWORD,  # PinterToSymbolTable 4
    PESize.DWORD,  # NumberOfSymbols 5
    PESize.WORD,  # SizeOfOptionalHeader 6
    PESize.WORD,  # Characteristics 7
    ##############################
    PESize.WORD,  # Magic 8
    PESize.BYTE,  # MajorLinker 9
    PESize.BYTE,  # MinorLinker 10
    PESize.DWORD,  # SizeOfCode 11
    PESize.DWORD,  # SizeOfInitData 12
    PESize.DWORD,  # SizeOfUnintData 13
    PESize.DWORD,  # OEP 14
    PESize.DWORD,  # BaseOfCode 15
    PESize.DWORD,  # BaseOfData 16
    PESize.DWORD,  # ImageBase 17
    PESize.DWORD,  # SectionAlignment 18
    PESize.DWORD,  # FileAlignment 19
    PESize.WORD,
    PESize.WORD,
    PESize.WORD,
    PESize.WORD,
    PESize.WORD,
    PESize.WORD,
    PESize.DWORD,  # Win32ver 26
    PESize.DWORD,  # SizeOfImage 27
    PESize.DWORD,  # SizeOfHeader 28
    PESize.DWORD,  # CheckSum 29
    PESize.WORD,
    PESize.WORD,
    PESize.DWORD,  # SizeOfStackReserve 32
    PESize.DWORD,
    PESize.DWORD,
    PESize.DWORD,
    PESize.DWORD,
    PESize.DWORD  # NumberOfRvaAndSizes 37
    # DataDirectory
    ##############################
]
data_dir_offset = 38
for i in range(1, len(nth_size_list)):
    nth_offset_list.append(int(nth_offset_list[i - 1]) + int(nth_size_list[i - 1]))
nth_buf = buf[file_pe_nthp:]
# for i in range(0, len(offset_list)):
#     print(offset_list[i])
data_dir_num = get_int(nth_buf, nth_offset_list[37], nth_offset_list[37] + nth_size_list[37])
# print(data_dir_num)
for i in range(0, data_dir_num):
    nth_size_list.append(PESize.QWORD)
    nth_offset_list.append(int(nth_size_list[-2]) + nth_offset_list[-1])
# for i in range(len(offset_list)):
#     print(str(size_list[i]) + " " + str(offset_list[i]))
magic = get_int(nth_buf, nth_offset_list[8], nth_offset_list[8] + nth_size_list[8])
print("Magic: " + hex(magic))
if magic == 0x20b:
    print("64 bits PE file (Unsupported)")
elif magic == 0x10b:
    print("32 bits PE file")
print("SectionAlignment: " + hex(get_int(nth_buf, nth_offset_list[18], nth_offset_list[18] + nth_size_list[18])))
print("FileAlignment:    " + hex(get_int(nth_buf, nth_offset_list[19], nth_offset_list[19] + nth_size_list[19])))
print("SizeOfImage:      " + hex(get_int(nth_buf, nth_offset_list[27], nth_offset_list[27] + nth_size_list[27])))
print("SizeOfHeader:     " + hex(get_int(nth_buf, nth_offset_list[28], nth_offset_list[28] + nth_size_list[28])))
image_base = get_int(nth_buf, nth_offset_list[17], nth_offset_list[17] + nth_size_list[17])
print("ImageBase:        " + hex(image_base))
import_dir_rva = get_int(nth_buf, nth_offset_list[data_dir_offset + 1],
                         nth_offset_list[data_dir_offset + 1] + int(PESize.DWORD))
import_dir_size = get_int(nth_buf, nth_offset_list[data_dir_offset + 1] + int(PESize.DWORD),
                          nth_offset_list[data_dir_offset + 1] + int(PESize.DWORD) + int(PESize.DWORD))
print("Import Dir RVA: " + hex(import_dir_rva))
print("Import Dir Size: " + hex(import_dir_size))
section_table_offset = nth_offset_list[-1] + nth_size_list[-1]
section_table_addr = file_pe_nthp + section_table_offset
print("SectionAddr: " + hex(section_table_addr))
section_number_offset = nth_offset_list[2]
section_number = get_int(nth_buf, section_number_offset, section_number_offset + nth_size_list[2])
print("NumberOfSections: " + hex(section_number))
sections_rva.append(image_base)
sections_foa.append(0)
sections_names.append(".header")
for i in range(0, section_number):
    nth_size_list.append(int(PESize.BYTE) * 40)
    nth_offset_list.append(nth_size_list[-2] + nth_offset_list[-1])
    section_name = get_str(nth_buf, nth_offset_list[-1], nth_offset_list[-1] + int(PESize.BYTE) * 8)
    # print(section_name)
    rva = get_int(nth_buf, nth_offset_list[-1] + int(PESize.BYTE) * 12,
                  nth_offset_list[-1] + int(PESize.BYTE) * 16)
    size = get_int(nth_buf, nth_offset_list[-1] + int(PESize.BYTE) * 16,
                   nth_offset_list[-1] + int(PESize.BYTE) * 20)
    foa = get_int(nth_buf, nth_offset_list[-1] + int(PESize.BYTE) * 20,
                  nth_offset_list[-1] + int(PESize.BYTE) * 24)
    if not (size == 0 or foa == 0):
        sections_rva.append(rva + image_base)
        sections_names.append(section_name)
        sections_foa.append(foa)
    # print("\tSection RVA: " + hex(rva))
    # print("\tSection Size: " + hex(size))
    # print("\tSection FOA: " + hex(foa))
for i in range(0, len(sections_names)):
    print(sections_names[i])
    print("\tRVA: " + hex(sections_rva[i]))
    print("\tFOA: " + hex(sections_foa[i]))
import_dir_foa = rva_find_foa(import_dir_rva + image_base)
print("Import Dir FOA: " + hex(import_dir_foa))
print("Starting ImportDirReader...")
##################################################
import_table_buf = buf[import_dir_foa:]
it_size_list = [
    PESize.DWORD,  # OriginFirstThunk RVA
    PESize.DWORD,
    PESize.DWORD,
    PESize.DWORD,  # Name
    PESize.DWORD  # FirstThunk
]
it_offset_list = [0]
for i in range(1, len(it_size_list)):  # generate offset list ...
    it_offset_list.append(it_offset_list[i - 1] + int(it_size_list[i - 1]))
it_size = 0
it_read_pos = 0
iid_list = []
while True:
    if get_int(import_table_buf, it_read_pos, it_read_pos + 20) == 0:
        break
    tmp_it_buf = import_table_buf[it_read_pos:it_read_pos + 20]
    # print(hex(get_int(tmp_it_buf, it_offset_list[3], it_offset_list[3] + it_size_list[3])))
    name_rva = get_int(tmp_it_buf, it_offset_list[3], it_offset_list[3] + it_size_list[3])
    name_foa = rva_find_foa(name_rva + image_base)
    name = get_str2(buf, name_foa)
    print("Found a DLL: " + name)
    it_read_pos += 20
    it_size += 1
print("FOUND: " + str(it_size) + " '.DLL' files.")
