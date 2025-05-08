import sys

def remove_encryption_flag(zip_file):
    with open(zip_file, "rb") as f:
        data = bytearray(f.read())

    # ZIP file signature
    LOCAL_FILE_HEADER_SIG = b'\x50\x4B\x03\x04'
    CENTRAL_DIR_HEADER_SIG = b'\x50\x4B\x01\x02'

    modified = False

    # modify file headers
    index = 0
    while (index := data.find(LOCAL_FILE_HEADER_SIG, index)) != -1:
        flag_index = index + 6       # offset to the general purpose bit flag
        if data[flag_index] & 0x01:  # check if encryption bit is set
            data[flag_index] &= 0xFE # unset encryption bit (bit 0)
            modified = True
        index += 30 # move to next header

    # modify the central directory headers
    index = 0
    while (index := data.find(CENTRAL_DIR_HEADER_SIG, index)) != -1:
        flag_index = index + 8       # offset to the general purpose bit flag
        if data[flag_index] & 0x01:  # check if encryption bit is set
            data[flag_index] &= 0xFE # unset encryption bit (bit 0)
            modified = True
        index += 46 # move to next header

    if modified:
        new_file = zip_file.replace(".zip", "_noenc.zip")
        with open(new_file, "wb") as f:
            f.write(data)
        print(f"[+] Encrypted flag removed. New file saved as: {new_file}")
    else:
        print("[-] No encryption flag found or already removed.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <encrypted.zip>")
        sys.exit(1)
    
    remove_encryption_flag(sys.argv[1])
