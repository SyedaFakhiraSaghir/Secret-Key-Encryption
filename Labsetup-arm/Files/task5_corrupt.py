import sys

def corrupt_file(filename, byte_pos):
    with open(filename, 'rb') as f:
        data = bytearray(f.read())
    # byte_pos is 1-based, so index = byte_pos - 1
    index = byte_pos - 1
    if index < len(data):
        # flip the least significant bit
        data[index] ^= 0x01
    else:
        print("Byte position out of range")
        return
    with open(filename, 'wb') as f:
        f.write(data)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python corrupt.py <filename> <byte_position>")
        sys.exit(1)
    filename = sys.argv[1]
    byte_pos = int(sys.argv[2])
    corrupt_file(filename, byte_pos)