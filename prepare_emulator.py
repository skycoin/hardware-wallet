filename = "emulator.img"
total_size = (512 * 1024)

with open(filename, "wb") as out:
    out.truncate(total_size)
    a = 255
    byte = a.to_bytes(1, byteorder='big')
    for i in range(total_size):
        out.write(byte);
    out.close()
