from log import log, INFO, WARN, ERROR, CRITICAL, DEBUG
import socket
import os

PORT = int(os.environ.get("PORT", 53))
IP = os.environ.get("IP", "127.0.0.1")

running = True


def buildResponse(data):
    def getFlags(flags):
        byte1 = bytes(flags[0:1])
        byte2 = bytes(flags[1:2])

        # Byte 1

        QR = '1'

        OPCODE = ''.join([str(ord(byte1)&(1<<bit)) for bit in range(1, 5)])

        AA = '1'
        TC = '0'    # Unsupported Feature ( xxx )
        RD = '0'    # Unsupported Feature ( Recursion xxx )

        # Byte 2
        RA = '0'    # Unsupported Feature ( Recursion Available )
        Z = '000'   # Unused Bits ( "Reserved for future use" according to specification )
        RC = '0000'

        # Combining the bits, forming them into bytes, then returning them
        return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big') + \
                int(RA+Z+RC, 2).to_bytes(1, byteorder='big')

    def getDomainFromBytes(domain):
        def decodeString(b, offset):
            length = int(b[:offset])
            substring = "".join([b[i].to_bytes(1, byteorder='big').decode('utf-8')
                                for i in range(offset, length+offset)])

        print(decodeString(domain, 1))


        # byteIndex = 0
        # nextByte = domain[byteIndex]
        # while (nextByte != b'\x00'):
        #     domainStr +=
        #
        #     byteIndex += 1
        #     nextByte = domain[byteIndex]
        print(domain)

    res = b''

    try:
        # Get the transaction ID
        tid = data[:2]
        tid_str = "".join([hex(byte)[2:].upper() for byte in tid])
        log("Transaction ID: 0x{}".format(tid_str), DEBUG)

        # Get the flags
        flags = getFlags(data[2:4])
        log("Flags: {}".format(flags), DEBUG)

        # Question Count
        QDCOUNT = b'\x00\x01'

        # Answer Count
        getDomainFromBytes(data[12:])

        res = tid + flags
    except Exception as e:
        raise e

    log("Response: {}".format(res), DEBUG)
    return res


def main():
    log("IP: {}".format(IP), DEBUG)
    log("PORT: {}".format(PORT), DEBUG)

    # Creating & binding the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))

    log("Listening for DNS Requests")
    while running:
        # Getting the data & address from the request
        data, addr = sock.recvfrom(512)
        log("Recieved connection from {}:{}".format(addr[0], addr[1]))

        # try:
        response = buildResponse(data)
        sock.sendto(response, addr)
        # except Exception as e:
            # log("Failed to build a response for the client @ {}:{}. Exception: {}"
                # .format(addr[0], addr[1], e), ERROR)
            # continue
    log("No longer listening for DNS Requests")


if __name__ == "__main__":
    print()
    print("    |    ____        ____  _   _ ____     |    ")
    print("    |   |  _ \ _   _|  _ \| \ | / ___|    |    ")
    print("    |   | |_) | | | | | | |  \| \___ \    |    ")
    print("    |   |  __/| |_| | |_| | |\  |___) |   |    ")
    print("    |   |_|    \__, |____/|_| \_|____/    |    ")
    print("    |          |___/                      |    ")
    print("    |                    Version 1.0      |    ")
    print()

    main()
