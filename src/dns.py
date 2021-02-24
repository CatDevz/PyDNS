from log import *
import socket
import json
import glob
import os
import sys

PORT = int(os.environ.get("PORT", 53))
IP = os.environ.get("IP", "127.0.0.1")

running = True
zones = {}


def loadZones():
    """ Loads all zone files into JSON format """
    jsonzone = {}
    zonefiles = glob.glob("zones/*.zone")
    for zonefile in zonefiles:
        with open(zonefile) as file:
            data = json.load(file)
            jsonzone[data["$origin"]] = data
    return jsonzone


def getRecords(domainParts, rawQuestionType):
    QUESTION_TYPES = {
        b'\x00\x01': 'a',
        b'\x00\x02': 'ns',
        b'\x00\x03': 'md',
        b'\x00\x04': 'mf',
        b'\x00\x05': 'cname',
        b'\x00\x06': 'soa',
        b'\x00\x07': 'mb',
        b'\x00\x08': 'mg',
        b'\x00\x09': 'mr',
        b'\x00\x0A': 'null',
        b'\x00\x0B': 'wks',
        b'\x00\x0C': 'ptr',
        b'\x00\x0D': 'hinfo',
        b'\x00\x0E': 'minfo',
        b'\x00\x0F': 'mx',
        b'\x00\x10': 'txt',
    }

    # Getting the question type in a readable form
    questionType = QUESTION_TYPES[rawQuestionType]

    # Getting the zone
    zone_name = "{}.".format('.'.join(domainParts))
    if not zone_name in zones:
        return zone_name, None, questionType
    zone = zones[zone_name]

    # Getting the records for that question type and zone
    records = zone[questionType]

    return (zone_name, records, questionType)


def getDomainQuestionFromBytes(data):
    """ Decodes a domain & question from bytes """
    domainParts = []

    pointer = 0
    nextByte = data[pointer]
    while nextByte != b'\x00':
        length = int(data[pointer])
        pointer += 1

        # Getting the string itself
        domainParts.append("".join([data[i:i+1].decode('utf-8')
                            for i in range(pointer, length + pointer)]))

        # Adding stuff to the offset
        pointer += length
        nextByte = data[pointer:pointer+1]#.to_bytes(1, byteorder="big")
    questionType = data[pointer+1:pointer+3]
    return (domainParts, questionType)


def getFlags(flags):
    """ Returns flags to use in a DNS Response """
    byte1 = bytes(flags[0:1])
    byte2 = bytes(flags[1:2])

    # Byte 1  ( 1XXXX100 )
    QR = '1'
    OPCODE = ''.join([str(ord(byte1)&(1<<bit)) for bit in range(1, 5)])
    AA = '1'
    TC = '0'    # Unsupported Feature ( xxx )
    RD = '0'    # Unsupported Feature ( Recursion xxx )

    # Byte 2  ( 00000000 )
    RA = '0'    # Unsupported Feature ( Recursion Available )
    Z = '000'   # Unused Bits ( "Reserved for future use" according to specification )
    RC = '0000'

    # Combining the bits, forming them into bytes, then returning them
    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big') + \
            int(RA+Z+RC, 2).to_bytes(1, byteorder='big')


def buildResponse(data):
    res = b''

    try:
        # Transaction ID
        TID = data[:2]

        # Flags
        FLAGS = getFlags(data[2:4])

        # Question Count
        QDCOUNT = b'\x00\x01'

        # Answer Count
        domainParts, rawQuestionType = getDomainQuestionFromBytes(data[12:])
        zone_name, records, questionType = getRecords(domainParts, rawQuestionType)
        ANCOUNT = len(records).to_bytes(2, byteorder='big')

        # Nameserver Count
        NSCOUNT = b'\x00\x00'

        # Additional Count
        ARCOUNT = b'\x00\x00'

        # Logging out some stuff
        log("Zone Requested: {}".format(zone_name), DEBUG)
        log("Question Type: {}".format(questionType), DEBUG)

        # Creating the final DNS Header & Body
        dnsheader = TID+FLAGS+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT
        dnsbody = b''  # TODO: Finish this tommorow :)

        res = dnsheader + dnsbody
    except Exception as e:
        raise e

    log("Response Generated: {}".format(res), DEBUG)
    return res


def main():
    # Getting all the zones from zones folder
    global zones
    zones = loadZones()

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
