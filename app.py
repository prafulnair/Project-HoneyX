from socket import *
import sys
import struct
import re
from datetime import datetime
import csv

def receivedata(s):
    data = ''
    np = 0
    counter = 0
    while np <= 5:
        try:
            data = s.recvfrom(65565)
        except timeout:
            data = ''
        except:
            print("Some Error Occurred")
            sys.exc_info()
        print("Total Packed Data")
        print(data)
        print("Initial Part of the data: packed")
        data2 = data[0]
        print("Unpacked Total data")
        unpackedData = struct.unpack('!BBHHHBBH4s4s', data2[:20])
        #        print(unpackedData)

        # extracting Version Infromation from the Version-IHL
        versionIHL = unpackedData[0]
        version = versionIHL >> 4
        IHL = versionIHL & 0xF

        data3 = unpackedData[1]
        # setting the values for TOS
        precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash Override", 5: "CRITIC/ ECIP",
                      6: "Internetwork control", 7: "Network control"}
        delay = {0: "Normal delay", 1: "Low Delay"}
        throughput = {0: "Normal Throughput", 1: "High throughput"}
        reliability = {0: "Normal Reliability", 1: "High Reliability"}
        cost = {0: "normal cost", 1: "Minimize Cost"}

        # extract TOS values now
        D = data3 & 0x10
        D >>= 4
        T = data3 & 0x8
        T >>= 3
        R = data3 & 0x4
        R >>= 2
        C = data3 & 0x2
        C >>= 1

        space = '\n\t\t\t'
        TOS = precedence[data3 >> 5] + space + delay[D] + space + throughput[T] + space + reliability[R] + space + cost[
            C]

        totalLength = unpackedData[2]
        ID = unpackedData[3]
        # initalising value for FLAG bits
        data4 = unpackedData[4]
        # dictionarry for flag bit values
        Reserved = {0: "Reserved bit"}
        DontFrag = {0: "Fragment if necessary", 1: "Donot Fragment"}
        MoreFrag = {0: "last Fragment", 1: " More Fragment"}

        # Extracting Flag bit data
        # get 1st bit
        R = data4 & 0x8000
        R >>= 15
        # get the 2nd bit
        DF = data4 & 0x4000
        DF >>= 14
        # get the 3rd bit
        MF = data4 & 0x2000
        MF >>= 13

        flags = Reserved[R] + space + DontFrag[DF] + space + MoreFrag[MF]

        fragmentOffset = unpackedData[4] & 0x1FFF

        TTL = unpackedData[5]

        # extracting protocol values ..
        # opening the protocol dB values file ' Protocol'

        protocolNr = unpackedData[6]
        protocolFile = open('Protocol.txt', 'r')
        protocolData = protocolFile.read()
        protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
        if protocol:
            protocol = protocol[0]
            protocol = protocol.replace("\n", "")
            protocol = protocol.replace(str(protocolNr), "")
            protocol = protocol.lstrip()
            print(protocol)
        else:
            protocol = 'Unable to Detect Protocol'

        checksum = unpackedData[7]
        sourceAddress = inet_ntoa(unpackedData[8])
        destinationAddress = inet_ntoa(unpackedData[9])

        #calculate date and time
        now = datetime.now()


        print('An IP packet Captured')
        print("Packet Number\t\t\t"+str(np))
        #print(np)
        print("date & Time of capture :\t\t\t"+str(now))
        #print(now)
        print('Raw data'+data[0])
        print('Version : \t\t\t'+str(version)+'\t\t\t Internet header length: '+str(IHL*4)+' bytes')
        print('Type of Service: \t\t\t'+str(TOS))
        print('Total Length:\t\t\t'+str(totalLength))
        print('Identification Bit:\t\t\t'+str(hex(ID)) + '(' +str(ID) +')')
        print('Flags:\t\t\t'+str(flags))
        print('Fragment Offset:\t\t\t'+ str(fragmentOffset))
        print('Time to Live: \t\t\t'+str(TTL)+'\t\t\t Protocol: \t\t\t'+protocol)
        print('Checksum:\t\t\t'+str(checksum))
        print('Source Address: \t\t\t'+sourceAddress)
        print('Destination Address:\t\t\t'+destinationAddress)
        print('Payload:\n'+data2[20:])

        #writing the extracted information into CSV file


        with open('nwslog.csv','ab') as file:
            writer = csv.writer(file)
            if counter == 0:
                writer.writerow(['Packet No', 'Date&Time', 'Version', 'IHL', 'TOS', 'Length', 'ID', 'Flags', 'Fragment Offset', 'TTL','Protocol', 'checksum', 'source Address', 'Destination Address', 'Payload'])
            else:
                writer.writerow([np, now, version, IHL * 4, TOS, totalLength, ID, flags, fragmentOffset, TTL, protocol, checksum, sourceAddress, destinationAddress, data2[20:]])
        counter = counter + 1
        np = np + 1


# obtain network interface
HOST = gethostbyname(gethostname())

# create socket and bind it to the network interface
s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
s.bind((HOST, 0))

# TO include all the IP headers
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
s.ioctl(SIO_RCVALL, RCVALL_ON)

# obtain packet data from mentioned above function
receivedata(s)
