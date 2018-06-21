
# ## Project Triton
### Pyshark Based Packet Parsing
### Python Coded Traffic Analysis
### Author : Harris (harrisjnu@gmail.com)

# Module Imports
import pyshark
from layer_data import ethernet
from layer_data import ip_layer
from layer_data import layer



# Logging Import and Declarations
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Program Root Entry

def programfeeds():
    print(" Welcome to Packet Analysis Section ")
    print("Select your option")
    print(" 1  > Live Packet Capture")
    print(" 2  > Analyse packets")

    operation = input("Enter Option: ")
    if operation == '1':
        print(" Packet capturing selected: ")
        packet_count = int(input("Enter number of packets to be analysed (Max 50000 Packets)"))
        interface = input("Interface: ")
        logger.info("Packet capture requested on : " + str(interface))
        if packet_count > 50000:
            print("Packet count exceeds maximum limit. Try Again")
            programfeeds()
        else:
            pass
            logger.info("Invalid option selected")
        live_capture(interface)

    elif operation == '2':
        print("Retrospective analysis of packet selected: ")
        file_path = input("Enter absolute path of .pcap file:  ")
        logger.info("Path provided: " + str(file_path))
        packet_analysis(path=file_path)

    else:
        print("Please select valid option: ")
        programfeeds()




def live_capture(interface):
    logging.debug("Entering Live Capturing Mode")
    print(interface)

def packet_analysis(path):
    logging.debug("Reading packets from PCAP File:  " + str(path))
    pcap = pyshark.FileCapture(str(path))

    ## Type Classification
    packet_type_list = {}

    ###Layer 2 Informations######
    s_mac_list = {}
    d_mac_list = {}
    #L2 Ethernet Conversation Data
    etherflow_list = {}
    ###Layer 3 Information######
    s_ip_list = {}
    d_ip_list = {}
    #L3 IP Conversation
    ipflow_list = {}


    ### Layer 3 Informations



    for idx, packet in enumerate(pcap):
        try:
            ## Layer Classification
            packet_type = layer.classification(packet)

            #Layer 2 Analysis Block
            src_mac = ethernet.src_mac(packet)
            dst_mac = ethernet.dst_mac(packet)
            ether_flow = (str(src_mac) + ">" + str(dst_mac))
            logging.debug("ETHER FLOW " + str(ether_flow))

            #Layer 3 Analysis Block
            src_ip = ip_layer.src_ip(packet)
            dst_ip = ip_layer.dst_ip(packet)
            ip_flow = (str(src_ip) + ">" + str(dst_ip))
            logging.debug("IP FLOW " + str(ip_flow))
        except:
            pass


        try:
            if packet_type in packet_type_list:
                packet_type_list[packet_type] += 1
                logging.debug("Packet type incremented for " + str(packet_type))
            else:
                packet_type_list[packet_type] = 1
                logging.debug("New packet type added: " + str(packet_type))
        except:
            pass

        try:
            if src_mac in s_mac_list:
                s_mac_list[src_mac] += 1
                logging.debug("Source MAC exist on the list " + str(src_mac) + "   Packet ID " + str(idx))
            else:
                s_mac_list[src_mac] = 1
                logging.debug("Source MAC added on the list " + str(src_mac) + " Packet ID " + str(idx))
        except:
            pass

        try:
            if dst_mac in d_mac_list:
                d_mac_list[dst_mac] += 1
                logging.debug("Destination MAC exist on the list " + str(dst_mac) + "   Packet ID " + str(idx))
            else:
                d_mac_list[dst_mac] = 1
                logging.debug("Destination MAC added on the list " + str(dst_mac) + " Packet ID " + str(idx))
        except:
            pass


        try:
            if ether_flow in etherflow_list:
                etherflow_list[ether_flow] += 1
                logging.debug("Eher flow recorded for " + str(src_mac) + ">" + str(dst_mac))
            else:
                etherflow_list[ether_flow] = 1
                logging.debug("New ether flow recorded" + str(src_mac) + ">" + str(dst_mac))
        except:
            pass

        try:
            if src_ip in s_ip_list:
                s_ip_list[src_ip] += 1
                logging.debug("Source IP exists on the list" + str(src_ip) + "Packet ID " + str(idx))
            else:
                s_ip_list[src_ip] = 1
                logging.debug("New Source IP added to the list" + str(src_ip) + "Packet ID " + str(idx))
        except:
            pass

        try:
            if dst_ip in d_ip_list:
                d_ip_list[dst_ip] += 1
                logging.debug("Destination IP exists on the list" + str(dst_ip) + "Packet ID " + str(idx))
            else:
                d_ip_list[src_ip] = 1
                logging.debug("New destination IP exists on the list" + str(dst_ip) + "Packet ID " + str(idx))
        except:
            pass

        try:
            if ip_flow in ipflow_list:
                ipflow_list[ip_flow] += 1
                logging.debug("IP flow recorded for " + str(src_ip) + ">" + str(dst_ip))
            else:
                ipflow_list[ip_flow] = 1
                logging.debug("New IP flow recorded " + str(src_ip) + ">" + str(dst_ip))
        except:
            pass




    #####LAYER INFORMATIONS########
    print("PACKET CLASSIFICATIONS: " + str(packet_type_list))
    #####LAYER 2 INFORMATIONS######
    print("Layer 2 Source Mac Share: " + str(s_mac_list))
    print("Layer 2 Destination Mac Share: " + str(d_mac_list))
    print("Layer 2 Top Conversations Share: " + str(etherflow_list))
    #####LAYER 3 INFORMATIONS######
    print("Layer 3 Source IP Share: " + str(s_ip_list))
    print("Layer 3 Destination IP Share: " + str(d_ip_list))
    print("Layer 3 Top Conversations Share: " + str(ipflow_list))






programfeeds()