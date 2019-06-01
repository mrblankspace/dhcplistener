from kamene.layers.dhcp import dhcp_request, DHCP
from kamene.all import *
from kamene.modules.nmap import nmap_fp


def  getMac(packet):
     src_mac = packet.getlayer(Ether).fields['src']
    #src_mac = packet.getlayer(DHCP).fields['options']
     return src_mac
#
# def getUserName(packet):
#     user_name = src_mac = packet.getlayer(DHCP).fields['options']

# def getDHCPOption(packet):
#     options = packet.getlayer(DHCP).fields['options']
#     print(packet[DHCP].options)
#     print(options)



def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                if key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass

#option_list
def get_option_list(dhcp_options):
    option_list = ""
    for i in dhcp_options:
        option_list += i[0]

    return option_list


#回调函数
def pack_callback(packet):
    #操作系统探测
    nmap_fp("", oport=443, cport=1)

    #dhcp request
    if DHCP in packet and packet[DHCP].options[0][1] == 3:
        print('---')
        print('New DHCP REQUEST')
        hostname = get_option(packet[DHCP].options, 'hostname')
        #mac = get_option(packet[DHCP].options, 'client_id')
        mac = getMac(packet)
        param_req_list = get_option(packet[DHCP].options,'param_req_list')
        option_list = get_option_list(packet[DHCP].options)
        print(f"Host {hostname}")
        print(f"mac:{mac}")
        print(f"param_req_list:{param_req_list}")

        print(packet[DHCP].options)
        print(packet[DHCP])
    #getMac(packet)



sniff(filter="udp and (port 67 or 68)",prn=pack_callback)