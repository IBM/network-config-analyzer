#
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

class ProtocolNameResolver:
    """
    This class holds the names of the standard protocols and their numbers
    """
    _protocol_name_to_number_dict = {'HOPOPT': 0, 'ICMP': 1, 'IGMP': 2, 'GGP': 3, 'IPv4': 4, 'ST': 5, 'TCP': 6,
                                     'CBT': 7, 'EGP': 8, 'IGP': 9, 'BBNRCCMON': 10, 'NVPII': 11, 'PUP': 12,
                                     'ARGUSdeprecated': 13, 'EMCON': 14, 'XNET': 15, 'CHAOS': 16, 'UDP': 17,
                                     'MUX': 18, 'DCNMEAS': 19, 'HMP': 20, 'PRM': 21, 'XNSIDP': 22, 'TRUNK1': 23,
                                     'TRUNK2': 24, 'LEAF1': 25, 'LEAF2': 26, 'RDP': 27, 'IRTP': 28, 'ISOTP4': 29,
                                     'NETBLT': 30, 'MFENSP': 31, 'MERITINP': 32, 'DCCP': 33, '3PC': 34, 'IDPR': 35,
                                     'XTP': 36, 'DDP': 37, 'IDPRCMTP': 38, 'TP': 39, 'IL': 40, 'IPv6': 41, 'SDRP': 42,
                                     'IPv6Route': 43, 'IPv6Frag': 44, 'IDRP': 45, 'RSVP': 46, 'GRE': 47, 'DSR': 48,
                                     'BNA': 49, 'ESP': 50, 'AH': 51, 'INLSP': 52, 'SWIPEdeprecated': 53, 'NARP': 54,
                                     'MOBILE': 55, 'TLSP': 56, 'SKIP': 57, 'ICMPv6': 58, 'IPv6NoNxt': 59,
                                     'IPv6Opts': 60, 'CFTP': 62, 'SATEXPAK': 64, 'KRYPTOLAN': 65, 'RVD': 66, 'IPPC': 67,
                                     'SATMON': 69, 'VISA': 70, 'IPCV': 71, 'CPNX': 72, 'CPHB': 73, 'WSN': 74, 'PVP': 75,
                                     'BRSATMON': 76, 'SUNND': 77, 'WBMON': 78, 'WBEXPAK': 79, 'ISOIP': 80, 'VMTP': 81,
                                     'SECUREVMTP': 82, 'VINES': 83, 'TTP': 84, 'IPTM': 84, 'NSFNETIGP': 85, 'DGP': 86,
                                     'TCF': 87, 'EIGRP': 88, 'OSPFIGP': 89, 'SpriteRPC': 90, 'LARP': 91, 'MTP': 92,
                                     'AX25': 93, 'IPIP': 94, 'MICPdeprecated': 95, 'SCCSP': 96, 'ETHERIP': 97,
                                     'ENCAP': 98, 'GMTP': 100, 'IFMP': 101, 'PNNI': 102, 'PIM': 103, 'ARIS': 104,
                                     'SCPS': 105, 'QNX': 106, 'AN': 107, 'IPComp': 108, 'SNP': 109, 'CompaqPeer': 110,
                                     'IPXinIP': 111, 'VRRP': 112, 'PGM': 113, 'L2TP': 115, 'DDX': 116, 'IATP': 117,
                                     'STP': 118, 'SRP': 119, 'UTI': 120, 'SMP': 121, 'SMdeprecated': 122, 'PTP': 123,
                                     'ISISoverIPv4': 124, 'FIRE': 125, 'CRTP': 126, 'CRUDP': 127, 'SSCOPMCE': 128,
                                     'IPLT': 129, 'SPS': 130, 'PIPE': 131, 'SCTP': 132, 'FC': 133, 'RSVPE2EIGNORE': 134,
                                     'MobilityHeader': 135, 'UDPLite': 136, 'MPLSinIP': 137, 'manet': 138, 'HIP': 139,
                                     'Shim6': 140, 'WESP': 141, 'ROHC': 142, 'Ethernet': 143}
    _protocol_number_to_name_dict = {0: 'HOPOPT', 1: 'ICMP', 2: 'IGMP', 3: 'GGP', 4: 'IPv4', 5: 'ST', 6: 'TCP', 7: 'CBT',
                                     8: 'EGP', 9: 'IGP', 10: 'BBNRCCMON', 11: 'NVPII', 12: 'PUP', 13: 'ARGUSdeprecated',
                                     14: 'EMCON', 15: 'XNET', 16: 'CHAOS', 17: 'UDP', 18: 'MUX', 19: 'DCNMEAS',
                                     20: 'HMP', 21: 'PRM', 22: 'XNSIDP', 23: 'TRUNK1', 24: 'TRUNK2', 25: 'LEAF1',
                                     26: 'LEAF2', 27: 'RDP', 28: 'IRTP', 29: 'ISOTP4', 30: 'NETBLT', 31: 'MFENSP',
                                     32: 'MERITINP', 33: 'DCCP', 34: '3PC', 35: 'IDPR', 36: 'XTP', 37: 'DDP',
                                     38: 'IDPRCMTP', 39: 'TP', 40: 'IL', 41: 'IPv6', 42: 'SDRP', 43: 'IPv6Route',
                                     44: 'IPv6Frag', 45: 'IDRP', 46: 'RSVP', 47: 'GRE', 48: 'DSR', 49: 'BNA', 50: 'ESP',
                                     51: 'AH', 52: 'INLSP', 53: 'SWIPEdeprecated', 54: 'NARP', 55: 'MOBILE', 56: 'TLSP',
                                     57: 'SKIP', 58: 'ICMPv6', 59: 'IPv6NoNxt', 60: 'IPv6Opts', 62: 'CFTP',
                                     64: 'SATEXPAK', 65: 'KRYPTOLAN', 66: 'RVD', 67: 'IPPC', 69: 'SATMON', 70: 'VISA',
                                     71: 'IPCV', 72: 'CPNX', 73: 'CPHB', 74: 'WSN', 75: 'PVP', 76: 'BRSATMON',
                                     77: 'SUNND', 78: 'WBMON', 79: 'WBEXPAK', 80: 'ISOIP', 81: 'VMTP', 82: 'SECUREVMTP',
                                     83: 'VINES', 84: 'IPTM', 85: 'NSFNETIGP', 86: 'DGP', 87: 'TCF', 88: 'EIGRP',
                                     89: 'OSPFIGP', 90: 'SpriteRPC', 91: 'LARP', 92: 'MTP', 93: 'AX25', 94: 'IPIP',
                                     95: 'MICPdeprecated', 96: 'SCCSP', 97: 'ETHERIP', 98: 'ENCAP', 100: 'GMTP',
                                     101: 'IFMP', 102: 'PNNI', 103: 'PIM', 104: 'ARIS', 105: 'SCPS', 106: 'QNX',
                                     107: 'AN', 108: 'IPComp', 109: 'SNP', 110: 'CompaqPeer', 111: 'IPXinIP',
                                     112: 'VRRP', 113: 'PGM', 115: 'L2TP', 116: 'DDX', 117: 'IATP', 118: 'STP',
                                     119: 'SRP', 120: 'UTI', 121: 'SMP', 122: 'SMdeprecated', 123: 'PTP',
                                     124: 'ISISoverIPv4', 125: 'FIRE', 126: 'CRTP', 127: 'CRUDP', 128: 'SSCOPMCE',
                                     129: 'IPLT', 130: 'SPS', 131: 'PIPE', 132: 'SCTP', 133: 'FC', 134: 'RSVPE2EIGNORE',
                                     135: 'MobilityHeader', 136: 'UDPLite', 137: 'MPLSinIP', 138: 'manet', 139: 'HIP',
                                     140: 'Shim6', 141: 'WESP', 142: 'ROHC', 143: 'Ethernet'}

    @staticmethod
    def get_protocol_name(protocol_number: int) -> str:
        """
        :param protocol_number: Protocol number
        :return: The protocol name. If the protocol is not in the DB the protocol's number is returned as string, deeming it \
                 its 'name' for lack of a specific one.
        :rtype: str
        """
        if protocol_number < 1 or protocol_number > 255:
            raise Exception('Protocol number must be in the range 1-255')

        return ProtocolNameResolver._protocol_number_to_name_dict.get(protocol_number, str(protocol_number))

    @staticmethod
    def get_protocol_number(protocol_name: str) -> int:
        """
        :param protocol_name: Protocol name
        :return: The protocol number
        :rtype: int
        """
        if isinstance(protocol_name, int):
            return protocol_name

        protocol_num = ProtocolNameResolver._protocol_name_to_number_dict.get(protocol_name)
        if not protocol_num:
            raise Exception('Unknown protocol name: ' + protocol_name)

        return protocol_num

    @staticmethod
    def is_standard_protocol(protocol: int) -> bool:
        """
        :param protocol: Protocol number
        :return: If the protocol is in the protocol DB
        :rtype: bool
        """
        return protocol in ProtocolNameResolver._protocol_number_to_name_dict
