#!/usr/bin/python
# -*- coding: utf-8 -*-
# This file is not now part of Scapy
## Look iniqua.com for more informations
## ffranz <ffranz@iniqua.com>
## This program is published under a GPLv2 license

import time
import logging

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import _IPOption_HDR
from scapy.all import IP, IPv6, TCP, UDP, Raw, Ether
from scapy.all import *

#   ToDo:
#   GTPv0/1
#
#   GTP-C
# ---------------------------
#
#   GTPHeader()
#
#
#   GTP-U
# ---------------------------
#
#   GTP_U_Header()

GTPmessageType = {
    1: 'echo_request',
    2: 'echo_response',
    16: 'create_pdp_context_req',
    20: 'delete_pdp_context_req',
    21: 'delete_pdp_context_res',
    26: 'error_indication',
    255: 'gtp_u_header',
    }

IEType = {
    1: 'Cause',
    2: 'IMSI',
    3: 'RAI',
    4: 'TLLI',
    5: 'P_TMSI',
    14: 'Recovery',
    15: 'SelectionMode',
    16: 'TEIDI',
    17: 'TEICP',
    19: 'TeardownInd',
    20: 'NSAPI',
    26: 'ChargingChrt',
    27: 'TraceReference',
    28: 'TraceType',
    128: 'EndUserAddress',
    131: 'AccessPointName',
    133: 'GSNAddress',
    }

CauseValues = {
    0x0000: 'Request IMSI',
    1: 'Request IMEI',
    2: 'Request IMSI and IMEI',
    3: 'No identity needed',
    4: 'MS Refuses',
    5: 'MS is not GPRS Responding',
    128: 'Request accepted',
    129: 'New PDP type due to network prefernce',
    130: 'New PDP type due to single address bearer only',
    192: 'Non-exitent',
    133: 'dl_pdu_session',
    193: 'Invalid message format',
    194: 'IMSI not known',
    195: 'MS is GPRS Detached',
    196: 'MS is not GPRS Responding',
    197: 'MS Refuses',
    198: 'Version not supported',
    199: 'No resources available',
    200: 'Service not supported',
    201: 'Mandatory IE incorrect',
    202: 'Mandatory IE missing',
    203: 'Optional IE incorrect',
    204: 'System failure',
    205: 'Roaming restriction',
    206: 'P-TMSI Signature mismatch',
    207: 'GRPS connection suspended',
    208: 'Authentication failure',
    209: 'User authentication failed',
    210: 'Context not found',
    211: 'All dynamic PDP addresses are occupied',
    212: 'No memory is available',
    213: 'Realocation failure',
    214: 'Unknown mandatory extension header',
    215: 'Semantic error in the TFT operation',
    216: 'Syntactic error in TFT operation',
    217: 'Semantc errors in packet filter(s)',
    218: 'Syntactic errors in packet filter(s)',
    219: 'Missing or unknown APN',
    220: 'Unknown PDP address or PDP type',
    221: 'PDP context without TFT already activated',
    222: 'APN access denied : no subscription',
    223: 'APN Restriction type incompatibility with currently active PDP Contexts',
    224: 'MS MBMS Capabilities Insufficient',
    225: 'Invalid Correlation : ID',
    226: 'MBMS Bearer Context Superseded',
    227: 'Bearer Control Mode violation',
    228: 'Collision with network initiated request',
    }

Selection_Mode = {
    11111100: 'MSorAPN',
    11111101: 'MS',
    11111110: 'NET',
    11111111: 'FutureUse',
    }

TeardownInd_value = {254: 'False', 255: 'True'}


class GTPHeader(Packet):

    # 3GPP TS 29.060 V9.1.0 (2009-12)

    name = 'GTP Header'
    fields_desc = [
        BitField('version', 1, 3),
        BitField('PT', 1, 1),
        BitField('Reserved', 0x0000, 1),
        BitField('E', 0x0000, 1),
        BitField('S', 1, 1),
        BitField('PN', 0x0000, 1),
        ByteEnumField('type', None, GTPmessageType),
        BitField('length', None, 16),
        XBitField('TEID', 0x0000, 32),
        ]

    def post_build(self, p, pay):
        p += pay
        warning('Packet length: ' + str(len(p) - 8))
        if self.length is None:
            l = len(p) - 8
            p = p[:1] + struct.pack('!i', l) + p[4:]
        if self.type is None:
            if isinstance(self.payload, GTPEchoRequest):
                t = 1
            elif isinstance(self.payload, GTPEchoResponse):
                t = 2
            elif isinstance(self.payload, GTPCreatePDPContextRequest):
                t = 16
            elif isinstance(self.payload, GTPDeletePDPContextRequest):
                t = 20
            elif isinstance(self.payload, GTPDeletePDPContextResponse):
                t = 21
            elif isinstance(self.payload, GTPErrorIndication):
                t = 26
            else:
                warning('GTPHeader: cannot GPT type! Set type 1 (Echo Request).'
                        )
                t = 1
            p = p[:1] + struct.pack('!B', t) + p[3:]

        # if self.payload.seq is not None:
        # ....warning("TODO: Set S bit '1' because seq number is present.")
        # else:
        # ....warning("TODO: Set S bit '0' because seq number is not present.")

        return p


class GTPEchoRequest(Packet):

    # 3GPP TS 29.060 V9.1.0 (2009-12)

    name = 'GTP Echo Request'
    fields_desc = [XBitField('seq', 0x0000, 16), ByteField('npdu',
                   0x0000), ByteField('next_ex', 0x0000)]


class GTPEchoResponse(Packet):

        # 3GPP TS 29.060 V9.1.0 (2009-12)

    name = 'GTP Echo Response'
    fields_desc = [XBitField('seq', 0x0000, 16), ByteField('npdu',
                   0x0000), ByteField('next_ex', 0x0000),
                   ByteEnumField('IE_Recovery', 'Recovery', IEType),
                   ByteField('res-counter', 24)]


class GTPCreatePDPContextRequest(Packet):

    # 3GPP TS 29.060 V9.1.0 (2009-12)

    name = 'GTP Create PDP Context Request'
    fields_desc = [  # IMSI: Conditional - Suscariber identity of de MS
                     # RAI: Optional - Routeing Area Identity
                     # MNC: If only have 2 digits, then third digit (1byte) is 0xf
                     # Selection Mode: Conditional - Indicates the origin of the APN in the message
                     # First 6 bits are "1". Use only first 2 bits.
                     # TEIDI: Mandatory - Tunnel Endpoint Identifier Data I
                     # TEICP: Conditional - Tunnel Endpoint Identifier Control Plane
                     # NSAPI: Mandatory - identifying a PDP context in a mobility management context specified by TEICP
                     # Charging Characteristics: Conditional - way of informing both the SGSN and GGSN of the rules for
                     # ............    producing charging informarion based on opetaror configured triggers.
                     # ....0000 .... .... .... : spare
                     # ........ 1... .... .... : normal charging
                     # ........ .0.. .... .... : prepaid charging
                     # ........ ..0. .... .... : flat rate charging
                     # ........ ...0 .... .... : hot billing charging
                     # ........ .... 0000 0000 : reserved
                     # Trace Reference: Optional - Identifies a record or a collection of records for a particular trace.
                     # Trace Type: Optional - Indicate the type of the trace
                     # End User Address: Conditional - to supply protocol specific information of the external packet
                     # data network accessed by the GGPRS suscribers.
                     # ....- Request
                     # ........1....Type (1byte)
                     # ........2-3....Length (2bytes) - value 2
                     # ........4....Spare + PDP Type Organization
                     # ........5....PDP Type Number....
                     # ....- Response
                     # ........6-n....PDP Address
                     # Access Point Name: Conditional - Sent by SGSN or by GGSN as defined in 3GPP TS 23.060
                     # ,....length_from=lambda pkt:len(pkt.APNUrl)),
                     # Protocol Configuration:
                     # GSN Address:
        XBitField('seq', 0x0000, 16),
        ByteField('npdu', 0x0000),
        ByteField('next_ex', 0x0000),
        ByteEnumField('IE_IMSI', 'IMSI', IEType),
        BitField('IMSI', 0x0000, 64),
        ByteEnumField('IE_RAI', 'RAI', IEType),
        BitField('MCC', None, 12),
        BitField('MNC', None, 12),
        BitField('LAC', None, 16),
        ByteField('RAC', None),
        ByteEnumField('IE_SelectionMode', 'SelectionMode', IEType),
        BitEnumField('SelectionMode', 'MSorAPN', 8, Selection_Mode),
        ByteEnumField('IE_TEIDI', 'TEIDI', IEType),
        XBitField('TEIDI', 0x0000, 32),
        ByteEnumField('IE_TEICP', 'TEICP', IEType),
        XBitField('TEICP', 0x0000, 32),
        ByteEnumField('IE_NASPI', 'NSAPI', IEType),
        XBitField('SpareNSAPI', 0x0000, 4),
        XBitField('NSAPI', 0x0000, 4),
        ByteEnumField('IE_ChargingChrt', 'ChargingChrt', IEType),
        XBitField('Ch_ChSpare', None, 4),
        XBitField('normal_charging', None, 1),
        XBitField('prepaid_charging', None, 1),
        XBitField('flat_rate_charging', None, 1),
        XBitField('hot_billing_charging', None, 1),
        XBitField('Ch_ChReserved', 0x0000, 8),
        ByteEnumField('IE_TraceReference', 'TraceReference', IEType),
        XBitField('Trace_reference', None, 16),
        ByteEnumField('IE_TraceType', 'TraceType', IEType),
        XBitField('Trace_type', None, 16),
        ByteEnumField('IE_EndUserAddress', 'EndUserAddress', IEType),
        BitField('EndUserAddressLength', 2, 16),
        BitField('EndUserAddress', 1111, 4),
        BitField('PDPTypeOrganization', 1, 4),
        XByteField('PDPTypeNumber', None),
        ByteEnumField('IE_AccessPointName', 'AccessPointName', IEType),
        ByteField('APNLength', None),
        StrField('APNUrl', 'apn.es'),
        ByteEnumField('IE_GSNAddress1', 'GSNAddress', IEType),
        LongField('GSNAddressLength', 4),
        IPField('IPGSN1', '0.0.0.0'),
        ]


        # GSN Address:

class GTPErrorIndication(Packet):

    # 3GPP TS 29.060 V9.1.0 (2009-12)

    name = 'GTP Error Indication'
    fields_desc = [  # TEIDI: Mandatory - Tunnel Endpoint Identifier Data I
                     # GSN Address:
        XBitField('seq', 0x0000, 16),
        ByteField('npdu', 0x0000),
        ByteField('next_ex', 0x0000),
        ByteEnumField('IE_TEIDI', 'TEIDI', IEType),
        XBitField('TEIDI', 0x0000, 32),
        ByteEnumField('IE_GSNAddress1', 'GSNAddress', IEType),
        BitField('GSNAddressLength', 4, 16),
        IPField('IPGSN1', '252.253.254.255'),
        ]


class GTPDeletePDPContextRequest(Packet):

        # 3GPP TS 29.060 V9.1.0 (2009-12)....

    name = 'GTP Delete PDP Context Request'
    fields_desc = [  # Teardown Ind: conditional - If this element is set to "1", all PDP Contexts thatt share the same PDP
                     # ................address or two IP addresses with the PDP context indentified by the
                     # ................NSAPI included in the Delete PDP Context Request Message shall be torn down.
                     # NSAPI: Mandatory - identifying a PDP context in a mobility management context specified by TEICP
        XBitField('seq', 0x0000, 16),
        ByteField('npdu', 0x0000),
        ByteField('next_ex', 0x0000),
        ByteEnumField('IE_TeardownInd', 'TeardownInd', IEType),
        ByteEnumField('TeardownInd', 'True', TeardownInd_value),
        ByteEnumField('IE_NSAPI', 'NSAPI', IEType),
        XBitField('SpareNSAPI', 0x0000, 4),
        XBitField('NSAPI', 0x0000, 4),
        ]


        # Protocol Configuration Options: Optional - TODO

        # Private Extansions: Optional - Contains vendor specific information. TODO

class GTPDeletePDPContextResponse(Packet):

        # 3GPP TS 29.060 V9.1.0 (2009-12)

    name = 'GTP Delete PDP Context Response'
    fields_desc = [  # Cause: Mandatory -
        XBitField('seq', 0x0000, 16),
        ByteField('npdu', 0x0000),
        ByteField('next_ex', 0x0000),
        ByteEnumField('IE_Cause', 'Cause', IEType),
        BitField('Response', None, 1),
        BitField('Rejection', None, 1),
        BitEnumField('CauseValue', None, 6, CauseValues),
        ]


        # Protocol Configuration Options: Optional - TODO

        # User Location Information: Optional - TODO

        # MS Time Zone: Optional - TODO

        # Private Extension: Optional - TODO

class GTP_U_Header(Packet):

    # 3GPP TS 29.060 V9.1.0 (2009-12)

    name = 'GTP-U Header'

    # GTP-U protocol is used to transmit T-PDUs between GSN pairs (or between an SGSN and an RNC in UMTS),
    # encapsulated in G-PDUs. A G-PDU is a packet including a GTP-U header and a T-PDU. The Path Protocol
    # defines the path and the GTP-U header defines the tunnel. Several tunnels may be multiplexed on a single path.

    fields_desc = [
        BitField('version', 1, 3),
        BitField('PT', 1, 1),
        BitField('Reserved', 0x0000, 1),
        BitField('E', 0x0000, 1),
        BitField('S', 0x0000, 1),
        BitField('PN', 0x0000, 1),
        ByteEnumField('type', 255, GTPmessageType),
        BitField('length', None, 16),
        XBitField('TEID', 0x0000, 32),
        ]


                    # BitField("next_ex",     10000101,   8),
        # ....ConditionalField(XBitField("seq",        0,      16), lambda pkt:pkt.E==1 or pkt.S==1 or pkt.PN==1),
                       # ConditionalField(ByteField("npdu",       0), lambda pkt:pkt.E==1 or pkt.S==1 or pkt.PN==1),
                       # ConditionalField(ByteField("next_ex",    0), lambda pkt:pkt.E==1 or pkt.S==1 or pkt.PN==1),

class GTPmorethan1500(Packet):

    # 3GPP TS 29.060 V9.1.0 (2009-12)

    name = 'GTP More than 1500'

        # GTP-U protocol is used to transmit T-PDUs between GSN pairs (or between an SGSN and an RNC in UMTS),
        # encapsulated in G-PDUs. A G-PDU is a packet including a GTP-U header and a T-PDU. The Path Protocol
        # defines the path and the GTP-U header defines the tunnel. Several tunnels may be multiplexed on a single path.

    fields_desc = [ByteEnumField('IE_Cause', 'Cause', IEType),
                   BitField('IE', 1, 12000)]


class dl_pdu_session(Packet):

    name = 'DL PDU Session'
    fields_desc = [
        BitField('gtp_ext', 0x0000, 8),
        BitField('PDU_type', 0x0000, 4),
        BitField('Spare', 0x0000, 5),
        BitField('RQI', 0x0000, 1),
        BitField('QoSID', 0x0000, 6),
        BitField('padding', 0x0000, 8),
        ]


class ul_pdu_session(Packet):

    name = 'UL PDU Session'
    fields_desc = [BitField('gtp_ext', 0x0000, 8), BitField('PDU_type',
                   1, 4), BitField('Spare', 0x0000, 6), BitField('QoSID'
                   , 0x0000, 6), BitField('padding', 0x0000, 8)]


# Bind GTP-C

bind_layers(UDP, GTPHeader)

# bind_layers( GTPHeader, GTPEchoRequest)
# bind_layers( GTPHeader, GTPEchoResponse)
# bind_layers( GTPHeader, GTPCreatePDPContextRequest)
# bind_layers( GTPHeader, GTPDeletePDPContextRequest)
# bind_layers( GTPHeader, GTPDeletePDPContextResponse)
# Bind GTP-U
# bind_layers(UDP,GTP_U_Header) tester

bind_layers(GTP_U_Header, IP)
bind_layers(GTP_U_Header, IPv6)

# bind_layers(GTP_U_Header,dl_pdu_session) testar
# bind_layers(GTP_U_Header,ul_pdu_session) testar

bind_layers(dl_pdu_session, IP)
bind_layers(ul_pdu_session, IP)
bind_layers(dl_pdu_session, IPv6)
bind_layers(ul_pdu_session, IPv6)

if __name__ == '__main__':
    interact(mydict=globals(), mybanner='Test GTP add-on v0.1')
