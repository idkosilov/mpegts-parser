import io
from collections import namedtuple
from struct import unpack

TS_Packet = namedtuple(typename="TS_Packet",
                       field_names=["ts_header",
                                    "adaptation_field",
                                    "payload"]
                       )

TS_Header = namedtuple(typename="TS_Header",
                       field_names=["sync_byte",
                                    "transport_error_indicator",
                                    "payload_unit_start_indicator ",
                                    "transport_priority",
                                    "packet_identifier",
                                    "transport_scrambling_control",
                                    "adaptation_field_control",
                                    "continuity_counter"]
                       )

AF_Header = namedtuple(typename="AF_Header",
                       field_names=["af_length",
                                    "di",
                                    "rai",
                                    "espi",
                                    "pcrf",
                                    "opcrf",
                                    "spf",
                                    "tpdf",
                                    "afef"]
                       )

TS_Payload = namedtuple(typename="TS_Payload",
                        field_names=["payload_pointer",
                                     "payload"]
                        )


AdaptationField = namedtuple(typename="AdaptationField",
                             field_names=["af_length",
                                          "adaptation_field_header",
                                          "pcr",
                                          "opcr",
                                          "splicing_point",
                                          "transport_private_data",
                                          "adaptation_field_extension"
                                          ])


def mpeg_ts_packet_generator(filename):
    with open(filename, "rb") as mpeg_ts_file:
        while mpeg_ts_packet := mpeg_ts_file.read(188):
            yield mpeg_ts_packet


def init_ts_header(packet):
    ts_header = unpack("!I", packet)[0]
    sync = (ts_header & 0xff000000) >> 24  # sync byte
    tei = (ts_header & 0x00800000) >> 23  # transport error indicator
    pusi = (ts_header & 0x00400000) >> 22  # payload unit start indicatorc
    tp = (ts_header & 0x200000) >> 21  # transport_priority
    pid = (ts_header & 0x1fff00) >> 8  # packet identifier
    tsc = (ts_header & 0xc0) >> 6  # transport scrambling control
    afc = (ts_header & 0x30) >> 4  # adaptation field control
    cc = ts_header & 0xf  # continuity counter

    return TS_Header(sync, tei, pusi, tp, pid, tsc, afc, cc)


def init_adaptation_field_header(af_length, packet):
    if af_length != 0:
        af_header = unpack("!B", packet.read(1))[0]
        di = (af_header & 0x80) >> 7  # discontinuity indicator
        rai = (af_header & 0x40) >> 6  # random access indicator
        espi = (af_header & 0x20) >> 5  # elementary stream priority indicator
        pcrf = (af_header & 0x10) >> 4  # PCR flag
        opcrf = (af_header & 0x08) >> 3  # OPCR flag
        spf = (af_header & 0x04) >> 2  # splicing point flag
        tpdf = (af_header & 0x02) >> 1  # transport private data flag
        afef = (af_header & 0x01)  # Adaptation field extension flag
    else:
        di = None  # discontinuity indicator
        rai = None  # random access indicator
        espi = None  # elementary stream priority indicator
        pcrf = None  # PCR flag
        opcrf = None  # OPCR flag
        spf = None  # splicing point flag
        tpdf = None  # transport private data flag
        afef = None
    return AF_Header(af_length, di, rai, espi, pcrf, opcrf, spf, tpdf, afef)


def calc_pcr(packet):
    pcr, rsrv, pcr_ex = unpack("!LBB", packet)
    pcr = (pcr << 1) + (rsrv >> 7)
    pcr_ex = pcr_ex + ((rsrv & 1) << 9)
    pcr = pcr * 300 + pcr_ex
    return pcr


def get_splicing_point(packet):
    splicing_point = unpack("!b", packet)[0]
    return splicing_point


def get_tpd(packet):
    tpdl = unpack("!B", packet.read(1))[0]
    tpd = packet.read(tpdl)
    return tpd, tpdl


def get_adaptation_field_extension(packet):
    ael = unpack("!B", packet.read(1))[0]
    ae = packet.read(ael)
    return ae, ael


def strip_stuffing_bytes(packet, stuffing_bytes_length):
    packet.read(stuffing_bytes_length)


def init_adaptation_field(packet):
    af_length = unpack("!B", packet.read(1))[0]
    adaptation_field_header = init_adaptation_field_header(af_length, packet)
    if af_length == 0:
        stuffing_bytes_length = adaptation_field_header.af_length
    else:
        stuffing_bytes_length = adaptation_field_header.af_length - 1
    pcr = None
    if adaptation_field_header.pcrf:
        pcr = calc_pcr(packet.read(6))
        stuffing_bytes_length -= 6
    opcr = None
    if adaptation_field_header.opcrf:
        opcr = calc_pcr(packet.read(6))
        stuffing_bytes_length -= 6
    splicing_point = None
    if adaptation_field_header.spf:
        splicing_point = get_splicing_point(packet.read(1))
        stuffing_bytes_length -= 1
    transport_private_data = None
    if adaptation_field_header.tpdf:
        transport_private_data, tpd_length = get_tpd(packet)
        stuffing_bytes_length -= 1 + tpd_length
    adaptation_field_extension = None
    if adaptation_field_header.afef:
        adaptation_field_extension, afe_length = get_adaptation_field_extension(packet)
        stuffing_bytes_length -= 1 + afe_length
    strip_stuffing_bytes(packet, stuffing_bytes_length)
    return AdaptationField(af_length, adaptation_field_header, pcr, opcr,
                           splicing_point, transport_private_data, adaptation_field_extension)


def init_payload(packet, payload_pointer_flag):
    if payload_pointer_flag:
        payload_pointer = unpack("!B", packet.read(1))[0]
        payload = packet.read()
    else:
        payload_pointer = None
        payload = packet.read()
    return TS_Payload(payload_pointer, payload)


def init_ts_packet(packet):
    packet = io.BytesIO(packet)
    ts_header = init_ts_header(packet.read(4))
    if ts_header.afc in [2, 3]:
        adaptation_field = init_adaptation_field(packet)
    else:
        adaptation_field = None

    payload = init_payload(packet, ts_header.pusi)
    return TS_Packet(ts_header,
                     adaptation_field,
                     payload)


if __name__ == "__main__":
    for pack in mpeg_ts_packet_generator("main.ts"):
        print(init_ts_packet(pack))
