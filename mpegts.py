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
                                    "payload_unit_start_indicator",
                                    "transport_priority",
                                    "packet_identifier",
                                    "transport_scrambling_control",
                                    "adaptation_field_control",
                                    "continuity_counter"]
                       )

AF_Header = namedtuple(typename="AF_Header",
                       field_names=["adaptation_field_length",
                                    "discontinuity_indicator",
                                    "random_access_indicator",
                                    "elementary_stream_priority_indicator",
                                    "program_clock_reference_flag",
                                    "original_program_clock_reference_flag",
                                    "splicing_point_flag",
                                    "transport_private_data_flag",
                                    "adaptation_field_extension_flag"]
                       )

TS_Payload = namedtuple(typename="TS_Payload",
                        field_names=["payload_pointer",
                                     "payload"]
                        )

AdaptationField = namedtuple(typename="AdaptationField",
                             field_names=["adaptation_field_length",
                                          "adaptation_field_header",
                                          "program_clock_reference",
                                          "original_program_clock_reference",
                                          "splicing_point",
                                          "transport_private_data",
                                          "adaptation_field_extension"
                                          ])


def mpeg_ts_packet_generator(filename):
    with open(filename, "rb") as mpeg_ts_file:
        while mpeg_ts_packet := mpeg_ts_file.read(188):
            yield mpeg_ts_packet


def init_ts_header(packet):
    ts_header = unpack("!I", packet.read(4))[0]
    sync_byte = (ts_header & 0xff000000) >> 24
    transport_error_indicator = (ts_header & 0x00800000) >> 23
    payload_unit_start_indicator = (ts_header & 0x00400000) >> 22
    transport_priority = (ts_header & 0x200000) >> 21
    packet_identifier = (ts_header & 0x1fff00) >> 8
    transport_scrambling_control = (ts_header & 0xc0) >> 6
    adaptation_field_control = (ts_header & 0x30) >> 4
    continuity_counter = ts_header & 0xf

    return TS_Header(sync_byte,
                     transport_error_indicator,
                     payload_unit_start_indicator,
                     transport_priority,
                     packet_identifier,
                     transport_scrambling_control,
                     adaptation_field_control,
                     continuity_counter)


def init_adaptation_field_header(adaptation_field_length, packet):
    if adaptation_field_length != 0:
        adaptation_field_header = unpack("!B", packet.read(1))[0]
        discontinuity_indicator = (adaptation_field_header & 0x80) >> 7
        random_access_indicator = (adaptation_field_header & 0x40) >> 6
        elementary_stream_priority_indicator = (adaptation_field_header & 0x20) >> 5
        program_clock_reference_flag = (adaptation_field_header & 0x10) >> 4
        original_program_clock_reference_flag = (adaptation_field_header & 0x08) >> 3
        splicing_point = (adaptation_field_header & 0x04) >> 2
        transport_private_data = (adaptation_field_header & 0x02) >> 1
        adaptation_field_extension = (adaptation_field_header & 0x01)
    else:
        discontinuity_indicator = None
        random_access_indicator = None
        elementary_stream_priority_indicator = None
        program_clock_reference_flag = None
        original_program_clock_reference_flag = None
        splicing_point = None
        transport_private_data = None
        adaptation_field_extension = None

    return AF_Header(adaptation_field_length,
                     discontinuity_indicator,
                     random_access_indicator,
                     elementary_stream_priority_indicator,
                     program_clock_reference_flag,
                     original_program_clock_reference_flag,
                     splicing_point,
                     transport_private_data,
                     adaptation_field_extension)


def calc_program_clock_reference(packet):
    program_clock_reference, reserved, extension = unpack("!LBB", packet)
    program_clock_reference = (program_clock_reference << 1) + (reserved >> 7)
    extension = extension + ((reserved & 1) << 9)
    program_clock_reference = program_clock_reference * 300 + extension
    return program_clock_reference


def get_splicing_point(packet):
    splicing_point = unpack("!b", packet)[0]
    return splicing_point


def get_transport_private_data(packet):
    transport_private_data_length = unpack("!B", packet.read(1))[0]
    transport_private_data = packet.read(transport_private_data_length)
    return transport_private_data, transport_private_data_length


def get_adaptation_extension(packet):
    adaptation_extension_length = unpack("!B", packet.read(1))[0]
    adaptation_extension = packet.read(adaptation_extension_length)
    return adaptation_extension, adaptation_extension_length


def strip_stuffing_bytes(packet, stuffing_bytes_length):
    packet.read(stuffing_bytes_length)


def init_adaptation_field(packet):
    adaptation_field_length = unpack("!B", packet.read(1))[0]
    adaptation_field_header = init_adaptation_field_header(adaptation_field_length, packet)
    if adaptation_field_length == 0:
        stuffing_bytes_length = adaptation_field_header.adaptation_field_length
    else:
        stuffing_bytes_length = adaptation_field_header.adaptation_field_length - 1

    program_clock_reference = None
    if adaptation_field_header.program_clock_reference_flag:
        program_clock_reference = calc_program_clock_reference(packet.read(6))
        stuffing_bytes_length -= 6

    original_program_clock_reference = None
    if adaptation_field_header.original_program_clock_reference_flag:
        original_program_clock_reference = calc_program_clock_reference(packet.read(6))
        stuffing_bytes_length -= 6

    splicing_point = None
    if adaptation_field_header.splicing_point_flag:
        splicing_point = get_splicing_point(packet.read(1))
        stuffing_bytes_length -= 1

    transport_private_data = None
    if adaptation_field_header.transport_private_data_flag:
        transport_private_data, tpd_length = get_transport_private_data(packet)
        stuffing_bytes_length -= 1 + tpd_length

    adaptation_extension = None
    if adaptation_field_header.adaptation_field_extension_flag:
        adaptation_extension, adaptation_extension_length = get_adaptation_extension(packet)
        stuffing_bytes_length -= 1 + adaptation_extension_length

    strip_stuffing_bytes(packet, stuffing_bytes_length)
    return AdaptationField(adaptation_field_length,
                           adaptation_field_header,
                           program_clock_reference,
                           original_program_clock_reference,
                           splicing_point,
                           transport_private_data,
                           adaptation_extension)


def init_payload(packet, payload_pointer_flag):
    if payload_pointer_flag:
        payload_pointer = unpack("!B", packet.read(1))[0]
        payload = packet.read()
    else:
        payload_pointer = None
        payload = packet.read()
    return TS_Payload(payload_pointer,
                      payload)


def init_ts_packet(packet):
    packet = io.BytesIO(packet)
    ts_header = init_ts_header(packet)
    if ts_header.adaptation_field_control in [2, 3]:
        adaptation_field = init_adaptation_field(packet)
    else:
        adaptation_field = None

    payload = init_payload(packet, ts_header.payload_unit_start_indicator)
    return TS_Packet(ts_header,
                     adaptation_field,
                     payload)


if __name__ == "__main__":
    for pack in mpeg_ts_packet_generator("main.ts"):
        print(init_ts_packet(pack))
