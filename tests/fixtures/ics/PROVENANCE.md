# Provenance of the capture fixtures

The captures in this folder are real industrial-protocol traffic, used as test input for the passive OT decoders (`core/src/otpassive/real_traffic.rs`) and as fuzz seeds. They are copied byte for byte, unmodified, from the public repository below.

- Source: <https://github.com/ITI/ICS-Security-Tools>, directory `pcaps/`
- Commit: `bcb93ee1cdf395a457cc08f639cf29aab5975f01`
- Licence: [Creative Commons Attribution 4.0 International (CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/), stated by the repository as a whole; the individual captures may have been contributed to it by other parties
- Attribution: "ICS-Security-Tools packet captures, ITI/ICS-Security-Tools (https://github.com/ITI/ICS-Security-Tools), licensed under CC-BY-4.0"
- Changes: none to the files. The fuzz seeds in `fuzz/corpus/` named `ics_*` are these captures (the `pcapfile` ones byte for byte) or frames and message bodies cut out of them, see below

The captures are untrusted input. Tests read them only through the capture reader and the decoders.

| File | Upstream path (under `pcaps/`) | SHA-256 | Size (bytes) | Content |
|---|---|---|---|---|
| `bacnet_test.pcap` | `BACnet/bacnet_test.pcap` | `973724800eef38e1131368d4ebce0eafc6593ccb4763916b8ee69b3b1328d8ff` | 1956 | BACnet/IP ReadProperty requests and replies |
| `enip_cip_stop_plc.pcap` | `EthernetIP/cip_stop_plc.pcap` | `93e5d388193fcaff3f3f38878de34269afcd01318897a2d36647c773d1e5ed3d` | 146 | EtherNet/IP CIP Stop request |
| `enip_test.pcap` | `EthernetIP/enip_test.pcap` | `0ba6c01fde28912e9f890d839b991cff71cca8e8259e1d93e9c3a312c43bc255` | 925 | EtherNet/IP List Identity |
| `iec104_diverse.pcap` | `IEC60870-5-104/090813_diverse.pcap` | `07b9a0879dc83e420c4cf83b37fb5830d1d8fb5f6ac6edc435896f70b0fc6bc7` | 13952 | IEC 60870-5-104 commands (loopback capture) |
| `iec104_test_dissect.pcap` | `IEC60870-5-104/TestDissectIec104.pcap` | `292c18a8765db3b1bcaa9bd0b8455e4e61b8366cc5910a7363b7381eb11441b8` | 11409 | IEC 60870-5-104 master and outstation |
| `mms_read_request.pcap` | `IEC61850/MMS - Specific Commands/mms-readRequest.pcap` | `6b445ad695c740f42dd2045eca7c74f0c7f470983b86eed3de020f95ebf1c488` | 1277 | IEC 61850 MMS read request |
| `mms_stop_request.pcap` | `IEC61850/MMS - Specific Commands/mms-stopRequest.pcap` | `8ce1b9ecee08ac1af99579eafefb8398cad8c49c1cd74b5a88de7fa35df9099a` | 1906 | IEC 61850 MMS Start and Stop of a program invocation |
| `melsec_melsoft_udp.pcap` | `MELSEC/melsoft_UDP_clean_2.pcap` | `3cc6dcf628f17af8208ec5d56227462e176f0871092bd55618d7c5649162479b` | 71702 | Mitsubishi MELSOFT direct connection over UDP (an FX5U; too large for the fuzz seed corpus, the first 60 frames seed `otpassive_feed`) |
| `modbus_test_data_part1.pcap` | `ModbusTCP/modbus_test_data_part1.pcap` | `94942b3d014810710f50836c95d3faf6df6e6370a6560bae541397c1df50213d` | 10181 | Modbus/TCP reads, writes, diagnostics and device identification |
| `modbus_test_data_part2.pcap` | `ModbusTCP/modbus_test_data_part2.pcap` | `f7cca627fe9b740b5881e8b33b4143b59158240192ecbf5caa727a7dda35d110` | 27764 | Modbus/TCP walk through the function codes |
| `opcua_method_call.pcap` | `OPC/opc-ua-ap-method-wireshark-freeze.pcap` | `2a7bc18fc97829db65d04be564ef8db4d4e3950d0b0b07f77197449fbc9300de` | 46516 | OPC UA session on port 12001 (GetEndpoints, CreateSession) |
| `dnp3_read_and_response.pcap` | `dnp3/read_and_response.pcap` | `26e2d60fd228280993c5c41ffb4f4d3105e75c2c2dbefea732e4f99fe3ae2698` | 1254 | DNP3 Read and response |
| `dnp3_select_operate.pcap` | `dnp3/select_operate_and_responses.pcap` | `2b9c0c043d076e562f3870f5b2b3146f562dfa91d9625c7a0de51a9818ae96ff` | 1044 | DNP3 Select and Operate with responses |
| `dnp3_write_binary_output.pcap` | `dnp3/write_binary_output.pcap` | `9f0e6a090280879729b543ba693e09756723e3707daf78303aca6b71c7b73b1f` | 115 | DNP3 Write of a binary output |
| `fox_info.pcap` | `fox/fox_info.pcap` | `04226fe5f8d5a9b32c74e3ddaaf0af84bf27fc40cf392d4306cf80ee6185246a` | 1954 | Niagara Fox hello exchange (the nmap `fox-info` handshake) |
| `omron_test.pcap` | `omron/omron_test.pcap` | `73c6e2d6ab4a96e4330d5a0bf01ca721ee6676b014ff1b674aa5034349e0a307` | 1582 | Omron FINS: Controller Data Read over TCP and UDP |
| `profinet_dcp_change_ip.pcap` | `profinet/PROFINET-RT-DCP_ChangeIPUsingDCP.pcap` | `aaba0d1492ca2cae77dcac3ae311bcc5c63b72e79b2a8fd04389c0f9d1d01c98` | 532 | Profinet DCP Identify and Set IP |
| `profinet_test.pcap` | `profinet/profinet.pcap` | `bda384b5cf3b7035f13ae3bdc860d5d971627c1ded3c5e588a7b8f559effb931` | 572 | Profinet CBA/DCOM over UDP |
| `s7_1200_hmi.pcap` | `s7/s7-1200-hmi.pcap` | `b38ccaf183673619e7f5d69476293a01da743076a281c96e949f0f29a42d1650` | 11559 | S7-1200 and HMI (S7CommPlus) |
| `s7comm_downloading_block_db1.pcap` | `s7/s7comm_downloading_block_db1.pcap` | `48725bd1af7b778821351cd0f50f0ee259e438074a27f8431a8a1a3351dfd3d0` | 9523 | S7comm block download of DB1 |
| `s7comm_reading_plc_status.pcap` | `s7/s7comm_reading_plc_status.pcap` | `e71f81b471bd67da2fd6e40dc69a7179574ba66771c6150cd7bfe232cc07b8a9` | 25112 | S7comm SZL reads of CPU status |
| `snap7_s300_stop.pcapng` | `s7/snap7_s300_stop.pcapng` | `c3d47f730f76f37a0114fd7bae4dbe580c8bf22c71201852a2817cc5c9192de5` | 217 | S7comm PLC Stop (snap7, S7-300) |

## Fuzz seeds derived from the captures

Files below `fuzz/corpus/` whose name starts with `ics_` (all captures under 64 KB; `melsec_melsoft_udp.pcap` is left out):

- `pcapfile/ics_*`: the capture files, unchanged.
- `otpassive_feed/ics_*`: the frames of the Modbus, S7, EtherNet/IP, IEC 104, DNP3 and BACnet captures re-packed into the record layout of that target (flag byte 0, first timestamp, then length, timestamp step and frame per record).
- `s7_szl/ics_*`: the two S7comm userdata replies (SZL 0x11 and the first fragment of SZL 0x1c) of `s7comm_reading_plc_status.pcap`; the PDU reference is rewritten to 2, the one the probe's parser expects.
- `opcua_reply/ics_*`: the OpenSecureChannel response body, the GetEndpoints response body (request handle rewritten to 2) and the ERR message body from `opcua_method_call.pcap`.
- `otpassive_feed/ics_omron_test`, `ics_fox_info`, `ics_mms_read_request`, `ics_mms_stop_request`, `ics_profinet_dcp_change_ip` and `ics_melsec_melsoft_udp_head` (the first 60 frames): the frames in the same record layout.
- `fins_reply/ics_omron_udp_reply`, `fox_hello/ics_fox_station_hello` and `ics_fox_client_hello`: the payloads of the Omron UDP reply and of the two Fox hellos.
- `enip_list_identity/ics_1756_enbt`: the List Identity reply of `enip_test.pcap` without its encapsulation header.
