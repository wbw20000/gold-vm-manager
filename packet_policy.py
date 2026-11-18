"""Fail-closed, single-guest Ethernet policy. No sockets or process management.

PacketPolicy(guest_mac, [('tcp', 'PUBLIC_IPV4', port), ...]) exposes
allow_outbound(frame) and allow_inbound(frame). A True result authorizes the
*unchanged* datagram, not any stream concatenation. The caller MUST reject
recvmsg MSG_TRUNC, use one isolated VM/socket pair, and close its forwarding
sockets on failure. This module neither starts networking nor configures TUN.

IPv4 only; MTU 1500; no IP options/fragments/VLAN/ICMP/TCP Fast Open. IPv4 and
TCP checksums are required; IPv4 UDP's legal zero checksum is accepted. TCP
tracking validates the handshake and tuple, not established sequence windows:
this is an endpoint restriction, NOT protection against malicious guest root
spoofing an existing transport endpoint. TCP/UDP/DHCP state is bounded. Only
initiator traffic renews a flow. UDP replies require a prior allowed request.
Management SSH is off by default and admits only gateway-initiated TCP/22.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import ipaddress
import math
import struct
import threading
import time
from typing import Callable, Iterable


BROADCAST_MAC = b'\xff' * 6
ZERO_MAC = b'\x00' * 6
ZERO_IP = b'\x00' * 4
BROADCAST_IP = b'\xff' * 4
SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04


class _Reject(Exception):
    pass


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise _Reject(reason)


def _mac(value: str) -> bytes:
    try:
        parts = value.split(':')
        if len(parts) != 6 or any(len(p) != 2 for p in parts):
            raise ValueError
        result = bytes(int(p, 16) for p in parts)
    except (ValueError, AttributeError):
        raise ValueError('MAC must contain six two-digit hexadecimal octets') from None
    if result == ZERO_MAC or result[0] & 1:
        raise ValueError('MAC must be nonzero unicast')
    return result


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def _positive_int(value: int, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(name + ' must be a positive integer')
    return value


@dataclass(frozen=True)
class _Packet:
    src: bytes
    dst: bytes
    protocol: int
    sport: int
    dport: int
    flags: int
    seq: int
    ack: int
    payload: bytes


@dataclass
class _Flow:
    management: bool
    expires: float
    state: str = 'udp'
    initiator_seq: int = 0
    responder_seq: int = 0
    initiator_fin: bool = False
    responder_fin: bool = False


@dataclass
class _DHCP:
    expires: float
    request_type: int


class PacketPolicy:
    """Stateful allow/deny decisions for one pinned guest and gateway.

    endpoints is an iterable of ("tcp"|"udp", public_ipv4_string, port).
    Address/port/protocol matching is exact; port 53 is always forbidden.
    Expired entries are removed, but live entries are never evicted to admit
    a new flow. Cache exhaustion therefore denies new connections.
    """

    def __init__(
        self,
        guest_mac: str,
        endpoints: Iterable[tuple[str, str, int]],
        *,
        guest_ip: str = '192.168.127.2',
        gateway_ip: str = '192.168.127.1',
        gateway_mac: str = '5a:94:ef:e4:0c:dd',
        allow_management: bool = False,
        max_flows: int = 512,
        max_dhcp_transactions: int = 16,
        tcp_timeout: float = 300.0,
        udp_timeout: float = 60.0,
        dhcp_timeout: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.guest_mac = _mac(guest_mac)
        self.gateway_mac = _mac(gateway_mac)
        self.guest_ip = ipaddress.IPv4Address(guest_ip).packed
        self.gateway_ip = ipaddress.IPv4Address(gateway_ip).packed
        if self.guest_mac == self.gateway_mac or self.guest_ip == self.gateway_ip:
            raise ValueError('guest and gateway identities must differ')
        subnet = ipaddress.IPv4Network('192.168.127.0/24')
        if any(ipaddress.IPv4Address(a) not in subnet or a[-1] in (0, 255)
               for a in (self.guest_ip, self.gateway_ip)):
            raise ValueError('guest and gateway must be usable 192.168.127.0/24 addresses')
        if type(allow_management) is not bool:
            raise ValueError('allow_management must be bool')
        self._allow_management = allow_management
        self.max_flows = _positive_int(max_flows, 'max_flows')
        self.max_dhcp_transactions = _positive_int(max_dhcp_transactions, 'max_dhcp_transactions')
        for value in (tcp_timeout, udp_timeout, dhcp_timeout):
            if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value <= 0:
                raise ValueError('timeouts must be finite positive numbers')
        self.tcp_timeout = float(tcp_timeout)
        self.udp_timeout = float(udp_timeout)
        self.dhcp_timeout = float(dhcp_timeout)
        self._clock = clock
        self._endpoints: frozenset[tuple[int, bytes, int]] = frozenset(
            self._endpoint(item) for item in endpoints
        )
        if not self._endpoints:
            raise ValueError('at least one explicit proxy endpoint is required')
        self._flows: dict[tuple[int, int, bytes, int], _Flow] = {}
        self._dhcp: dict[int, _DHCP] = {}
        self._counts: Counter[str] = Counter()
        self._lock = threading.RLock()
        self._last_now = -math.inf
        self._next_gc = -math.inf

    @staticmethod
    def _endpoint(item: tuple[str, str, int]) -> tuple[int, bytes, int]:
        try:
            protocol, address, port = item
        except (ValueError, TypeError):
            raise ValueError('endpoint must be (tcp|udp, public IPv4, port)') from None
        if protocol not in ('tcp', 'udp'):
            raise ValueError('endpoint protocol must be tcp or udp')
        ip = ipaddress.IPv4Address(address)
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local:
            raise ValueError('endpoint must be a globally routable unicast IPv4 address')
        if type(port) is not int or not 1 <= port <= 65535 or port == 53:
            raise ValueError('endpoint port must be 1..65535, excluding DNS port 53')
        return (6 if protocol == 'tcp' else 17, ip.packed, port)

    def set_management_enabled(self, enabled: bool) -> None:
        """Disable atomically and revoke every existing management tuple."""
        if type(enabled) is not bool:
            raise ValueError('management setting must be bool')
        with self._lock:
            self._allow_management = enabled
            if not enabled:
                self._flows = {k: v for k, v in self._flows.items() if not v.management}

    def snapshot(self) -> dict[str, object]:
        """Aggregated counters only: no IP addresses, payloads, or credentials."""
        with self._lock:
            return {'counters': dict(self._counts), 'flows': len(self._flows),
                    'dhcp_transactions': len(self._dhcp),
                    'management_enabled': self._allow_management}

    def allow_outbound(self, frame: bytes) -> bool:
        return self._decide(frame, outbound=True)

    def allow_inbound(self, frame: bytes) -> bool:
        return self._decide(frame, outbound=False)

    def _prune(self, now: float, *, force: bool = False) -> None:
        if force or now >= self._next_gc:
            self._flows = {k: v for k, v in self._flows.items() if v.expires > now}
            self._dhcp = {k: v for k, v in self._dhcp.items() if v.expires > now}
            self._next_gc = now + 1.0

    def _decide(self, frame: bytes, *, outbound: bool) -> bool:
        direction = 'out' if outbound else 'in'
        with self._lock:
            try:
                now = float(self._clock())
                _require(math.isfinite(now) and now >= self._last_now, 'clock')
                self._last_now = now
                self._prune(now)
                _require(isinstance(frame, (bytes, bytearray, memoryview)), 'frame_type')
                _require(14 <= len(frame) <= 1514, 'ethernet_length')
                data = bytes(frame)
                dst, src = data[:6], data[6:12]
                _require(src == (self.guest_mac if outbound else self.gateway_mac), 'ethernet_source')
                _require(dst in ((self.gateway_mac, BROADCAST_MAC) if outbound else (self.guest_mac, BROADCAST_MAC)),
                         'ethernet_destination')
                ethertype = struct.unpack_from('!H', data, 12)[0]
                if ethertype == 0x0806:
                    self._arp(data, outbound, dst)
                elif ethertype == 0x0800:
                    packet = self._ipv4(data)
                    if packet.protocol == 17 and (packet.sport, packet.dport) in ((68, 67), (67, 68)):
                        self._handle_dhcp(packet, outbound, dst, now)
                    else:
                        _require(dst == (self.gateway_mac if outbound else self.guest_mac), 'data_broadcast')
                        _require((packet.src if outbound else packet.dst) == self.guest_ip, 'guest_ip')
                        self._data(packet, outbound, now)
                else:
                    raise _Reject('ethertype')
            except _Reject as exc:
                self._counts[direction + '.dropped'] += 1
                self._counts['drop.' + str(exc)] += 1
                return False
            except Exception:
                # No packet or exception payload is logged. Unexpected failures
                # revoke state as well as refusing the packet.
                self._flows.clear()
                self._dhcp.clear()
                self._counts[direction + '.dropped'] += 1
                self._counts['drop.internal_error'] += 1
                return False
            self._counts[direction + '.allowed'] += 1
            return True

    @staticmethod
    def _padding(data: bytes, expected: int) -> None:
        _require(len(data) == expected or (expected < 60 and expected <= len(data) <= 60), 'frame_length')

    def _arp(self, frame: bytes, outbound: bool, eth_dst: bytes) -> None:
        _require(len(frame) >= 42, 'arp_length')
        self._padding(frame, 42)
        htype, ptype, hlen, plen, op = struct.unpack_from('!HHBBH', frame, 14)
        _require((htype, ptype, hlen, plen) == (1, 0x0800, 6, 4) and op in (1, 2), 'arp_header')
        sha, spa, tha, tpa = frame[22:28], frame[28:32], frame[32:38], frame[38:42]
        _require(sha == (self.guest_mac if outbound else self.gateway_mac), 'arp_sender_mac')
        if outbound:
            if op == 1:
                # A unicast cache probe may fill THA with the known gateway.
                # This exception is NOT valid for broadcast or address probes.
                known_gateway = (spa == self.guest_ip and tpa == self.gateway_ip
                                 and tha == self.gateway_mac and eth_dst == self.gateway_mac)
                _require((tha == ZERO_MAC and eth_dst in (BROADCAST_MAC, self.gateway_mac))
                         or known_gateway, 'arp_request_target')
                # Address-conflict probe, gratuitous announcement, or gateway lookup.
                _require((spa == ZERO_IP and tpa == self.guest_ip and eth_dst == BROADCAST_MAC)
                         or (spa == self.guest_ip and tpa in (self.guest_ip, self.gateway_ip)
                             and (tpa != self.guest_ip or eth_dst == BROADCAST_MAC)), 'arp_addresses')
            else:
                normal = (spa == self.guest_ip and tpa == self.gateway_ip
                          and tha == self.gateway_mac and eth_dst == self.gateway_mac)
                gratuitous = (spa == tpa == self.guest_ip and eth_dst == BROADCAST_MAC
                              and tha in (self.guest_mac, BROADCAST_MAC))
                _require(normal or gratuitous, 'arp_addresses')
        else:
            _require(spa == self.gateway_ip, 'arp_gateway_ip')
            if op == 1:
                # Mirror the exact-identity unicast probe, never a broadcast
                # request carrying a nonzero target hardware address.
                known_guest = (tpa == self.guest_ip and tha == self.guest_mac
                               and eth_dst == self.guest_mac)
                _require((tha == ZERO_MAC and tpa in (self.guest_ip, self.gateway_ip))
                         or known_guest, 'arp_addresses')
                _require(tpa != self.gateway_ip or eth_dst == BROADCAST_MAC, 'arp_addresses')
            else:
                normal = tpa == self.guest_ip and tha == self.guest_mac and eth_dst == self.guest_mac
                gratuitous = (tpa == self.gateway_ip and eth_dst == BROADCAST_MAC
                              and tha in (self.gateway_mac, BROADCAST_MAC))
                _require(normal or gratuitous, 'arp_addresses')

    def _ipv4(self, frame: bytes) -> _Packet:
        _require(len(frame) >= 34, 'ipv4_length')
        ip = frame[14:]
        _require(ip[0] == 0x45, 'ipv4_version_options')
        total = struct.unpack_from('!H', ip, 2)[0]
        _require(20 <= total <= 1500 and len(ip) >= total, 'ipv4_length')
        self._padding(frame, total + 14)
        _require(_checksum(ip[:20]) == 0, 'ipv4_checksum')
        _require(struct.unpack_from('!H', ip, 6)[0] & 0xbfff == 0, 'ipv4_fragment')
        _require(ip[8] != 0, 'ipv4_ttl')
        proto, src, dst = ip[9], ip[12:16], ip[16:20]
        _require(proto in (6, 17), 'ip_protocol')
        segment = ip[20:total]
        _require(len(segment) >= (20 if proto == 6 else 8), 'transport_length')
        sport, dport = struct.unpack_from('!HH', segment)
        _require(sport != 0 and dport != 0, 'transport_port')
        pseudo = src + dst + struct.pack('!BBH', 0, proto, len(segment))
        if proto == 17:
            length, checksum = struct.unpack_from('!HH', segment, 4)
            _require(length == len(segment), 'udp_length')
            _require(checksum == 0 or _checksum(pseudo + segment) == 0, 'udp_checksum')
            return _Packet(src, dst, proto, sport, dport, 0, 0, 0, segment[8:])
        header_len = (segment[12] >> 4) * 4
        _require(20 <= header_len <= len(segment) and not segment[12] & 0x0e, 'tcp_header')
        _require(_checksum(pseudo + segment) == 0, 'tcp_checksum')
        flags = segment[13]
        _require(not (flags & SYN and flags & (FIN | RST)) and not (flags & FIN and flags & RST), 'tcp_flags')
        _require(bool(flags & (SYN | ACK | RST)), 'tcp_flags')
        payload = segment[header_len:]
        _require(not (flags & (SYN | RST) and payload), 'tcp_syn_rst_payload')
        offset = 20
        while offset < header_len:
            kind = segment[offset]
            if kind == 0:
                _require(all(b == 0 for b in segment[offset:header_len]), 'tcp_options')
                break
            if kind == 1:
                offset += 1
                continue
            _require(offset + 1 < header_len, 'tcp_options')
            size = segment[offset + 1]
            _require(size >= 2 and offset + size <= header_len, 'tcp_options')
            if kind in (2, 3, 4, 8):
                _require(size == {2: 4, 3: 3, 4: 2, 8: 10}[kind], 'tcp_options')
            if kind == 5:
                _require(size >= 10 and (size - 2) % 8 == 0, 'tcp_options')
            offset += size
        seq, ack = struct.unpack_from('!II', segment, 4)
        return _Packet(src, dst, proto, sport, dport, flags, seq, ack, payload)

    @staticmethod
    def _dhcp_fields(payload: bytes) -> tuple[int, int, dict[int, bytes]]:
        _require(len(payload) >= 241 and payload[236:240] == b'\x63\x82\x53\x63', 'dhcp_length_cookie')
        _require(payload[1:4] == b'\x01\x06\x00', 'dhcp_hardware')
        _require(struct.unpack_from('!H', payload, 10)[0] in (0, 0x8000), 'dhcp_flags')
        _require(payload[24:28] == ZERO_IP, 'dhcp_relay')
        options: dict[int, bytes] = {}
        pos = 240
        ended = False
        while pos < len(payload):
            code = payload[pos]
            pos += 1
            if code == 0:
                continue
            if code == 255:
                ended = True
                _require(all(b == 0 for b in payload[pos:]), 'dhcp_padding')
                break
            _require(pos < len(payload), 'dhcp_options')
            size = payload[pos]
            pos += 1
            _require(pos + size <= len(payload) and code not in options, 'dhcp_options')
            options[code] = payload[pos:pos + size]
            pos += size
        _require(ended and len(options.get(53, b'')) == 1, 'dhcp_message_type')
        # Option-overload hides additional options in BOOTP fields. It is not
        # needed for the pinned gvproxy configuration and is deliberately denied.
        _require(52 not in options, 'dhcp_overload')
        return struct.unpack_from('!I', payload, 4)[0], options[53][0], options

    def _handle_dhcp(self, p: _Packet, outbound: bool, eth_dst: bytes, now: float) -> None:
        xid, message, options = self._dhcp_fields(p.payload)
        _require(p.payload[28:34] == self.guest_mac, 'dhcp_client_mac')
        _require(p.payload[12:16] in (ZERO_IP, self.guest_ip), 'dhcp_client_ip')
        if outbound:
            _require((p.sport, p.dport) == (68, 67) and p.payload[0] == 1, 'dhcp_direction')
            _require(p.src in (ZERO_IP, self.guest_ip) and p.dst in (BROADCAST_IP, self.gateway_ip), 'dhcp_addresses')
            _require((p.dst == BROADCAST_IP and eth_dst == BROADCAST_MAC)
                     or (p.dst == self.gateway_ip and eth_dst == self.gateway_mac), 'dhcp_ethernet')
            _require(p.payload[16:24] == ZERO_IP * 2 and message in (1, 3), 'dhcp_request')
            _require(54 not in options or options[54] == self.gateway_ip, 'dhcp_server')
            # A previous network's requested-IP hint is not an assignment.
            # gvproxy always returns its pinned lease; enforce the actual lease
            # on replies, while allowing INIT-REBOOT to recover from old NAT.
            _require(50 not in options or len(options[50]) == 4, 'dhcp_requested_ip')
            self._prune(now, force=True)
            _require(xid in self._dhcp or len(self._dhcp) < self.max_dhcp_transactions, 'dhcp_cache_full')
            self._dhcp[xid] = _DHCP(now + self.dhcp_timeout, message)
        else:
            _require((p.sport, p.dport) == (67, 68) and p.payload[0] == 2, 'dhcp_direction')
            _require(p.src == self.gateway_ip and p.dst in (self.guest_ip, BROADCAST_IP), 'dhcp_addresses')
            _require((p.dst == BROADCAST_IP and eth_dst == BROADCAST_MAC)
                     or (p.dst == self.guest_ip and eth_dst == self.guest_mac), 'dhcp_ethernet')
            _require(p.payload[16:20] == self.guest_ip and p.payload[20:24] in (ZERO_IP, self.gateway_ip), 'dhcp_offer_ip')
            _require(options.get(54) == self.gateway_ip, 'dhcp_server')
            _require(1 not in options or options[1] == b'\xff\xff\xff\x00', 'dhcp_subnet')
            _require(3 not in options or options[3] == self.gateway_ip, 'dhcp_router')
            _require(6 not in options or options[6] == self.gateway_ip, 'dhcp_dns')
            _require(not any(code in options for code in (33, 121, 249)), 'dhcp_routes')
            transaction = self._dhcp.get(xid)
            _require(transaction is not None and transaction.expires > now, 'dhcp_unsolicited')
            _require((transaction.request_type, message) in ((1, 2), (3, 5)), 'dhcp_response_type')
            # Preserve briefly for retransmissions; replies never renew state.

    def _data(self, p: _Packet, outbound: bool, now: float) -> None:
        _require(p.sport != 53 and p.dport != 53, 'dns')
        peer, peer_port, local_port = ((p.dst, p.dport, p.sport) if outbound
                                      else (p.src, p.sport, p.dport))
        management = p.protocol == 6 and peer == self.gateway_ip and local_port == 22
        if management:
            _require(self._allow_management and 1024 <= peer_port <= 65535, 'management_disabled_or_port')
        else:
            _require((p.protocol, peer, peer_port) in self._endpoints, 'endpoint')
        key = (p.protocol, local_port, peer, peer_port)
        flow = self._flows.get(key)
        if flow is not None and flow.expires <= now:
            del self._flows[key]
            flow = None
        initiator = (not outbound) if management else outbound
        if flow is None:
            _require(initiator, 'unsolicited_reply')
            if p.protocol == 6:
                _require(bool(p.flags & SYN) and not p.flags & (ACK | FIN | RST), 'tcp_new_not_syn')
            self._prune(now, force=True)
            _require(len(self._flows) < self.max_flows, 'flow_cache_full')
            timeout = self.tcp_timeout if p.protocol == 6 else self.udp_timeout
            self._flows[key] = _Flow(management, now + timeout,
                                     'syn_sent' if p.protocol == 6 else 'udp', p.seq)
            return
        _require(flow.management == management, 'flow_kind')
        if p.protocol == 17:
            if initiator:
                flow.expires = now + self.udp_timeout
            return
        self._tcp(flow, p, initiator)
        if p.flags & RST:
            del self._flows[key]
        elif initiator:
            timeout = min(self.tcp_timeout, 30.0) if (flow.initiator_fin or flow.responder_fin) else self.tcp_timeout
            flow.expires = now + timeout

    @staticmethod
    def _tcp(flow: _Flow, p: _Packet, initiator: bool) -> None:
        syn, ack, rst = bool(p.flags & SYN), bool(p.flags & ACK), bool(p.flags & RST)
        initial_next = (flow.initiator_seq + 1) & 0xffffffff
        if flow.state == 'syn_sent':
            if initiator:
                _require(syn and not ack and p.seq == flow.initiator_seq, 'tcp_handshake')
            elif rst:
                _require(ack and p.ack == initial_next, 'tcp_reset')
            else:
                _require(syn and ack and p.ack == initial_next, 'tcp_handshake')
                flow.responder_seq = p.seq
                flow.state = 'syn_received'
            return
        if flow.state == 'syn_received':
            if rst:
                _require(ack, 'tcp_reset')
                return
            if initiator:
                if syn:
                    _require(not ack and p.seq == flow.initiator_seq, 'tcp_handshake')
                else:
                    _require(ack and not p.flags & FIN and p.seq == initial_next
                             and p.ack == ((flow.responder_seq + 1) & 0xffffffff), 'tcp_handshake')
                    flow.state = 'established'
            else:
                _require(syn and ack and p.seq == flow.responder_seq and p.ack == initial_next, 'tcp_handshake')
            return
        _require(flow.state == 'established', 'tcp_state')
        # Retransmitted SYN-ACK after a lost final ACK is harmless and necessary.
        if syn:
            _require(not initiator and ack and p.seq == flow.responder_seq and p.ack == initial_next, 'tcp_unexpected_syn')
            return
        _require(ack or rst, 'tcp_established_flags')
        if p.flags & FIN:
            if initiator:
                flow.initiator_fin = True
            else:
                flow.responder_fin = True
