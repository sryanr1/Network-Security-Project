# pex.py
# Network Security Project
#
# This file implements utilities for a Peer-EXchange based peer-to-peer swarm
# network.  Most useful is probably the PexNode, which implements a single node
# on such a network.
#
# This file is released under a BSD license.  See license.txt for details.

import swarm
import time
import hashlib
import struct
import socket

# The number of seconds between broadcasts, if enabled
_BROADCAST_INTERVAL = 2

# The maximum length of a sending/receiving buffer
_PACKET_BUFSIZE = 1024

# The magic bytes at the beginning of every packet
_MAGIC_BYTES = b'seth'

# The size of the packet header in bytes
_PACKET_HEADER_SIZE = len(_MAGIC_BYTES) + 3

# Constants for different packet types
_PACKET_TYPE_MESSAGE = 0
_PACKET_TYPE_ACK = 1
_PACKET_TYPE_PING = 2
_PACKET_TYPE_PEX = 3
_MAX_PACKET_TYPE = 3

# How long the sender should wait before retransmitting each time
_TIMEOUT_LENGTHS = [0.01, 0.1, 1, 10]

def _addrToPeerId(ip, port):
    'Convert an IP address/port combo to the matching peer ID.'
    
    # Give the sha256 sum of the string <ip>:<port>
    s = hashlib.sha256()
    s.update(bytearray(ip, 'ascii'))
    s.update(b":")
    s.update(bytearray(str(port), 'ascii'))
    return s.hexdigest()

def _sanitizePeerId(peerId):
    '''Convert the given peer ID into a lower case string, checking it for
    sanity at the same time.'''
    
    # Make sure ID is of the right length
    if len(peerId) != 64:
        return False
    
    # Convert to lower case string
    peerId = str(peerId).tolower()
    
    # Now make sure all characters are valid
    for char in peerId:
        if not ('a' <= char <= 'f' or '0' <= char <= '9'):
            return False
    return True

def _unpackPacketHeader(packet):
    '''This returns either a tuple of the type of packet, the ID of the packet,
    and the payload of the packet or False if the packet was not valid.'''
    
    # Check magic value
    if len(packet) < _PACKET_HEADER_SIZE or not packet.startswith(_MAGIC_BYTES):
        return False
    
    # Unpack values
    packType, packId = struct.unpack('!BH', packet[4:7])
    
    # Check if values are acceptable
    if packType > _MAX_PACKET_TYPE:
        return False
    else:
        return (packType, packId, packet[_PACKET_HEADER_SIZE:])

def _packPacket(packetType, packetId, payload):
    'Pack the given payload in a packet with the specified type and identifier.'
    
    # Make sure the payload fits in the packet
    if len(payload) > _PACKET_BUFSIZE - _PACKET_HEADER_SIZE:
        
        # TODO Make the packet automatically fragment later
        raise Exception('Packet payload too long!')
    
    # Return the encapsulated payload
    header = struct.pack('!BH', packetType, packetId)
    return _MAGIC_BYTES + header + payload

class _PeerRecord:
    'A description of a peer that this node knows about.'
    
    def __init__(self, identifier, address):
        self.identifier = identifier
        self.address = address
        self.nextPacketId = 0
        self.lastActivityTime = time.clock()
        
    def touch(self):
        self.lastActivityTime = time.clock()
        
    def generateNextPacketId(self):
        packetId = self.nextPacketId
        self.nextPacketId = (self.nextPacketId + 1) % 65536
        return packetId

class PexNode(swarm.SwarmNode):
    '''This class implements a node in a swarm network that exchanges peers via
    a peer exchange protocol.'''
    
    def __init__(self, ip = '0.0.0.0', port = 4141, broadcast = True):
        '''Create a new peer-exchange based node in the swarm network.  The node
        will bind to the given ip and port on the local machine.  If broadcast
        is True, then this node will broadcast ping packets to find neighbors on
        the same local network on the same port.'''
        
        # Initialize properties
        self.broadcast = broadcast
        
        # Initialize other members
        self._lastBroadcastTime = time.clock() - _BROADCAST_INTERVAL
        self._peers = {}
        self._unackedMessages = []
        self._port = port
        
        # Create socket and bind local machine
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(False)
        self._sock = sock
    
    def __del__(self):
        
        # Close out socket
        self._sock.close()
    
    def _handlePacket(self, peerAddr, packetType, packetId, payload):
        'Process a packet given its type, ID, and payload.'
        
        peerId = _addrToPeerId(*peerAddr)
        if packetType == _PACKET_TYPE_MESSAGE:
            message = result[2]
            self.receiveCallback(self, peerId, message)

        elif packetType == _PACKET_TYPE_ACK:
            pass
        
        elif packetType == _PACKET_TYPE_PING:
            
            # Ack the message
            ackPacket = _packPacket(_PACKET_TYPE_ACK, packetId)
            self._sock.sendto(ackPacket, peerAddr)
            
        elif packetType == _PACKET_TYPE_PEX:
            pass
        
        else:
            raise ValueError("Invalid packet type %d detected!" % packetType)
        
        # Add the peer if it is not in our records
        if peerId not in self._peers:
            _peers[peerId] = _PeerRecord(peerId, peerAddr)
    
    def poll(self):
        
        # Do broadcast if necessary
        curTime = time.clock()
        if self.broadcast and self._lastBroadcastTime < curTime - 2:
            self._lastBroadcastTime = curTime
            broadcastPkt = _packPacket(_PACKET_TYPE_PING, 0, b'')
            self._sock.sendto(broadcastPkt, ('<broadcast>', self._port))
        
        # Get input messages
        while True:
            try:
                
                # Try to read packet from port
                packet, peerAddr = self._sock.recvfrom(_PACKET_BUFSIZE)
                
                # Handle message if it is valid
                result = _unpackPacketHeader(packet)
                if result:
                    _handlePacket(peerAddr, result[0], result[1], result[2])
            except BlockingIOError:
                break
        
        # Resend unacked messages
        for msg in self._unackedMessages:
            pass
        
    def addPeer(self, ip, port):

        # Generate the peer ID and add the peer record
        peerId = _addrToPeerId(ip, port)
        if peerId not in self._peers:
            
            # Create peer record to insert later
            peerRecord = _PeerRecord(peerId, (ip, port))
            
            # Send ping packet
            pktId = peerRecord.generateNextPacketId()
            pingPkt = _packPacket(_PACKET_TYPE_PING, pktId, b'')
            self._sock.sendto(pingPkt, peerRecord.address)
            
            # Store peer record if we got here
            self._peers[peerId] = peerRecord
    
    def sendMessage(self, peerId, message):
        
        # Send to known peer if possible
        peerId = _sanitizePeerId(peerId)
        if peerId in self._peers:
            peerRecord = self._peers[peerId]
            pktId = peerRecord.generateNextPacketId()
            msgPacket = _packPacket(_PACKET_TYPE_MESSAGE, pktId, message)
            self._sock.sendto(msgPacket, peerRecord.address)
        else:
            raise InaccessiblePeerException(peerId)
    
    @property
    def knownPeers(self):
        return self._peers.keys()
