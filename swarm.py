# swarm.py
# Network Security Project
#
# This file implements the interface for the base swarm level of the system.
#
# This file is released under a BSD license.  See license.txt for details.

class MalformedPeerIdException(Exception):
    'An exception for when a poorly formed peer ID is provided.'
    
    def __init__(self, badPeerId):
        Exception.__init__(self, 'Malformed peer ID: %s' % badPeerId)
class InaccessiblePeerException(Exception):
    'Thrown when the peer with the given ID cannot be contacted.'
    
    def __init__(self, peerId):
        Exception.__init__(self, 'Cannot send message to peer %s' % peerId)

class SwarmNode:
    'A base class for a node belonging to a type of swarm peer-to-peer network.'
    
    @property
    def knownPeers(self):
        raise NotImplementedError('A subclass must implement knownPeers')