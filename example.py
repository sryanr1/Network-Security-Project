#!/usr/bin/env python3
#
# example.py
# Network Security Project
#
# This file implements an example of how to use the PeerCom system to
# communicate with other peers on the network.
#
# This file is released under a BSD license.  See license.txt for details.

import pex
import threading
import time

class PollThread(threading.Thread):
    '''This thread helps to poll a given swarm node so that it can perform
    delayed network operations.'''
    
    def __init__(self, swarmNode, nodeLock):
        threading.Thread.__init__(self)
        
        self._swarmNode = swarmNode
        self._nodeLock = nodeLock
        self._running = True
        
    def run(self):
        while self._running:
            with self._nodeLock:
                self._swarmNode.poll()
            time.sleep(0.01)
            
    def stop(self):
        self._running = False

def printHelp():
    'Show a list of valid commands for the prompt.'
    
    print('Valid commands:')
    print('  h - Show this dialog')
    print('  l - List all known peers')
    print('  m <peer> <message> - Send a message to the given peer')
    print('  a <peer> - Add a new peer to the list of peers')
    print('  q - Quit this program')
    
def parseAddress(desc):
    '''This parses an IP address/port combination from a description string.  It
    is expected that the string is specified by a host name and a port,
    separated by a colon.  On failure, this will return False, instead of a
    tuple of (hostname, port).'''
    
    parts = desc.split(':')
    if len(parts) != 2:
        return False
    
    try:
        return (parts[0].strip(), int(parts[1]))
    except ValueError:
        return False
    
def handleMessageCommand(node, cmd):
    
    # Make sure command is long enough
    if not cmd.startswith('m '):
        print('Invalid send message command')
        return
    
    # Parse out peer and add to list
    cmd = cmd[2:]
    splitInd = cmd.find(' ')
    if splitInd <= 0 or splitInd + 1 >= len(cmd):
        print('Invalid send message command')
        return
    
    # Get peer description and message
    peerDesc = cmd[:splitInd]
    message = cmd[splitInd + 1:].strip()
    
    # Now send the message
    try:
        node.sendMessage(peerDesc, message)
        print('Sent message')
    except MalformedPeerIdException:
        print('"%s" does not specify a valid peer' % peerDesc)

def handleAddPeerCommand(node, cmd):
    
    # Make sure command is long enough
    if not cmd.startswith('a '):
        print('Invalid add peer command')
        return
    
    # Parse out peer and add to list
    desc = cmd[2:].strip()
    peerAddr = parsePeer(desc)
    if peerAddr:
        node.addPeer(*peerAddr)
        print('Added peer "%s"' % desc)
    else:
        print('"%s" does not specify a valid peer' % desc)

def printPeers(node):
    'Print all the peers connected to our node.'
    
    if len(node.knownPeers) > 0:
        for peer in node.knownPeers:
            print(peer)
    else:
        print('No peers connected')

# Create the Node instance
print('Enter command or "h" for help')
node = pex.PexNode()

# Create polling thread and lock
nodeLock = threading.Lock()
pollThread = PollThread(node, nodeLock)
pollThread.start();

# Main prompting loop
while True:
    
    # Try to get input
    try:
        cmd = input('Command: ').strip()
    except EOFError:
        print()
        break
    
    # Respond to command
    with nodeLock:
        if cmd == 'h':
            printHelp()
        elif cmd == 'l':
            printPeers(node)
        elif cmd.startswith('m'):
            handleMessageCommand(node, cmd)
        elif cmd.startswith('a'):
            handleAddPeerCommand(node, cmd)
        elif cmd == 'q':
            break
        else:
            print('Unrecognized command "%s"' % cmd)
    
# Clean up and exit
print('Exiting program')
pollThread.stop()
pollThread.join()
