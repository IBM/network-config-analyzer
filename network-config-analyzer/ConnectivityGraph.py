from collections import defaultdict
from ConnectionSet import ConnectionSet
from Peer import Peer


class ConnectivityGraph:
    """
    Represents a connectivity digraph, that is a set of labeled edges, where the nodes are peers and
    the labels on the edges are the allowed connections between two peers.
    """
    def __init__(self):
        self.connections_to_peers = defaultdict(list)

    def add_edge(self, source_peer, dest_peer, connections):
        """
        Adding a labeled edge to the graph
        :param Peer source_peer: The source peer
        :param Peer dest_peer: The dest peer
        :param ConnectionSet connections: The allowed connections from source_peer to dest_peer
        :return: None
        """
        self.connections_to_peers[connections].append((source_peer, dest_peer))

    def output_as_firewall_rules(self):
        """
        Prints the graph as a set of firewall rules
        :return: None
        """
        connections_sorted_by_size = [(conn, peer_pair) for conn,peer_pair in self.connections_to_peers.items()]
        connections_sorted_by_size.sort(reverse=True)

        for connections, peer_pairs in connections_sorted_by_size:
            for src_peer, dst_peer in  peer_pairs:
                print(f'src: {src_peer}, dest: {dst_peer}, allowed conns: {connections}')
