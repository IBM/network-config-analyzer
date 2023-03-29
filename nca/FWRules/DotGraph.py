#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re
from dataclasses import dataclass
from enum import Enum


class DotGraph:
    """
    represents a dot graph
    """
    class NodeType(Enum):
        IPBlock = 0
        Pod = 1
        Livesim = 2
        Clique = 3
        BiClique = 4
        MultiPod = 5

    class Subgraph:
        def __init__(self, name):
            self.name = name
            self.nodes = []

    @dataclass
    class Node:
        name: str
        node_type: int
        label: str

    @dataclass
    class Edge:
        src: str
        dst: str
        label: str
        is_dir: bool

    def __init__(self, name):
        self.subgraphs = {}
        self.name = name
        self.edges = []
        self.all_nodes = {}
        self.labels = set()
        self.labels_dict = {}
        self.node_styles = \
            {self.NodeType.IPBlock: 'shape=box fontcolor=red2',
             self.NodeType.Pod: 'shape=box fontcolor=blue',
             self.NodeType.Livesim: 'shape=box fontcolor=magenta',
             self.NodeType.Clique:
                 'shape=egg fontcolor=indigo color=indigo width=0.2 height=0.2 label=clq fontsize=10 margin=0',
             self.NodeType.BiClique: 'shape=box fontcolor=red color=red width=0.3 height=0.1 label=biclq fontsize=10 margin=0',
             self.NodeType.MultiPod: 'shape=box color=blue4',
             }

    def add_node(self, subgraph, name, node_type, label):
        """
        add a node to the graph
        param subgraph: subgraph name
        param name: node name
        param node_type: node type
        param label: node label
        """
        label = [tok.strip() for tok in label if tok != '']
        if subgraph not in self.subgraphs:
            self.subgraphs[subgraph] = self.Subgraph(subgraph)
        node = self.Node(name, node_type, label)
        self.subgraphs[subgraph].nodes.append(node)
        self.all_nodes[name] = node
        if node_type in {self.NodeType.Clique, self.NodeType.BiClique}:
            self.labels.add(label[0])

    def add_edge(self, src_name, dst_name, label, is_dir):
        """
        add a edge to the graph
        param src_name: src node name
        param dst_name: dst node name
        param label: edge label
        is_dir: is directed edge
        """
        label = label.strip()
        src_node = self.all_nodes[src_name]
        dst_node = self.all_nodes[dst_name]
        self.edges.append(self.Edge(src_node, dst_node, label, is_dir))
        self.labels.add(label)

    def to_str(self):
        """
        creates a string in a dot file format
        return str: the string
        """
        output_result = f'// The Connectivity Graph of {self.name}\n'
        output_result += 'digraph ' + '{\n'

        output_result += f'\tlabel=\"Connectivity Graph of {self.name}\"'
        output_result += '\tlabelloc = "t"\n'
        output_result += '\tfontsize=30\n'
        output_result += '\tfontcolor=maroon\n'
        if self._set_labels_dict():
            output_result += self._labels_dict_to_str()
        self.subgraphs = dict(sorted(self.subgraphs.items()))
        output_result += ''.join([self._subgraph_to_str(subgraph) for subgraph in self.subgraphs.values()])
        output_result += ''.join(sorted([self._edge_to_str(edge) for edge in self.edges]))
        output_result += '}\n'
        return output_result

    def _labels_dict_to_str(self):
        """
        creates a string for the label dict in a dot file format
        return str: the string
        """
        if not self.labels_dict:
            return ''
        items_to_present = [(short, label) for label, short in self.labels_dict.items() if label != short]
        items_to_present.sort()
        dict_table = '\\l'.join([f'{short:<15}{label}' for short, label in items_to_present])
        dict_table = f'label=\"Connectivity legend\\l{dict_table}\\l\"'
        return f'\tdict_box [{dict_table} shape=box]\n'

    def _subgraph_to_str(self, subgraph):
        """
        creates a string for the subgraph in a dot file format
        return str: the string
        """
        output_result = ''
        if subgraph.name:
            nc_diag_name = str(subgraph.name).replace('-', '_')
            output_result += f'subgraph cluster_{nc_diag_name}_namespace' + '{\n'
            output_result += f'\tlabel=\"{subgraph.name}\"\n'
            output_result += '\tfontsize=20\n'
            output_result += '\tfontcolor=blue\n'
        nodes_lines = set()
        for node in subgraph.nodes:
            nodes_lines.add(self._node_to_str(node))
        output_result += ''.join(line for line in sorted(list(nodes_lines)))
        if subgraph.name:
            output_result += '}\n'
        return output_result

    def _node_to_str(self, node):
        """
        creates a string for the node in a dot file format
        return str: the string
        """
        if node.node_type not in {self.NodeType.Clique, self.NodeType.BiClique}:
            border = '2' if node.node_type == self.NodeType.MultiPod else '0'
            table = f'<<table border="{border}" cellspacing="0">'
            for line in node.label:
                if line:
                    table += f'<tr><td>{line}</td></tr>'
            table += '</table>>'
            label = f'label={table}'
            return f'\t\"{node.name}\" [{label} {self.node_styles[node.node_type]}]\n'
        else:
            return f'\t\"{node.name}\" [{self.node_styles[node.node_type]}  xlabel=\"{self.labels_dict[node.label[0]]}\"]\n'

    def _edge_to_str(self, edge):
        """
        creates a string for the edge in a dot file format
        return str: the string
        """
        is_clq_edge = self.NodeType.Clique in [edge.src.node_type, edge.dst.node_type]
        is_biclq_edge = self.NodeType.BiClique in [edge.src.node_type, edge.dst.node_type]
        edge_color = 'indigo' if is_clq_edge else 'red' if is_biclq_edge else 'darkorange4'
        src_type = 'normal' if not is_clq_edge and not edge.is_dir else 'none'
        dst_type = 'normal' if not is_clq_edge else 'none'
        label = f'label=\"{self.labels_dict[str(edge.label)]}\"' if not is_clq_edge and not is_biclq_edge else ''

        line = f'\t\"{edge.src.name}\" -> \"{edge.dst.name}\"'
        line += f'[{label} color={edge_color} fontcolor=darkgreen dir=both arrowhead={dst_type} arrowtail={src_type}]\n'
        return line

    def _set_labels_dict(self):
        """
        creates a dict of label -> to label_short
        in the dot graph we uses the label_short to label edges, so graph gets smaller.
        """
        if not self.labels:
            return False
        if len(max(self.labels, key=len)) <= 11:
            self.labels_dict = {label: label for label in self.labels}
            return False

        labels_tokens = {}
        for label in self.labels:
            # todo - we might need a better approach splitting the labels to tokens
            # we should revisit this code after reformatting connections labels
            labels_tokens[label] = re.findall(r"[\w']+", label)
        first_tokens = set(t[0] for t in labels_tokens.values())
        for first_token in first_tokens:
            token_labels = [label for label, tokens in labels_tokens.items() if tokens[0] == first_token]
            if len(token_labels) == 1:
                self.labels_dict[token_labels[0]] = first_token
            else:
                one_token_labels = [label for label in token_labels if labels_tokens[label] == [first_token]]
                if len(one_token_labels) == 1:
                    self.labels_dict[one_token_labels[0]] = first_token
                    token_labels.remove(one_token_labels[0])

                # we want sort the labels before giving each label its index:
                token_labels.sort()
                for label in token_labels:
                    self.labels_dict[label] = f'{first_token}_{token_labels.index(label)}'
                    # todo - maybe put another token instead of the index
                    # we should revisit this code after reformatting connections labels
        return True
