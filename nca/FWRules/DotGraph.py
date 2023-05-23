#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from dataclasses import dataclass
from enum import Enum
import string
import ast


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

        self.node_tooltip = \
            {self.NodeType.IPBlock: 'IP Block',
             self.NodeType.Pod: 'Workload',
             self.NodeType.Livesim: 'Automatically added workload',
             self.NodeType.Clique: 'Traffic allowed between any two workloads connected to the CLIQUE:\n',
             self.NodeType.BiClique:
                 'Traffic allowed from any source workload of the BICLIQUE to any of its destination workloads:\n',
             self.NodeType.MultiPod: 'A set of workloads having exactly the same connectivity',
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

        output_result += '\tlabelloc = "t"\n'
        if self._set_labels_dict():
            output_result += self._labels_dict_to_str()
        self.subgraphs = dict(sorted(self.subgraphs.items()))
        output_result += ''.join([self._subgraph_to_str(subgraph) for subgraph in self.subgraphs.values()])
        output_result += ''.join(sorted([self._edge_to_str(edge) for edge in self.edges]))
        output_result += '\tcolor=white\n'
        output_result += self._explanation_to_str()
        output_result += '\tfontsize=15\n'
        output_result += '\tfontcolor=maroon\n'
        output_result += '}\n'
        return output_result

    @staticmethod
    def _explanation_to_str():
        """
        creates a string in dot format of the explanation label
        """
        explanation = ['Application connectivity graph',
                       ' ',
                       ' ',
                       ]
        explanation_table = '<<table border="0" cellspacing="0">'
        for line in explanation:
            explanation_table += f'<tr><td align="text" >{line} <br align="left" /></td></tr>'
        explanation_table += '</table>>\n'

        return f'\tlabel={explanation_table}'

    def _labels_dict_to_str(self):
        """
        creates a string for the label dict in a dot file format
        return str: the string
        """
        if not self.labels_dict:
            return ''
        items_to_present = [(short, label) for label, short in self.labels_dict.items()]
        items_to_present.sort()

        dict_table = '<<table border="0" cellspacing="0">'
        dict_table += '<tr><td  align="text">Connectivity legend<br align="left" /></td></tr>'
        for short, label in items_to_present:
            trimmed = f'{label[0:30]}...' if len(label) > 32 else label
            line = f'{short}     {trimmed}'
            dict_table += f'<tr><td align="text" tooltip="{label}" href="bogus">{line}<br align="left" /></td></tr>'
        dict_table += '</table>>'

        dict_table = f'label={dict_table}'
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
            output_result += '\ttooltip="Namespace"\n'
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
            border = '1' if node.node_type == self.NodeType.MultiPod else '0'
            table = f'<<table border="{border}" cellspacing="0">'
            for line in node.label:
                if line:
                    table += f'<tr><td>{line}</td></tr>'
            table += '</table>>'
            label = f'label={table}'
            node_desc = f'{label} {self.node_styles[node.node_type]} tooltip=\"{self.node_tooltip[node.node_type]}\"'
        else:
            node_desc = f'{self.node_styles[node.node_type]}  xlabel=\"{self.labels_dict[node.label[0]]}\" ' \
                   f'tooltip=\"{self.node_tooltip[node.node_type]}{node.label[0]}\"'
        return f'\t\"{node.name}\" [{node_desc}]\n'

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
        arrow_type = f'dir=both arrowhead={dst_type} arrowtail={src_type}'
        label = f'label=\"{self.labels_dict[str(edge.label)]}\"' if not is_clq_edge and not is_biclq_edge else ''
        tooltip = f'labeltooltip=\"{edge.label}\"' if not is_clq_edge and not is_biclq_edge else ''
        line = f'\t\"{edge.src.name}\" -> \"{edge.dst.name}\"'
        line += f'[{label} {tooltip} color={edge_color} fontcolor=darkgreen {arrow_type}]\n'
        return line

    def _set_labels_dict(self):
        """
        creates a dict of label -> to label_short
        in the dot graph we uses the label_short to label edges, so graph gets smaller.
        """
        if not self.labels:
            return False
        if len(self.labels) == 1 and len(next(iter(self.labels))) <= 11:
            self.labels_dict = {label: label for label in self.labels}
            return False

        labels_short = {}
        # for each label, the short will look like "tcp<port>" if there is a port, or "TCP" if there is no port
        for label in self.labels:
            splitted_label = label.split(' ', 1)
            label_type = splitted_label.pop(0)
            label_port = splitted_label[0] if splitted_label else ''
            if label_port.startswith('{'):
                # it is not a port, its a list of dict, a dict can have 'dst_ports'
                # we will use only one 'dst_ports':
                connections = ast.literal_eval(f'[{label_port}]')
                ports = [conn['dst_ports'] for conn in connections if 'dst_ports' in conn.keys()]
                label_port = ports[0] if ports else ''
            # a 'dst_ports' can be too long (like 'port0,port1-port2' ) we trim it to the first port:
            if len(label_port) > 6:
                label_port = label_port.split(',')[0].split('-')[0]
            labels_short[label] = f'{label_type.lower()}{label_port}' if label_port else label_type

        # for labels sharing the same short, we will add a letter to the end of the short:
        for short in set(labels_short.values()):
            short_labels = [label for label, l_short in labels_short.items() if l_short == short]

            # we want sort the labels before giving each label an extention:
            short_labels.sort()
            if len(short_labels) == 1:
                self.labels_dict[short_labels[0]] = short
            elif len(short_labels) < len(string.ascii_lowercase):
                for label in short_labels:
                    self.labels_dict[label] = f'{short}{string.ascii_lowercase[short_labels.index(label)]}'
            else:
                for label in short_labels:
                    self.labels_dict[label] = f'{short}_{short_labels.index(label)}'

        return True
