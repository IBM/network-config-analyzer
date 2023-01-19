#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re


class DotGraph:

    class Subgraph:
        def __init__(self, name):
            self.name = name
            self.nodes = []

    class Node:
        def __init__(self, name, node_type, label):
            self.name = name
            self.node_type = node_type
            self.label = label

    class Edge:
        def __init__(self, src, dst, label, is_dir):
            self.src = src
            self.dst = dst
            self.label = label
            self.is_dir = is_dir

    def __init__(self, name):
        self.subgraphs = {}
        self.name = name
        self.edges = []
        self.all_nodes = {}
        self.labels = []
        self.labels_dict = {}
        self.node_styles = {'ip_block': 'shape=plaintext style=filled fontcolor=red2',
                            'pod': 'shape=plaintext style=filled fontcolor=blue',
                            'clq': 'shape=circle fontcolor = purple color=purple width=0.2 height=0.2 label=\"\"',
                            }

    def add_node(self, subgraph, name, node_type, label):
        if subgraph not in self.subgraphs.keys():
            self.subgraphs[subgraph] = self.Subgraph(subgraph)
        node = self.Node(name, node_type, label)
        self.subgraphs[subgraph].nodes.append(node)
        self.all_nodes[name] = node
        if node_type == 'clq':
            self.labels.append(label[0])

    def add_edge(self, src_name, dst_name, label, is_dir):
        src_node = self.all_nodes[src_name]
        dst_node = self.all_nodes[dst_name]
        self.edges.append(self.Edge(src_node, dst_node, label, is_dir))
        self.labels.append(label)

    def to_str(self):
        self._set_labels_dict()
        output_result = f'// The Connectivity Graph of {self.name}\n'
        output_result += 'digraph ' + '{\n'

        output_result += f'label=\"Connectivity Graph of {self.name}\"'
        output_result += ' labelloc = "t"\n'
        output_result += ' fontsize=30 \n'
        output_result += ' fontcolor=webmaroon\n'
        output_result += self._labels_dict_to_str()
        output_result += ''.join([self._subgraph_to_str(subgraph) for subgraph in self.subgraphs.values()])
        output_result += ''.join([self._edge_to_str(edge) for edge in self.edges])
        output_result += '}\n'
        return output_result

    def _labels_dict_to_str(self):
        dict_table = 'label=<<table align="left" border="0" cellspacing="0">'
        dict_table += f'<tr><td><b>communication shortcuts:</b></td> </tr>'
        for label, key in self.labels_dict.items():
            dict_table += f'<tr><td><b>{key}</b></td> <td><b>{label}</b></td> </tr>'
        dict_table += f'</table>>'
        return f'dict_box [{dict_table} shape=box]\n'

    def _subgraph_to_str(self, subgraph):
        output_result = ''
        if subgraph.name:
            nc_diag_name = str(subgraph.name).replace('-', '_')
            output_result += f'subgraph cluster_{nc_diag_name}_namespace'+'{\n'
            output_result += f'label=<<b>{subgraph.name}</b>>\n'
            output_result += ' fontsize=20 \n'
            output_result += ' fontcolor=green \n'
        nodes_lines = set()
        for node in subgraph.nodes:
            nodes_lines.add(self._node_to_str(node))
        output_result += ''.join(line for line in sorted(list(nodes_lines)))
        if subgraph.name:
            output_result += '}\n'
        return output_result

    def _node_to_str(self, node):
        if node.node_type != 'clq':
            table = '<<table border="0" cellspacing="0">'
            for line in node.label:
                if line:
                    table += f'<tr><td><b>{line}</b></td></tr>'
            table += f'</table>>'
            label = f'label={table}'
            return f'\t\"{node.name}\" [{label} {self.node_styles[node.node_type]}]\n'
        else:
            return f'\"{node.name}\" [{self.node_styles[node.node_type]}  xlabel={self.labels_dict[node.label[0]]}]\n'

    def _edge_to_str(self, edge):
        is_clq_edge = 'clq' in [edge.src.node_type, edge.dst.node_type]
        edge_color = 'purple' if is_clq_edge else 'gold2' if edge.is_dir else 'red2'
        src_type = 'normal' if is_clq_edge and edge.src.node_type != 'clq' else 'none'
        dst_type = 'normal' if edge.dst.node_type != 'clq' else 'none'
        label = f'label=\"{self.labels_dict[str(edge.label)]}\"' if not is_clq_edge else ''

        line = f'\"{edge.src.name}\" -> \"{edge.dst.name}\"'
        line += f'[{label} color={edge_color} fontcolor=darkgreen dir=both arrowhead={dst_type} arrowtail={src_type}]\n'
        return line

    def _set_labels_dict(self):
        for label in self.labels:
            self.labels_dict[label] = re.findall(r"[\w']+", label)[0][0:3]
        for short in set(self.labels_dict.values()):
            labels_short = [label for label in self.labels_dict.keys() if self.labels_dict[label] == short]
            if len(labels_short) > 1:
                for label in labels_short:
                    self.labels_dict[label] = f'{short}_{labels_short.index(label)}'
