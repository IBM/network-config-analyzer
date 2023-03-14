import sys

import networkx
from bs4 import BeautifulSoup
import os
import shutil
import itertools
import copy
from collections import defaultdict
from dataclasses import dataclass, field

# Tags Attributes:
CLASS_TA = 'class'
ID_TA = 'id'
TITLE_TA = 'title'
CONNECTIVITY_TA = 'connectivity'

# Class types
GRAPH_CT = 'graph'
LEGEND_MISC_CT = 'conn_legend_misc'
BACKGROUND_CT = 'background'
NAMESPACE_CT = 'cluster'
NODE_CT = 'node'
EDGE_CT = 'edge'
CONNECTIVITY_CT = 'connectivity'




class InteractiveConnectivityGraph:

    class SvgEditor:
        def __init__(self, input_svg_file, output_directory):
            self.input_svg_file = input_svg_file
            self.output_directory = output_directory
            self.soup = None

        def read_input_file(self):
            with open(file_name) as cvg_file:
                self.soup = BeautifulSoup(cvg_file.read(), 'xml')


        def set_tags_info(self):
            # wrap the title + background polygon with an <a>:
            graph_polygon = self.soup.svg.polygon
            graph_polygon = graph_polygon.wrap(self.soup.new_tag('a'))
            graph_polygon[CLASS_TA] = BACKGROUND_CT
            graph_text = self.soup.svg.find('text')
            graph_polygon.append(graph_text)

            # update class to connectivities:
            conn_legend = self.soup.svg.find('title', string='dict_box')
            if conn_legend:
                conn_legend = conn_legend.find_parent('g')
                conn_legend[CLASS_TA] = LEGEND_MISC_CT
                for conn in conn_legend.find_all('a'):
                    conn[CLASS_TA] = CONNECTIVITY_CT
                for conn in conn_legend.find_all('g'):
                    conn[CLASS_TA] = LEGEND_MISC_CT


            # for element that we want to add a link, we replace <g> with <a>:
            for tag in self.soup.svg.find_all('g'):
                if tag[CLASS_TA] not in [GRAPH_CT, LEGEND_MISC_CT]:
                    tag.name = 'a'

            # add missing id and titles:
            for tag in self.soup.svg.find_all('a'):
                if tag[CLASS_TA] == BACKGROUND_CT:
                    tag[ID_TA] = 'index'
                    tag[TITLE_TA] = tag.find('text').string
                elif tag[CLASS_TA] == CONNECTIVITY_CT:
                    short = tag.text.split()[0]
                    conn_id = 'conn_' + short
                    tag[ID_TA] = conn_id
                    tag[TITLE_TA] = short
                else:
                    tag[TITLE_TA] = tag.title.string

                # 3. set connectivity:
                if tag[CLASS_TA] == EDGE_CT and tag.find('text'):
                    tag[CONNECTIVITY_TA] = tag.find('text').string
                elif tag[CLASS_TA] == NODE_CT and tag.title and 'clique' in tag.title.string:
                    tag[CONNECTIVITY_TA] = tag.find_all('text')[1].string
                elif tag[CLASS_TA] == CONNECTIVITY_CT:
                    tag[CONNECTIVITY_TA] = tag[TITLE_TA]


        @staticmethod
        def get_tag_info(tag):
            t_id = tag[ID_TA]
            t_class = tag[CLASS_TA]
            t_title = tag[TITLE_TA]
            t_conn = tag.get(CONNECTIVITY_TA) if tag.get(CONNECTIVITY_TA) else ''
            return t_id, t_class, str(t_title), t_conn


        def get_tags_info(self):
            return [(self.get_tag_info(tag)) for tag in self.soup.svg.find_all('a')]


        def create_output(self, relations, highlights):
            if os.path.isdir(self.output_directory):
                shutil.rmtree(self.output_directory)
            os.mkdir(self.output_directory)
            os.mkdir(os.path.join(self.output_directory, 'elements'))
            for tag in self.soup.svg.find_all('a'):
                t_id, t_class, _, _ = self.get_tag_info(tag)
                if t_class == BACKGROUND_CT:
                    tag_file_name = os.path.join(self.output_directory, t_id + '.svg')
                else:
                    tag_file_name = os.path.join(self.output_directory, 'elements', t_id + '.svg')
                tag_soup = copy.copy(self.soup)
                ids = relations[t_id]
                for tag2 in tag_soup.svg.find_all('a'):
                    t_id2, t_class2, _, _ = self.get_tag_info(tag2)
                    if t_id2 not in ids:
                        tag2.extract()
                        continue
                    if (t_class == BACKGROUND_CT and t_class2 == BACKGROUND_CT) or (t_class != BACKGROUND_CT and t_class2 != BACKGROUND_CT):
                        tag2['xlink:href'] = t_id2 + '.svg'
                    elif t_class == BACKGROUND_CT and t_class2 != BACKGROUND_CT:
                        tag2['xlink:href'] = 'elements/' + t_id2 + '.svg'
                    else:
                        tag2['xlink:href'] = '../' + t_id2 + '.svg'

                    if t_id2 in highlights[t_id]:
                        if t_class2 == NODE_CT:
                            tag2.polygon['stroke-width'] = '5'
                        if t_class2 == NAMESPACE_CT:
                            tag2.polygon['stroke-width'] = '5'
                            tag2['font-weight'] = 'bold'
                        if t_class2 == EDGE_CT:
                            tag2.path['stroke-width'] = '3'
                            tag2['font-weight'] = 'bold'
                        if t_class2 == CONNECTIVITY_CT:
                            tag2['text-decoration'] = 'underline'
                            tag2['font-weight'] = 'bold'
                with open(tag_file_name, 'wb') as tag_cvg_file:
                    tag_cvg_file.write(tag_soup.prettify(encoding='utf-8'))


    class GraphRelations:

        @dataclass
        class ConnLegend:
            conns: dict = field(default_factory=dict)

        @dataclass(unsafe_hash=True)
        class Conn:
            t_id: str = ''

        @dataclass
        class Namespace:
            t_id: str
            name: str
            nodes: list = field(default_factory=list)

        @dataclass
        class Node:
            t_id: str
            name: str
            #conn: Conn
            conn: int
            edges: list = field(default_factory=list)

            def real_node(self):
                return self.conn.t_id == ''

        @dataclass
        class Edge:
            t_id: str
            src_name: str
            dst_name: str
            #conn: Conn
            conn: int
            # src: Node = None
            # dst: Node = None
            src: int = 0
            dst: int = 0

        @dataclass
        class Clique:
            #conn: Conn
            conn: int
            nodes: list = field(default_factory=list)
            edges: list = field(default_factory=list)

        @dataclass
        class BiClique:
            #conn: Conn
            conn: int
            #node: Node
            node: int
            src_nodes: list = field(default_factory=list)
            src_edges: list = field(default_factory=list)
            dst_nodes: list = field(default_factory=list)
            dst_edges: list = field(default_factory=list)

        @dataclass
        class Graph:
            t_id: str = ''
            name: str = ''
            namespaces: dict = field(default_factory=dict)
            nodes: dict = field(default_factory=dict)
            edges: dict = field(default_factory=dict)
            cliques: list = field(default_factory=list)
            bicliques: list = field(default_factory=list)
            conn_legend = None



        def __init__(self, tags_info):
            self.tags_info = tags_info
            self.graph = self.Graph()
            self.graph.conn_legend = self.ConnLegend()
            self.relations = defaultdict(set)
            self.highlights = defaultdict(set)

        def create_graph_elements(self):
            all_conns = set(t[3] for t in self.tags_info)
            for t_conn in all_conns:
                self.graph.conn_legend.conns[t_conn] = self.Conn()
            for t_id, t_class, t_title, t_conn in self.tags_info:
                if t_class == BACKGROUND_CT:
                    self.graph.t_id = t_id
                    self.graph.name = t_title
                elif t_class == NAMESPACE_CT:
                    namespace_name = t_title.replace('cluster_', '').replace('_namespace', '')
                    self.graph.namespaces[namespace_name] = self.Namespace(t_id, namespace_name)
                elif t_class == NODE_CT:
                    self.graph.nodes[t_title] = self.Node(t_id, t_title, self.graph.conn_legend.conns[t_conn])
                elif t_class == EDGE_CT:
                    src_name, dst_name = t_title.split('->')
                    self.graph.edges[(src_name, dst_name)] = self.Edge(t_id, src_name, dst_name, self.graph.conn_legend.conns[t_conn])
                elif t_class == CONNECTIVITY_CT:
                    self.graph.conn_legend.conns[t_conn].t_id = t_id


        def connect_graph_elements(self):
            for name, node in self.graph.nodes.items():
                node.edges = [edge for edge in self.graph.edges.values() if node.name in [edge.src_name, edge.dst_name]]
                namespace_name = node.name.split('/')[0].replace('-', '_')
                namespace = self.graph.namespaces.get(namespace_name, None)
                if namespace:
                    namespace.nodes.append(node)

            for (src_name, dst_name), edge in self.graph.edges.items():
                edge.src = self.graph.nodes[src_name]
                edge.dst = self.graph.nodes[dst_name]

            all_cliques_nodes = [node for node in self.graph.nodes.keys() if node.startswith('clique_')]
            # todo:
            all_cliques_edges = [edge for edge in self.graph.edges.keys() if edge[0].startswith('clique_') and edge[1].startswith('clique_')]
            clqs_graph = networkx.Graph()
            clqs_graph.add_nodes_from(all_cliques_nodes)
            clqs_graph.add_edges_from(all_cliques_edges)
            clique_sets = networkx.connected_components(clqs_graph)

            for clique_set in clique_sets:
                clique_conn = self.graph.nodes[list(clique_set)[0]].conn
                clique = self.Clique(clique_conn)
                clique_set_names = clique_set
                clique.edges = [edge for edge in self.graph.edges.values() if edge.src_name in clique_set_names or edge.dst_name in clique_set_names]
                node_names = set(e.src_name for e in clique.edges) | set(e.dst_name for e in clique.edges)
                clique.nodes = [node for node in self.graph.nodes.values() if node.name in node_names]
                self.graph.cliques.append(clique)

            all_bicliques_nodes = [node for name, node in self.graph.nodes.items() if name.startswith('biclique_')]
            for biclique_node in all_bicliques_nodes:
                biclique = self.BiClique(biclique_node.conn, biclique_node)
                biclique.src_edges = [edge for edge in self.graph.edges.values() if edge.dst_name == biclique_node.name]
                biclique.dst_edges = [edge for edge in self.graph.edges.values() if edge.src_name == biclique_node.name]
                biclique.src_nodes = [edge.src for edge in biclique.src_edges]
                biclique.dst_nodes = [edge.dst for edge in biclique.dst_edges]
                self.graph.bicliques.append(biclique)


        def set_tags_relations(self):

            for tag_id in [tag_info[0] for tag_info in self.tags_info]:
                self.relations[tag_id].add(tag_id)
                self.highlights[tag_id].add(tag_id)
                self.relations[tag_id].add(self.graph.t_id)
                for c in self.graph.conn_legend.conns.values():
                    self.relations[tag_id].add(c.t_id)
                self.relations[self.graph.t_id].add(tag_id)
                self.relations[tag_id] |= set(n.t_id for n in self.graph.nodes.values() if n.real_node())

            for namespace in self.graph.namespaces.values():
                for node in namespace.nodes:
                    self.relations[node.t_id].add(namespace.t_id)

            for edge in self.graph.edges.values():
                self.relations[edge.t_id] |= self.relations[edge.src.t_id]
                self.relations[edge.t_id] |= self.relations[edge.dst.t_id]
                self.relations[edge.conn.t_id] |= self.relations[edge.t_id]

            for node in self.graph.nodes.values():
                for edge in node.edges:
                    self.relations[node.t_id] |= self.relations[edge.t_id]

            for clique in self.graph.cliques:
                for el in clique.nodes + clique.edges:
                    for e in clique.edges:
                        self.relations[el.t_id] |= self.relations[e.t_id]
                        self.relations[clique.conn.t_id] |= self.relations[e.t_id]
                clq_core = [n for n in clique.nodes if not n.real_node()] + clique.edges
                for cc in clq_core:
                    self.highlights[cc.t_id].add(clique.conn.t_id)
                for cc1, cc2 in itertools.product(clq_core, clq_core):
                    self.highlights[cc1.t_id].add(cc2.t_id)

            for biclique in self.graph.bicliques:
                dst_edges_relations = set().union(*[self.relations[e.t_id] for e in biclique.dst_edges])
                src_edges_relations = set().union(*[self.relations[e.t_id] for e in biclique.src_edges])
                for n in biclique.src_nodes:
                    self.relations[n.t_id] |= dst_edges_relations
                for n in biclique.dst_nodes:
                    self.relations[n.t_id] |= src_edges_relations
                for e in biclique.dst_edges + biclique.src_edges:
                    self.relations[e.t_id] |= src_edges_relations
                    self.relations[e.t_id] |= dst_edges_relations
                self.relations[biclique.conn.t_id] |= self.relations[biclique.node.t_id]
                biclq_core = biclique.dst_edges + biclique.src_edges + [biclique.node]
                for bcc in biclq_core:
                    self.highlights[bcc.t_id].add(biclique.conn.t_id)
                for bcc1, bcc2 in itertools.product(biclq_core, biclq_core):
                    self.highlights[bcc1.t_id].add(bcc2.t_id)

            for namespace in self.graph.namespaces.values():
                for node in namespace.nodes:
                    self.relations[namespace.t_id] |= self.relations[node.t_id]

            for edge in self.graph.edges.values():
                self.highlights[edge.t_id].add(edge.conn.t_id)

        def get_tags_relations(self):
            return self.relations, self.highlights


    @staticmethod
    def create_interactive_graph(file_name, output_directory):
        svg_editor = InteractiveConnectivityGraph.SvgEditor(file_name,output_directory)
        svg_editor.read_input_file()
        svg_editor.set_tags_info()
        tags_info = svg_editor.get_tags_info()
        graph_relations = InteractiveConnectivityGraph.GraphRelations(tags_info)
        graph_relations.create_graph_elements()
        graph_relations.connect_graph_elements()
        graph_relations.set_tags_relations()
        relations, highlights = graph_relations.get_tags_relations()
        svg_editor.create_output(relations, highlights)


if __name__ == "__main__":
    file_name = sys.argv[1]
    output_directory = file_name + '_connectivity_dir'
    InteractiveConnectivityGraph.create_interactive_graph(file_name, output_directory)


