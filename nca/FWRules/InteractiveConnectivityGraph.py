import sys
from collections import defaultdict

import networkx
from bs4 import BeautifulSoup
import os
import shutil
import itertools
import copy
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

    @dataclass
    class ElementInfo:
        e_id: str
        e_class: str
        e_title: str
        e_conn: str

    @dataclass
    class ElementRelations:
        relations: set = field(default_factory=set)
        highlights: set = field(default_factory=set)

    class SvgGraph:
        def __init__(self, input_svg_file, output_directory):
            self.input_svg_file = input_svg_file
            self.output_directory = output_directory
            self.soup = None

        def read_input_file(self):
            with open(file_name) as cvg_file:
                self.soup = BeautifulSoup(cvg_file.read(), 'xml')


        def set_soup_tags_info(self):
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
        def get_soup_tag_info(tag):
            t_id = tag[ID_TA]
            t_class = tag[CLASS_TA]
            t_title = tag[TITLE_TA]
            t_conn = tag.get(CONNECTIVITY_TA) if tag.get(CONNECTIVITY_TA) else ''
            return InteractiveConnectivityGraph.ElementInfo(t_id, t_class, str(t_title), t_conn)


        def get_elements_info(self):
            elements_info = [ self.get_soup_tag_info(tag) for tag in self.soup.svg.find_all('a')]
            elements_info.append(InteractiveConnectivityGraph.ElementInfo('', '', '', ''))
            return elements_info

        def highlight_tag(self, tag, t_class):
            if t_class == NODE_CT:
                tag.polygon['stroke-width'] = '5'
            if t_class == NAMESPACE_CT:
                tag.polygon['stroke-width'] = '5'
                tag['font-weight'] = 'bold'
            if t_class == EDGE_CT:
                tag.path['stroke-width'] = '3'
                tag['font-weight'] = 'bold'
            if t_class == CONNECTIVITY_CT:
                tag['text-decoration'] = 'underline'
                tag['font-weight'] = 'bold'

        def set_related_tag_link(self, related_tag, related_tag_info, t_class):
            if (t_class == BACKGROUND_CT and related_tag_info.e_class == BACKGROUND_CT) or (
                    t_class != BACKGROUND_CT and related_tag_info.e_class != BACKGROUND_CT):
                related_tag['xlink:href'] = related_tag_info.e_id + '.svg'
            elif t_class == BACKGROUND_CT and related_tag_info.e_class != BACKGROUND_CT:
                related_tag['xlink:href'] = 'elements/' + related_tag_info.e_id + '.svg'
            else:
                related_tag['xlink:href'] = '../' + related_tag_info.e_id + '.svg'

        def save_tag_file(self, tag_soup, tag_info):
            if tag_info.e_class == BACKGROUND_CT:
                tag_file_name = os.path.join(self.output_directory, tag_info.e_id + '.svg')
            else:
                tag_file_name = os.path.join(self.output_directory, 'elements', tag_info.e_id + '.svg')
            with open(tag_file_name, 'wb') as tag_cvg_file:
                tag_cvg_file.write(tag_soup.prettify(encoding='utf-8'))

        def create_output(self, elements_relations):
            if os.path.isdir(self.output_directory):
                shutil.rmtree(self.output_directory)
            os.mkdir(self.output_directory)
            os.mkdir(os.path.join(self.output_directory, 'elements'))
            for tag in self.soup.svg.find_all('a'):
                tag_info = self.get_soup_tag_info(tag)
                tag_soup = copy.copy(self.soup)
                related_ids = elements_relations[tag_info.e_id].relations
                for related_tag in tag_soup.svg.find_all('a'):
                    related_tag_info = self.get_soup_tag_info(related_tag)
                    if related_tag_info.e_id not in related_ids:
                        related_tag.extract()
                        continue
                    self.set_related_tag_link(related_tag, related_tag_info, tag_info.e_class)
                    if related_tag_info.e_id in elements_relations[tag_info.e_id].highlights:
                        self.highlight_tag(related_tag, related_tag_info.e_class)
            self.save_tag_file(tag_soup, tag_info)

###################################################################################################################


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
            conn: int # todo
            edges: list = field(default_factory=list)

            def real_node(self):
                return self.conn.t_id == ''

        @dataclass
        class Edge:
            t_id: str
            src_name: str
            dst_name: str
            #conn: Conn
            conn: int # todo
            # src: Node = None
            # dst: Node = None
            src: int = 0 # todo
            dst: int = 0 # todo

        @dataclass
        class Clique:
            #conn: Conn
            conn: int # todo
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



        def __init__(self):
            self.graph = self.Graph()
            self.graph.conn_legend = self.ConnLegend()

        def create_graph_elements(self, elements_info):
            all_conns = set(t.e_conn for t in elements_info)
            for t_conn in all_conns:
                self.graph.conn_legend.conns[t_conn] = self.Conn()
            for el in elements_info:
                if el.e_class == BACKGROUND_CT:
                    self.graph.t_id = el.e_id
                    self.graph.name = el.e_title
                elif el.e_class == NAMESPACE_CT:
                    namespace_name = el.e_title.replace('cluster_', '').replace('_namespace', '')
                    self.graph.namespaces[namespace_name] = self.Namespace(el.e_id, namespace_name)
                elif el.e_class == NODE_CT:
                    self.graph.nodes[el.e_title] = self.Node(el.e_id, el.e_title, self.graph.conn_legend.conns[el.e_conn])
                elif el.e_class == EDGE_CT:
                    src_name, dst_name = el.e_title.split('->')
                    self.graph.edges[(src_name, dst_name)] = self.Edge(el.e_id, src_name, dst_name, self.graph.conn_legend.conns[el.e_conn])
                elif el.e_class == CONNECTIVITY_CT:
                    self.graph.conn_legend.conns[el.e_conn].t_id = el.e_id


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
            all_cliques_edges = [edge for edge in itertools.product(all_cliques_nodes, all_cliques_nodes) if edge in self.graph.edges.keys()]
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

        def set_basic_relations(self, tag_id, element_relation):
            element_relation.relations.add(tag_id)
            element_relation.highlights.add(tag_id)
            element_relation.relations.add(self.graph.t_id)
            for conn in self.graph.conn_legend.conns.values():
                element_relation.relations.add(conn.t_id)
            # to remain all pods in all graphs:
            # elements_relations[tag_id].relations |= set(n.t_id for n in self.graph.nodes.values() if n.real_node())

        def set_tags_relations(self):
            elements_relations = defaultdict(InteractiveConnectivityGraph.ElementRelations)
            all_items = list(self.graph.conn_legend.conns.values()) + list(self.graph.edges.values()) + \
                        list(self.graph.nodes.values()) + list(self.graph.namespaces.values()) + [self.graph]
            for item in all_items:
                self.set_basic_relations(item.t_id, elements_relations[item.t_id])
            elements_relations[self.graph.t_id].relations |= set(item.t_id for item in all_items)

            for namespace in self.graph.namespaces.values():
                for node in namespace.nodes:
                    elements_relations[node.t_id].relations.add(namespace.t_id)

            for edge in self.graph.edges.values():
                elements_relations[edge.t_id].relations |= elements_relations[edge.src.t_id].relations
                elements_relations[edge.t_id].relations |= elements_relations[edge.dst.t_id].relations
                elements_relations[edge.conn.t_id].relations |= elements_relations[edge.t_id].relations

            for node in self.graph.nodes.values():
                for edge in node.edges:
                    elements_relations[node.t_id].relations |= elements_relations[edge.t_id].relations

            for clique in self.graph.cliques:
                for el in clique.nodes + clique.edges:
                    for e in clique.edges:
                        elements_relations[el.t_id].relations |= elements_relations[e.t_id].relations
                        elements_relations[clique.conn.t_id].relations |= elements_relations[e.t_id].relations
                clq_core = [n for n in clique.nodes if not n.real_node()] + clique.edges
                for cc in clq_core:
                    elements_relations[cc.t_id].highlights.add(clique.conn.t_id)
                for cc1, cc2 in itertools.product(clq_core, clq_core):
                    elements_relations[cc1.t_id].highlights.add(cc2.t_id)

            for biclique in self.graph.bicliques:
                dst_edges_relations = set().union(*[elements_relations[e.t_id].relations for e in biclique.dst_edges])
                src_edges_relations = set().union(*[elements_relations[e.t_id].relations for e in biclique.src_edges])
                for n in biclique.src_nodes:
                    elements_relations[n.t_id].relations |= dst_edges_relations
                for n in biclique.dst_nodes:
                    elements_relations[n.t_id].relations |= src_edges_relations
                for e in biclique.dst_edges + biclique.src_edges:
                    elements_relations[e.t_id].relations |= src_edges_relations
                    elements_relations[e.t_id].relations |= dst_edges_relations
                elements_relations[biclique.conn.t_id].relations |= elements_relations[biclique.node.t_id].relations
                biclq_core = biclique.dst_edges + biclique.src_edges + [biclique.node]
                for bcc in biclq_core:
                    elements_relations[bcc.t_id].highlights.add(biclique.conn.t_id)
                for bcc1, bcc2 in itertools.product(biclq_core, biclq_core):
                    elements_relations[bcc1.t_id].highlights.add(bcc2.t_id)

            for namespace in self.graph.namespaces.values():
                for node in namespace.nodes:
                    elements_relations[namespace.t_id].relations |= elements_relations[node.t_id].relations

            for edge in self.graph.edges.values():
                elements_relations[edge.t_id].highlights.add(edge.conn.t_id)

            return elements_relations


    def __init__(self, file_name, output_directory):
        self.svg_graph = InteractiveConnectivityGraph.SvgGraph(file_name, output_directory)
        self.graph_relations = InteractiveConnectivityGraph.GraphRelations()

    def create_interactive_graph(self):
        self.svg_graph.read_input_file()
        self.svg_graph.set_soup_tags_info()
        elements_info = self.svg_graph.get_elements_info()
        self.graph_relations.create_graph_elements(elements_info)
        self.graph_relations.connect_graph_elements()
        elements_relations = self.graph_relations.set_tags_relations()
        self.svg_graph.create_output(elements_relations)


if __name__ == "__main__":
    file_name = sys.argv[1]
    output_directory = file_name + '_connectivity_dir'
    InteractiveConnectivityGraph(file_name, output_directory).create_interactive_graph()


