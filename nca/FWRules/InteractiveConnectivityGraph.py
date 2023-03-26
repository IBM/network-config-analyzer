#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from __future__ import annotations
import os
import sys
import shutil
import itertools
import copy
from dataclasses import dataclass, field
from collections import defaultdict
import posixpath
import networkx
from bs4 import BeautifulSoup


class InteractiveConnectivityGraph:
    """
    InteractiveConnectivityGraph is a class for creating an interactive connectivity graph from an svg file.
    The interactive connectivity graph is an set of svg files.
    Each element (aka tag) in the svg file has a link to another svg file.
    The input is an svg file, containing a connectivity graph
    The output is a set of svg files, one for each element in the graph
    the main process for creating the interactive graph:
    (1) parsing the input svg file, into a beautifulsoup object.
    (2) changing the soup object, for later enabling adding links, and adding missing information.
    (3) reading from the soup object abstract information of the elements in the graph.
    (4) using this abstract information to create an abstract connectivity graph.
    (5) from the abstract graph, for each element, creating a list of related elements.
    (5b) from the abstract graph, for each element, set the explanation of its connectivity graph.
    (6) for each element, create an svg file containing these related elements.

    InteractiveConnectivityGraph has two main inner classes:
      - class SvgGraph - implementation of steps (1) (2) (3) (6)
      - class AbstractGraph - implementation of steps (4) (5)

    another inner classes:
       - class ElementInfo - the abstract information extracted at step (3)
       - class ElementRelations - the relation information created at step (5)
    """
    @dataclass
    class ElementInfo:
        t_id: str
        t_class: str
        t_title: str
        t_conn: str
        t_text: list

    @dataclass
    class ElementRelations:
        """
        represents the relations between elements each element has:
        (1) a list of elements to be in the element svg file.
        (2) a list of elements to be highlighted in the element svg file.
        """
        relations: set = field(default_factory=set)
        highlights: set = field(default_factory=set)
        explanation: list = field(default_factory=set)

    def __init__(self, svg_file_name, output_directory):
        """
        Creates the InteractiveConnectivityGraph
        param: svg_file_name: str
        param: output_directory: str
        """
        self.svg_graph = self.SvgGraph(svg_file_name, output_directory)
        self.abstract_graph = self.AbstractGraph()

    def create_interactive_graph(self):
        """
        the main method of the creation of the interactive_graph
        """

        # (1) parsing the input svg file, into a beautifulsoup object:
        self.svg_graph.read_input_file()
        # (2) changing the soup object, for enabling linking, and adding missing information:
        self.svg_graph.set_soup_tags_info()
        # (3) reading from the soup object abstract information of the elements in the graph:
        elements_info = self.svg_graph.get_elements_info()
        # (4) using this abstract information to create an abstract connectivity graph:
        self.abstract_graph.create_graph(elements_info)
        # (5) from the abstract graph, for each element, creating a list of related elements:
        elements_relations = self.abstract_graph.set_tags_relations()
        # (5b) from the abstract graph, for each element, set the explanation of its connectivity graph:
        self.abstract_graph.set_tags_explanation(elements_relations)
        # (6) for each element, create an svg file containing these related elements:
        self.svg_graph.create_output(elements_relations)

    class SvgGraph:
        """
        The SvgGraph is responsible of reading, changing, and writing the svg information.
        """
        # Tags Attributes:
        CLASS_TA = 'class'
        ID_TA = 'id'
        TITLE_TA = 'title'
        CONNECTIVITY_TA = 'connectivity'
        CLICKABLE_TA = 'clickable'

        # Class types
        GRAPH_CT = 'graph'
        LEGEND_MISC_CT = 'conn_legend_misc'
        EXPLANATION_CT = 'explanation'
        BACKGROUND_CT = 'background'
        NAMESPACE_CT = 'cluster'
        NODE_CT = 'node'
        EDGE_CT = 'edge'
        CONNECTIVITY_CT = 'connectivity'

        def __init__(self, input_svg_file, output_directory):
            """
            Creates the InteractiveConnectivityGraph
            param: svg_file_name: str
            param: output_directory: str
            """
            self.input_svg_file = input_svg_file
            self.output_directory = output_directory
            self.soup = None

        def read_input_file(self):
            """
            read the file, and save is in soup object
            """
            try:
                with open(self.input_svg_file) as svg_file:
                    self.soup = BeautifulSoup(svg_file.read(), 'xml')
            except Exception as e:
                print(f'Failed to open file: {self.input_svg_file}\n{e} for reading', file=sys.stderr)

        def set_soup_tags_info(self):
            """
            do the following changes the soup object:
            (1) every element that we want to add a link - we must change its name from <g> to <a>, or wrap it with an <a>
            (2) adding/changing the following attribute to every element: id, class, title, conn

            """
            # wrap the title + background polygon with an <a>:
            graph_polygon = self.soup.svg.polygon
            graph_polygon = graph_polygon.wrap(self.soup.new_tag('a'))
            graph_polygon[self.CLASS_TA] = self.BACKGROUND_CT
            graph_text = self.soup.svg.find('text')
            graph_polygon.append(graph_text)

            # set class to all the legend components:
            conn_legend = self.soup.svg.find('title', string='dict_box')
            if conn_legend:
                conn_legend = conn_legend.find_parent('g')
                conn_legend[self.CLASS_TA] = self.LEGEND_MISC_CT
                for conn in conn_legend.find_all('a'):
                    conn[self.CLASS_TA] = self.CONNECTIVITY_CT
                for conn in conn_legend.find_all('g'):
                    conn[self.CLASS_TA] = self.LEGEND_MISC_CT

            # setting class to explanation tag:
            explanation_cluster = self.soup.svg.find('title', string='cluster_map_explanation').find_parent('g')
            explanation_cluster[self.CLASS_TA] = self.EXPLANATION_CT
            # for element that we want to add a link, we replace <g> with <a>:
            for tag in self.soup.svg.find_all(True):
                if tag.get(self.CLASS_TA):
                    if tag[self.CLASS_TA] not in [self.GRAPH_CT, self.LEGEND_MISC_CT, self.EXPLANATION_CT]:
                        tag[self.CLICKABLE_TA] = 'true'
                        tag.name = 'a'

            # add missing id and titles to background and conns:
            # moving the title for all the others:
            for tag in self.soup.svg.find_all('a'):
                if not tag.get(self.CLASS_TA):
                    # it is  a tooltip
                    continue
                if tag[self.CLASS_TA] == self.BACKGROUND_CT:
                    tag[self.ID_TA] = 'index'
                    tag[self.TITLE_TA] = tag.find('text').string
                elif tag[self.CLASS_TA] == self.CONNECTIVITY_CT:
                    short = tag.text.split()[0]
                    conn_id = 'conn_' + short
                    tag[self.ID_TA] = conn_id
                    tag[self.TITLE_TA] = short
                else:
                    tag[self.TITLE_TA] = tag.title.string

                # set connectivity for all elements:
                if tag[self.CLASS_TA] == self.EDGE_CT and tag.find('text'):
                    tag[self.CONNECTIVITY_TA] = tag.find('text').string
                elif tag[self.CLASS_TA] == self.NODE_CT and tag.title and 'clique' in tag.title.string:
                    tag[self.CONNECTIVITY_TA] = tag.find_all('text')[1].string
                elif tag[self.CLASS_TA] == self.CONNECTIVITY_CT:
                    tag[self.CONNECTIVITY_TA] = tag[self.TITLE_TA]

        def _get_soup_tag_info(self, tag):
            """
            read the information from a soup tag
            param: tag: the tag from the soup object
            return ElementInfo
            """
            t_id = tag[self.ID_TA]
            t_class = tag[self.CLASS_TA]
            t_title = tag[self.TITLE_TA]
            t_conn = tag.get(self.CONNECTIVITY_TA) if tag.get(self.CONNECTIVITY_TA) else ''
            if t_class == self.NODE_CT:
                t_text = [str(t.string) for t in tag.find_all('text')]
            elif t_class == self.CONNECTIVITY_CT:
                t_text = [tag.find_parent('g').a['xlink:title']]
            else:
                t_text = []
            return InteractiveConnectivityGraph.ElementInfo(t_id, t_class, str(t_title), t_conn, t_text)

        def _get_clickable_elements(self, soup):
            """
            get the clickable elements of the soup
            """
            return soup.find_all(attrs={self.CLICKABLE_TA: 'true'})

        def get_elements_info(self):
            """
            read the information from all soup tags
            return: list(ElementInformation): the information of each element
            """
            elements_info = [self._get_soup_tag_info(tag) for tag in self._get_clickable_elements(self.soup)]
            return elements_info

        def _set_related_tag_link(self, related_tag, related_tag_info, t_class):
            """
            Set the link in the soup tag.
            Not all the svg files sits in the same directory,
            (all svg file, except the main file, are in sub directory)
            therefore, relative path depends on the class of:
             1. the element that we creates the svg file for
             2. the soup tag for which we currently update the link

             param: related_tag: the tag from the soup object that we want to update its link
             param: related_tag_info :the information of this tag: ElementInfo
             param: t_class: the class of the tag that creates the svg file for: str
            """
            if (t_class == self.BACKGROUND_CT and related_tag_info.t_class == self.BACKGROUND_CT) or \
               (t_class != self.BACKGROUND_CT and related_tag_info.t_class != self.BACKGROUND_CT):
                relative_path = '.'
            elif t_class == self.BACKGROUND_CT and related_tag_info.t_class != self.BACKGROUND_CT:
                relative_path = 'elements'
            else:
                relative_path = '..'
            related_tag['xlink:href'] = posixpath.join(relative_path, related_tag_info.t_id + '.svg')

        def _highlight_tag(self, tag, t_class):
            """
            add highlight ingo to the soup tag, depends on the class
            param: tag: the soup tag to edit
            param: class: the class type of the tag
            """
            if t_class == self.NODE_CT:
                tag.polygon['stroke-width'] = '5'
            elif t_class == self.NAMESPACE_CT:
                tag.polygon['stroke-width'] = '5'
                tag['font-weight'] = 'bold'
            elif t_class == self.EDGE_CT:
                tag.path['stroke-width'] = '3'
                tag['font-weight'] = 'bold'
            elif t_class == self.CONNECTIVITY_CT:
                tag['text-decoration'] = 'underline'
                tag['font-weight'] = 'bold'

        def _save_tag_file(self, tag_soup, tag_info):
            """
            save the soup to an svg file, the name and location is according to the class and id
            (all svg file, except the main file, are in sub directory)
            param: tag_soup: the soup to save: soup
            param: tag_info: the information of the tag for which we currently save its soup
            """
            if tag_info.t_class == self.BACKGROUND_CT:
                tag_file_name = os.path.join(self.output_directory, tag_info.t_id + '.svg')
            else:
                tag_file_name = os.path.join(self.output_directory, 'elements', tag_info.t_id + '.svg')
            try:
                with open(tag_file_name, 'wb') as tag_svg_file:
                    tag_svg_file.write(tag_soup.prettify(encoding='utf-8'))
            except Exception as e:
                print(f'Failed to open file: {tag_file_name}\n{e} for writing', file=sys.stderr)

        def _set_explanation(self, tag_soup, explanation):
            explanation_cluster = tag_soup.svg.find('title', string='cluster_map_explanation').find_parent('g')
            place_holders = explanation_cluster.find_all('text')
            for holder, line in zip(place_holders, explanation + ['']*(len(place_holders) - len(explanation))):
                holder.string = line

        def create_output(self, elements_relations):
            """
            Creates the set of svg files as an interactive graph
            param: elements_relations: dict t_id -> ElementRelations:
            for each tag:
            1. a list of ids of tags that should be in the svg file of the tag.
            2. a list of ids of tags that should be highlighted in the svg file of the tag.

            for each tag:
            (1) creating duplicate the soap object
            (2) remove from the duplicated soup all other tags which are not related to the tag.
            (3) highlights the tags that should be highlighted in the the duplicated soup
            (4) save the duplicated soup to an svg file

            param:  elements_relations dict {str: ElementRelations}: for each element list of relations and list of highlights
            """
            try:
                if os.path.isdir(self.output_directory):
                    shutil.rmtree(self.output_directory)
                os.mkdir(self.output_directory)
                os.mkdir(os.path.join(self.output_directory, 'elements'))
            except Exception as e:
                print(f'Failed to create directory: {self.output_directory}\n{e} for writing', file=sys.stderr)
                return
            for tag in self._get_clickable_elements(self.soup):
                tag_info = self._get_soup_tag_info(tag)
                tag_soup = copy.copy(self.soup)
                if tag_info.t_class != self.BACKGROUND_CT:
                    self._set_explanation(tag_soup, elements_relations[tag_info.t_id].explanation)
                for related_tag in self._get_clickable_elements(tag_soup):
                    related_tag_info = self._get_soup_tag_info(related_tag)
                    if related_tag_info.t_id not in elements_relations[tag_info.t_id].relations:
                        related_tag.extract()
                        continue
                    self._set_related_tag_link(related_tag, related_tag_info, tag_info.t_class)
                    if related_tag_info.t_id in elements_relations[tag_info.t_id].highlights:
                        self._highlight_tag(related_tag, related_tag_info.t_class)
                self._save_tag_file(tag_soup, tag_info)

    class AbstractGraph:
        """
        AbstractGraph is responsible of
        (1) building the connectivity graph from the elements info
        (2) find the relations between the elements
        AbstractGraph has inner classes to build the graph: ConnLegend, Conn, Edge, Node, Namespace, Clique, BiClique, Graph

        the building of the graph is done in two steps:
        (1a) creating objects of these classes for each element
        (1b) connecting between the objects using naming convention
        """

        @dataclass
        class ConnLegend:
            conns: dict = field(default_factory=dict)

        @dataclass(unsafe_hash=True)
        class Conn:
            name: str
            t_id: str = ''
            full_description: str = field(default_factory=list)

        @dataclass
        class Namespace:
            t_id: str
            name: str
            nodes: list = field(default_factory=list)

        @dataclass
        class Node:
            t_id: str
            name: str
            conn: InteractiveConnectivityGraph.AbstractGraph.Conn
            short_names: list
            namespace: InteractiveConnectivityGraph.AbstractGraph.Namespace = None
            edges: list = field(default_factory=list)

            def real_node(self):
                return self.conn.t_id == ''

        @dataclass
        class Edge:
            t_id: str
            src_name: str
            dst_name: str
            conn: InteractiveConnectivityGraph.AbstractGraph.Conn
            src: InteractiveConnectivityGraph.AbstractGraph.Node = None
            dst: InteractiveConnectivityGraph.AbstractGraph.Node = None

        @dataclass
        class Clique:
            conn: InteractiveConnectivityGraph.AbstractGraph.Conn
            nodes: list = field(default_factory=list)
            edges: list = field(default_factory=list)

        @dataclass
        class BiClique:
            conn: InteractiveConnectivityGraph.AbstractGraph.Conn
            node: InteractiveConnectivityGraph.AbstractGraph.Node
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
            conn_legend: InteractiveConnectivityGraph.AbstractGraph.ConnLegend = None

        def __init__(self):
            self.graph = self.Graph()
            self.graph.conn_legend = self.ConnLegend()

        def create_graph(self, elements_info):
            """
            (1a) creating objects of these classes for each element
            (1b) connecting between the objects using naming convention
            param: elements_info: list(ElementInformation): the information of each element
            """
            self._create_graph_elements(elements_info)
            self._connect_graph_elements()

        def _create_graph_elements(self, elements_info):
            """
            creates an object for each element according to the element information
            param: elements_info: list(ElementInformation): the information of each element
            """
            all_conns = set(t.t_conn for t in elements_info)
            for t_conn in all_conns:
                self.graph.conn_legend.conns[t_conn] = self.Conn(t_conn)
            for el in elements_info:
                if el.t_class == InteractiveConnectivityGraph.SvgGraph.BACKGROUND_CT:
                    self.graph.t_id = el.t_id
                    self.graph.name = el.t_title
                elif el.t_class == InteractiveConnectivityGraph.SvgGraph.NAMESPACE_CT:
                    namespace_name = el.t_title.replace('cluster_', '').replace('_namespace', '')
                    self.graph.namespaces[namespace_name] = self.Namespace(el.t_id, namespace_name)
                elif el.t_class == InteractiveConnectivityGraph.SvgGraph.NODE_CT:
                    self.graph.nodes[el.t_title] = \
                        self.Node(el.t_id, el.t_title, self.graph.conn_legend.conns[el.t_conn], el.t_text)
                elif el.t_class == InteractiveConnectivityGraph.SvgGraph.EDGE_CT:
                    src_name, dst_name = el.t_title.split('->')
                    edge = self.Edge(el.t_id, src_name, dst_name, self.graph.conn_legend.conns[el.t_conn])
                    self.graph.edges[(src_name, dst_name)] = edge
                elif el.t_class == InteractiveConnectivityGraph.SvgGraph.CONNECTIVITY_CT:
                    self.graph.conn_legend.conns[el.t_conn].t_id = el.t_id
                    self.graph.conn_legend.conns[el.t_conn].full_description = el.t_text[0]

        def _connect_graph_elements(self):
            """
            building the graph
            (1) put every node in its namespace
            (2) set src and dst for each edge
            (3) creates clique and bicliques
            """
            for name, node in self.graph.nodes.items():
                node.edges = [edge for edge in self.graph.edges.values() if node.name in [edge.src_name, edge.dst_name]]
                namespace_name = node.name.split('/')[0].replace('-', '_')
                namespace = self.graph.namespaces.get(namespace_name, None)
                if namespace:
                    namespace.nodes.append(node)
                    node.namespace = namespace

            for (src_name, dst_name), edge in self.graph.edges.items():
                edge.src = self.graph.nodes[src_name]
                edge.dst = self.graph.nodes[dst_name]

            # creating cliques:
            # find all cliques nodes and edges:
            all_cliques_nodes = [node for node in self.graph.nodes if node.startswith('clique_')]
            all_cliques_edges = [edge for edge in itertools.product(all_cliques_nodes, all_cliques_nodes) if
                                 edge in self.graph.edges]
            # a clique can have more than one clique node, so
            # we find connected set of cliques nodes, each set is a clique
            clqs_graph = networkx.Graph()
            clqs_graph.add_nodes_from(all_cliques_nodes)
            clqs_graph.add_edges_from(all_cliques_edges)
            clique_sets = networkx.connected_components(clqs_graph)

            # for each set build its clique, add its nodes and edges:
            for clique_set in clique_sets:
                cliqut_conn = self.graph.nodes[list(clique_set)[0]].conn
                clique = self.Clique(cliqut_conn)
                clique_set_names = clique_set
                clique.edges = [edge for edge in self.graph.edges.values() if
                                edge.src_name in clique_set_names or edge.dst_name in clique_set_names]
                node_names = set(e.src_name for e in clique.edges) | set(e.dst_name for e in clique.edges)
                clique.nodes = [node for node in self.graph.nodes.values() if node.name in node_names]
                self.graph.cliques.append(clique)

            # creating bicliques:
            # each biclique node represent a biclique
            # so we just find the src and dst of a biclique node, and create a biclique
            all_bicliques_nodes = [node for name, node in self.graph.nodes.items() if name.startswith('biclique_')]
            for biclique_node in all_bicliques_nodes:
                biclique = self.BiClique(biclique_node.conn, biclique_node)
                biclique.src_edges = [edge for edge in self.graph.edges.values() if edge.dst_name == biclique_node.name]
                biclique.dst_edges = [edge for edge in self.graph.edges.values() if edge.src_name == biclique_node.name]
                biclique.src_nodes = [edge.src for edge in biclique.src_edges]
                biclique.dst_nodes = [edge.dst for edge in biclique.dst_edges]
                self.graph.bicliques.append(biclique)

        def _add_basic_relations(self, t_id, element_relation):
            """
            adding to the element_relation of t_id the elements that should be on every svg file
            param: t_id: string
            param: element_relation: ElementRelations
            """
            element_relation.relations.add(t_id)
            element_relation.highlights.add(t_id)
            element_relation.relations.add(self.graph.t_id)
            for conn in self.graph.conn_legend.conns.values():
                element_relation.relations.add(conn.t_id)
            # to remain all pods in all graphs:
            # elements_relations[t_id].relations |= set(n.t_id for n in self.graph.nodes.values() if n.real_node())

        def set_tags_relations(self):
            """
            find the related elements of each element
            return:  elements_relations dict {str: ElementRelations}: for each element list of relations and list of highlights
            """
            elements_relations = defaultdict(InteractiveConnectivityGraph.ElementRelations)

            # first add the basic relations:
            all_items = list(self.graph.conn_legend.conns.values()) + list(self.graph.edges.values()) +\
                list(self.graph.nodes.values()) + list(self.graph.namespaces.values()) + [self.graph]
            for item in all_items:
                self._add_basic_relations(item.t_id, elements_relations[item.t_id])

            # the grapg itself will have all the items:
            elements_relations[self.graph.t_id].relations |= set(item.t_id for item in all_items)

            # add namespaces to nodes:
            for namespace in self.graph.namespaces.values():
                for node in namespace.nodes:
                    elements_relations[node.t_id].relations.add(namespace.t_id)

            # add nodes of edge to an edge
            # add edge to its connectivity
            for edge in self.graph.edges.values():
                elements_relations[edge.t_id].relations |= elements_relations[edge.src.t_id].relations
                elements_relations[edge.t_id].relations |= elements_relations[edge.dst.t_id].relations
                elements_relations[edge.conn.t_id].relations |= elements_relations[edge.t_id].relations

            # add to nodes its edges
            for node in self.graph.nodes.values():
                for edge in node.edges:
                    elements_relations[node.t_id].relations |= elements_relations[edge.t_id].relations

            # add edge and nodes to all clique elements (conns already inside)
            # highlights all clique core elements with each other
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

            self._set_bicliques_relations(elements_relations)

            # add nodes to namespace:
            for namespace in self.graph.namespaces.values():
                for node in namespace.nodes:
                    elements_relations[namespace.t_id].relations |= elements_relations[node.t_id].relations

            # hightlights edge connectivity:
            for edge in self.graph.edges.values():
                elements_relations[edge.t_id].highlights.add(edge.conn.t_id)

            return elements_relations

        def _set_bicliques_relations(self, elements_relations):
            """
            for each *src* node/edge of the biclique, we do not add all biclique, we just add all *dst* nodes+edges
            we also hightlights all biclique core elements with each other + relevant connectivity

            param: elements_relations: dict {str: ElementRelations} : the relation to update
            """
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

        def set_tags_explanation(self, elements_relations):
            """
            set explanation of each element
            param:  elements_relations dict {str: ElementRelations}: to update the explanation
            """
            all_items = list(self.graph.conn_legend.conns.values()) + list(self.graph.edges.values()) +\
                list(self.graph.nodes.values()) + list(self.graph.namespaces.values()) + [self.graph]
            for item in all_items:
                elements_relations[item.t_id].explanation = [f'this is not a good explanation of {item.t_id}']*2

            for node in self.graph.nodes.values():
                if len(node.short_names) == 1:
                    elements_relations[node.t_id].explanation = [
                        f'This sub graph is a point of view of the pod \'{node.short_names[0]}\' (see highlighted)',
                        'It shows all the connections of the pod']
                    if node.namespace:
                        elements_relations[node.t_id].explanation.append(f'{node.name} is at namespace {node.namespace.name}')
                    if 'livesim' in node.name:
                        elements_relations[node.t_id].explanation.append('A livesim pod is ...')
                else:
                    elements_relations[node.t_id].explanation = [
                        f'This sub graph is a point of view of set of {len(node.short_names)}pods (see highlighted)',
                        'All The pods in this set have the same connectivity rules']
                    if node.namespace:
                        elements_relations[node.t_id].explanation.append(f'All the pods at namespace {node.namespace.name}')

            for edge in self.graph.edges.values():
                elements_relations[edge.t_id].explanation = [
                    f'This sub graph is a point of view of the connection between'
                    f' \'{edge.src.short_names[0]}\' and  \'{edge.dst.short_names[0]}\'',
                    f'with connectivity {edge.conn.full_description}']

            for clique in self.graph.cliques:
                clq_core = [n for n in clique.nodes if not n.real_node()] + clique.edges
                for cc in clq_core:
                    elements_relations[cc.t_id].explanation = [
                        f'This sub graph is a point of view of a Clique {clique.conn.full_description}']

            for biclique in self.graph.bicliques:
                biclq_core = biclique.dst_edges + biclique.src_edges + [biclique.node]
                for bcc in biclq_core:
                    elements_relations[bcc.t_id].explanation = [
                        f'This sub graph is a point of view of a biClique {biclique.conn.full_description}']

            for ns_name, namespace in self.graph.namespaces.items():
                elements_relations[namespace.t_id].explanation = [
                    f'This sub graph is a point of view of a namespace {ns_name}']

            for conn in self.graph.conn_legend.conns.values():
                elements_relations[conn.t_id].explanation = [
                    f'This sub graph is a point of view of a connectivity {conn.name}:',
                    f'{conn.full_description}']
