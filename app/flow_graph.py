from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

import networkx as nx


@dataclass
class Node:
    url: str
    depth: int = 0
    response_type: str = "unknown"
    parameters: List[str] = None

    def __post_init__(self) -> None:
        if self.parameters is None:
            self.parameters = []


@dataclass
class Edge:
    source_url: str
    destination_url: str
    parameter_name: str = ""
    method: str = "GET"
    example_value: str = ""


class FlowGraph:
    def __init__(self) -> None:
        self._graph = nx.MultiDiGraph()

    def add_node(self, url: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        clean_url = str(url or "").strip()
        if not clean_url:
            return

        metadata = metadata or {}
        node = Node(
            url=clean_url,
            depth=int(metadata.get("depth", 0) or 0),
            response_type=str(metadata.get("response_type", "unknown") or "unknown"),
            parameters=sorted(
                {
                    str(item or "").strip()
                    for item in (metadata.get("parameters") or [])
                    if str(item or "").strip()
                }
            ),
        )
        self._graph.add_node(clean_url, node=node)

    def add_edge(
        self,
        source: str,
        destination: str,
        parameter: str = "",
        method: str = "GET",
        example_value: str = "",
    ) -> None:
        source_url = str(source or "").strip()
        destination_url = str(destination or "").strip()
        if not source_url or not destination_url:
            return

        if source_url not in self._graph:
            self.add_node(source_url, {})
        if destination_url not in self._graph:
            self.add_node(destination_url, {})

        edge = Edge(
            source_url=source_url,
            destination_url=destination_url,
            parameter_name=str(parameter or "").strip(),
            method=str(method or "GET").strip().upper(),
            example_value=str(example_value or "").strip(),
        )
        self._graph.add_edge(source_url, destination_url, edge=edge)

    def get_downstream_nodes(self, url: str) -> List[str]:
        source = str(url or "").strip()
        if not source or source not in self._graph:
            return []
        return sorted(str(node) for node in nx.descendants(self._graph, source))

    def get_parameter_paths(self, parameter_name: str) -> List[Dict[str, Any]]:
        param = str(parameter_name or "").strip()
        if not param:
            return []

        paths: List[Dict[str, Any]] = []
        seen_paths: Set[Tuple[str, ...]] = set()

        for source in self._graph.nodes:
            for target in self._graph.nodes:
                if source == target:
                    continue
                if not nx.has_path(self._graph, source, target):
                    continue

                try:
                    shortest = nx.shortest_path(self._graph, source, target)
                except Exception:
                    continue
                if len(shortest) < 2:
                    continue

                matched_edges: List[Dict[str, Any]] = []
                for idx in range(len(shortest) - 1):
                    src = shortest[idx]
                    dst = shortest[idx + 1]
                    edge_bundle = self._graph.get_edge_data(src, dst, default={})
                    for edge_data in edge_bundle.values():
                        edge = edge_data.get("edge")
                        if not isinstance(edge, Edge):
                            continue
                        if edge.parameter_name != param:
                            continue
                        matched_edges.append(asdict(edge))

                if not matched_edges:
                    continue

                signature = tuple(str(x) for x in shortest)
                if signature in seen_paths:
                    continue
                seen_paths.add(signature)
                paths.append(
                    {
                        "parameter": param,
                        "path": [str(node) for node in shortest],
                        "hops": len(shortest) - 1,
                        "matching_edges": matched_edges,
                    }
                )

        return sorted(paths, key=lambda item: (item["hops"], item["path"]))

    def detect_long_chains(self, min_length: int = 3) -> List[Dict[str, Any]]:
        threshold = max(1, int(min_length))
        chains: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, ...]] = set()

        for source in self._graph.nodes:
            for target in self._graph.nodes:
                if source == target:
                    continue
                if not nx.has_path(self._graph, source, target):
                    continue
                try:
                    path = nx.shortest_path(self._graph, source, target)
                except Exception:
                    continue
                hops = len(path) - 1
                if hops < threshold:
                    continue
                signature = tuple(str(x) for x in path)
                if signature in seen:
                    continue
                seen.add(signature)
                chains.append({"path": [str(x) for x in path], "hops": hops})

        return sorted(chains, key=lambda item: item["hops"], reverse=True)

    def detect_cross_page_reflection(self, payload_marker: str) -> List[Dict[str, Any]]:
        marker = str(payload_marker or "").strip()
        if not marker:
            return []

        reflections: List[Dict[str, Any]] = []
        hits: List[str] = []
        for url, node_data in self._graph.nodes(data=True):
            node = node_data.get("node")
            attrs = node_data.get("metadata") or {}
            snippet = str(attrs.get("body_snippet") or "")
            if marker in snippet:
                hits.append(str(url))

        for source in hits:
            for sink in hits:
                if source == sink:
                    continue
                if not nx.has_path(self._graph, source, sink):
                    continue
                path = nx.shortest_path(self._graph, source, sink)
                reflections.append(
                    {"source": source, "sink": sink, "path": [str(x) for x in path]}
                )

        return reflections

    def export_graph_json(self) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        for url, data in self._graph.nodes(data=True):
            node = data.get("node")
            node_dict = asdict(node) if isinstance(node, Node) else {"url": str(url)}
            nodes.append(node_dict)

        edges: List[Dict[str, Any]] = []
        for _, _, data in self._graph.edges(data=True):
            edge = data.get("edge")
            if isinstance(edge, Edge):
                edges.append(asdict(edge))

        return {
            "node_count": self._graph.number_of_nodes(),
            "edge_count": self._graph.number_of_edges(),
            "nodes": sorted(nodes, key=lambda item: str(item.get("url") or "")),
            "edges": sorted(
                edges,
                key=lambda item: (
                    str(item.get("source_url") or ""),
                    str(item.get("destination_url") or ""),
                    str(item.get("parameter_name") or ""),
                ),
            ),
        }

    def shortest_path(self, source: str, destination: str) -> List[str]:
        src = str(source or "").strip()
        dst = str(destination or "").strip()
        if not src or not dst:
            return []
        if src not in self._graph or dst not in self._graph:
            return []
        if not nx.has_path(self._graph, src, dst):
            return []
        try:
            return [str(x) for x in nx.shortest_path(self._graph, src, dst)]
        except Exception:
            return []


def _extract_query_param_values(url: str) -> Dict[str, List[str]]:
    try:
        parsed = urlparse(str(url or ""))
    except Exception:
        return {}
    values = parse_qs(parsed.query, keep_blank_values=True)
    out: Dict[str, List[str]] = {}
    for key, items in values.items():
        name = str(key or "").strip()
        if not name:
            continue
        out[name] = [str(v or "") for v in items]
    return out


def build_flow_graph_from_crawler_output(crawler_output: Dict[str, Any]) -> FlowGraph:
    graph = FlowGraph()
    pages = crawler_output.get("pages")
    if not isinstance(pages, list):
        return graph

    for page in pages:
        if not isinstance(page, dict):
            continue
        url = str(page.get("url") or "").strip()
        if not url:
            continue
        params: Set[str] = set()
        for name in page.get("query_parameters") or []:
            param = str(name or "").strip()
            if param:
                params.add(param)
        for form in page.get("forms") or []:
            if not isinstance(form, dict):
                continue
            for input_item in form.get("inputs") or []:
                if not isinstance(input_item, dict):
                    continue
                name = str(input_item.get("name") or "").strip()
                if name:
                    params.add(name)
        graph.add_node(
            url,
            {
                "depth": int(page.get("depth", 0) or 0),
                "response_type": str(page.get("response_type") or "unknown"),
                "parameters": sorted(params),
            },
        )

    for page in pages:
        if not isinstance(page, dict):
            continue
        source = str(page.get("url") or "").strip()
        if not source:
            continue

        for link in page.get("internal_links") or []:
            destination = str(link or "").strip()
            if not destination:
                continue
            query_values = _extract_query_param_values(destination)
            if query_values:
                for param_name, examples in query_values.items():
                    graph.add_edge(
                        source,
                        destination,
                        parameter=param_name,
                        method="GET",
                        example_value=str(examples[0] if examples else ""),
                    )
            else:
                graph.add_edge(source, destination, parameter="", method="GET", example_value="")

        for form in page.get("forms") or []:
            if not isinstance(form, dict):
                continue
            action = str(form.get("action") or "").strip()
            if not action:
                continue
            method = str(form.get("method") or "GET").upper()
            inputs = form.get("inputs") or []
            if not isinstance(inputs, list) or not inputs:
                graph.add_edge(source, action, parameter="", method=method, example_value="")
                continue
            for input_item in inputs:
                if not isinstance(input_item, dict):
                    continue
                param_name = str(input_item.get("name") or "").strip()
                example_value = str(input_item.get("value") or "").strip()
                graph.add_edge(
                    source,
                    action,
                    parameter=param_name,
                    method=method,
                    example_value=example_value,
                )

        for endpoint in page.get("discovered_endpoints") or []:
            destination = str(endpoint or "").strip()
            if not destination:
                continue
            query_values = _extract_query_param_values(destination)
            if query_values:
                for param_name, examples in query_values.items():
                    graph.add_edge(
                        source,
                        destination,
                        parameter=param_name,
                        method="GET",
                        example_value=str(examples[0] if examples else ""),
                    )
            else:
                graph.add_edge(
                    source,
                    destination,
                    parameter="",
                    method="GET",
                    example_value="",
                )

    return graph


__all__ = [
    "Node",
    "Edge",
    "FlowGraph",
    "build_flow_graph_from_crawler_output",
]
