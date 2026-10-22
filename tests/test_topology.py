from lanwatch.topology import build_topology, topology_to_dot


def config():
    return {"name":"WiFi","address":"172.16.16.159","prefix":21,
            "network":"172.16.16.0/21","gateway":"172.16.16.1"}


def test_empty_topology_contains_local_and_configured_gateway_only():
    graph=build_topology(config(),[])
    by_kind={node["kind"]:node for node in graph["nodes"]}
    assert {node["kind"] for node in graph["nodes"]}=={"subnet","local","gateway"}
    assert by_kind["gateway"]["observed"] is False
    assert all(edge["evidence"]=="configured" for edge in graph["edges"])


def test_duplicate_observations_merge_metadata_and_keep_gateway_evidence():
    devices=[{"ip":"172.16.16.1","mac":"aa:bb:cc:dd:ee:01"},
             {"ip":"172.16.16.1","hostname":"router.local","vendor":"Example"},
             {"ip":"172.16.16.2","mac":"aa:bb:cc:dd:ee:02"}]
    graph=build_topology(config(),devices)
    gateway=[node for node in graph["nodes"] if node["kind"]=="gateway"][0]
    assert len([node for node in graph["nodes"] if node.get("ip")=="172.16.16.1"])==1
    assert gateway["observed"] is True
    assert gateway["hostname"]=="router.local"
    assert any(edge["evidence"]=="configured_and_observed_arp" for edge in graph["edges"])
    # No edge claims a direct link between the two remote devices.
    assert not any(edge["source"]=="device:172.16.16.1" and edge["target"]=="device:172.16.16.2" for edge in graph["edges"])


def test_incomplete_device_metadata_has_stable_node_and_explainable_edge():
    graph=build_topology(config(),[{"ip":"172.16.16.3","mac":None,"hostname":None,"vendor":None}])
    node=next(node for node in graph["nodes"] if node.get("ip")=="172.16.16.3")
    edge=next(edge for edge in graph["edges"] if edge["target"]==node["id"])
    assert node["observed"] is True and node["mac"] is None
    assert "unavailable: mac, hostname, vendor" in node["details"]
    assert edge["evidence"]=="observed_arp"
    dot=topology_to_dot(graph)
    assert "subnet membership inferred" in dot
    assert "172.16.16.3" in dot
