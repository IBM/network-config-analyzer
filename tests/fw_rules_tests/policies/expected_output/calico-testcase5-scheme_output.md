|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np_allowFirst||||||
||[kube-system]|[*]||ip block: 0.0.0.0/0|All connections|
||[kube-system]|[tier in (frontend)]|[kube-system]|[*]|All connections|


|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np_denyFirst||||||
||[kube-system]|[tier in (frontend)]|[kube-system]|[*]|ICMP [0-254] => [0-255];,UDP 1-65536,ICMPv6 [0-254] => [0-255];,SCTP 1-65536,UDPLite,protocols numbers: 2-5,7-16,18-57,59-131,133-134,136-255|
||[kube-system]|[*]||ip block: 0.0.0.0/0|All connections|
||[kube-system]|[app in (file-plugin,helm,keepalived-watcher,storage-watcher,vpn)]|[kube-system]|[*]|All connections|


