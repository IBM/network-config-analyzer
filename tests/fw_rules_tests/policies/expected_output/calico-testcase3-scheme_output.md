|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np_onlyAllow||||||
||[kube-system]|[app in (file-plugin,helm,keepalived-watcher,storage-watcher,vpn)]|[kube-system]|[has(tier)]|TCP 1-65536,|


|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np_FirstDenySubset||||||
||[kube-system]|[app in (helm,keepalived-watcher,vpn)]|[kube-system]|[has(tier)]|TCP 1-65536,|


|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np_firstAllowSuperSet||||||
||[kube-system]|[app in (file-plugin,helm,keepalived-watcher,storage-watcher,vpn)]|[kube-system]|[has(tier)]|TCP 1-65536,|


