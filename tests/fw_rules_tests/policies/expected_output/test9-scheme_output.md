|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np9|
|||ip block: 0.0.0.0/0|[default]|[{app in (skydive)} and {tier in (analyzer)}]|All connections|
|||ip block: 0.0.0.0/0|[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[default]|[{app in (skydive)} and {tier in (analyzer)}]||ip block: 0.0.0.0/0|All connections|
||[default]|[{app in (skydive)} and {tier in (analyzer)}]|[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]||ip block: 0.0.0.0/0|All connections|
||[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[default]|[{app in (skydive)} and {tier in (analyzer)}]|All connections|
||[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|


