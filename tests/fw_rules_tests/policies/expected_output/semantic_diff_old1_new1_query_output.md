|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|semantic_diff, config1: new1, config2: old1, key: Added connections between persistent peers||||||
||[demo]|[bank-ui]|[demo]|[account-command]|All but {protocols:TCP,dst_ports:8080,9090},{protocols:UDP,dst_ports:8080}|
|semantic_diff, config1: new1, config2: old1, key: Removed connections between persistent peers||||||
||[demo]|[account-query]|[demo]|[bank-ui]|All but {protocols:TCP,dst_ports:8080}|
