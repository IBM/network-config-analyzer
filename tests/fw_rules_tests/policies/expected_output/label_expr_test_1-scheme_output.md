|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|test_app_label, config: test1||||||
|||ip block: 0.0.0.0/0|[default]|[has(app)]|All connections|

|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|test_app_label, config: test2||||||
|||ip block: 0.0.0.0/0|[default]|[app in (A,B)]|All connections|
|||ip block: 0.0.0.0/0|[default]|[c]|All connections|

|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|test_app_label, config: test3||||||
|||ip block: 0.0.0.0/0|[default]|[!has(app) or app in (dev)]|All connections|

|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|test_app_label, config: test4||||||
|||ip block: 0.0.0.0/0|[default]|[app in (dev)]|All connections|
|||ip block: 0.0.0.0/0|[default]|[d]|All connections|


|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|test_tier_and_app_label, config: test5||||||
|||ip block: 0.0.0.0/0|[default]|[app in (G) and tier in (W)]|All connections|

|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|test_tier_and_app_label, config: test6||||||
|||ip block: 0.0.0.0/0|[default]|[has(app) and has(tier)]|All connections|

|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|test_tier_and_app_label, config: test7||||||
|||ip block: 0.0.0.0/0|[default]|[!has(app) and !has(tier)]|All connections|

|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|test_tier_and_app_label, config: test8||||||
|||ip block: 0.0.0.0/0|[default]|[!has(tier) and app in (B)]|All connections|

|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|test_tier_and_app_label, config: test9||||||
|||ip block: 0.0.0.0/0|[default]|[!has(tier) and {!has(app) or app in (B)}]|All connections|

|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|test_tier_and_app_label, config: test10||||||
|||ip block: 0.0.0.0/0|[default]|[(has(app) and app not in (B)) and tier in (W,X)]|All connections|


