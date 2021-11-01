|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: poc1||||||
||[default]|[app in (checkoutservice,frontend,recommendationservice)]|[default]|[productcatalogservice]|TCP dst_ports: (3550, ),|
||[default]|[app in (checkoutservice,frontend)]|[default]|[shippingservice]|TCP dst_ports: (50051, ),|
||[default]|[checkoutservice]|[default]|[paymentservice]|TCP dst_ports: (50051, ),|
||[default]|[frontend]|[default]|[checkoutservice]|TCP dst_ports: (5050, ),|
||[default]|[cartservice]|[default]|[redis-cart]|TCP dst_ports: (6379, ),|
||[default]|[app in (checkoutservice,frontend)]|[default]|[currencyservice]|TCP dst_ports: (7000, ),|
||[default]|[app in (checkoutservice,frontend)]|[default]|[cartservice]|TCP dst_ports: (7070, ),|
|||ip block: 0.0.0.0/0|[default]|[frontend]|TCP dst_ports: (8080, ),|
|||ip block: ::/0|[default]|[frontend]|TCP dst_ports: (8080, ),|
||[default]|[checkoutservice]|[default]|[emailservice]|TCP dst_ports: (8080, ),|
||[default]|[frontend]|[default]|[recommendationservice]|TCP dst_ports: (8080, ),|
||[default]|[loadgenerator]|[default]|[frontend]|TCP dst_ports: (8080, ),|
||[default]|[frontend]|[default]|[adservice]|TCP dst_ports: (9555, ),|


