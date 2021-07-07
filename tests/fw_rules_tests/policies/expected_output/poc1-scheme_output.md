|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: poc1||||||
||[default]|[app in (checkoutservice,frontend,recommendationservice)]|[default]|[productcatalogservice]|TCP 3550,|
||[default]|[app in (checkoutservice,frontend)]|[default]|[shippingservice]|TCP 50051,|
||[default]|[checkoutservice]|[default]|[paymentservice]|TCP 50051,|
||[default]|[frontend]|[default]|[checkoutservice]|TCP 5050,|
||[default]|[cartservice]|[default]|[redis-cart]|TCP 6379,|
||[default]|[app in (checkoutservice,frontend)]|[default]|[currencyservice]|TCP 7000,|
||[default]|[app in (checkoutservice,frontend)]|[default]|[cartservice]|TCP 7070,|
|||ip block: 0.0.0.0/0|[default]|[frontend]|TCP 8080,|
||[default]|[checkoutservice]|[default]|[emailservice]|TCP 8080,|
||[default]|[frontend]|[default]|[recommendationservice]|TCP 8080,|
||[default]|[loadgenerator]|[default]|[frontend]|TCP 8080,|
||[default]|[frontend]|[default]|[adservice]|TCP 9555,|


