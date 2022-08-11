topology: 
----------
    default/details (x1) 
    default/productpage (x1) 
    default/ratings (x1) 
    default/reviews (x3) 
    istio-system/istio-ingressgateway 
    ingress-nginx/ingress-nginx-controller 




config: testcase26-config-1-k8s-istio-ingress
-----------------------------------------------

input policies - describe inferred connectivity (as expected) from each policy:

testcase26-networkpolicy-k8s:   


    ratings ->  productpage (all connections) 
    ratings cannot egress to anything else but productpage 



testcase26-networkpolicy-istio:  


    ratings ->  productpage (TCP restricted to GET method, non-TCP is not restricted)
    on TCP, productpage cannot get ingress from anything else than ratings (for non-TCP it is not limited)




testcase26-ingress-policy 


    ingress-nginx-controller -> details (TCP restricted to path /details*, port 9080)



connectivity results:



    src: 0.0.0.0/0 dst_ns: [default] dst_pods: [*] conn: All but TCP
    src: 0.0.0.0/0 dst_ns: [default] dst_pods: [app!=productpage] conn: All connections
    src: 0.0.0.0/0 dst_ns: [ingress-nginx,istio-system] dst_pods: [*] conn: All connections
    src: ::/0 dst_ns: [default] dst_pods: [*] conn: All but TCP
    src: ::/0 dst_ns: [default] dst_pods: [app!=productpage] conn: All connections
    src: ::/0 dst_ns: [ingress-nginx,istio-system] dst_pods: [*] conn: All connections
    src_ns: [default,istio-system] src_pods: [*] dst_ns: [default] dst_pods: [ratings-v1-b6994bb9] conn: All connections
    src_ns: [default] src_pods: [app in (details,reviews)] dst_ns: [default] dst_pods: [*] conn: All but TCP
    src_ns: [default] src_pods: [app in (details,reviews)] dst_ns: [default] dst_pods: [app=reviews] conn: All connections
    src_ns: [default] src_pods: [app!=ratings] dst: 0.0.0.0/0 conn: All connections
    src_ns: [default] src_pods: [app!=ratings] dst: ::/0 conn: All connections
    src_ns: [default] src_pods: [app!=ratings] dst_ns: [ingress-nginx,istio-system] dst_pods: [*] conn: All connections
    src_ns: [default] src_pods: [app=reviews] dst_ns: [default] dst_pods: [details-v1-79f774bdb9] conn: All connections
    src_ns: [default] src_pods: [productpage-v1-6b746f74dc] dst_ns: [default] dst_pods: [*] conn: All connections
    src_ns: [default] src_pods: [ratings-v1-b6994bb9] dst_ns: [default] dst_pods: [productpage-v1-6b746f74dc] conn: All but TCP {'methods': 'all but GET'}
    src_ns: [ingress-nginx,istio-system] src_pods: [*] dst_ns: [ingress-nginx] dst_pods: [*] conn: All connections
    src_ns: [ingress-nginx] src_pods: [*] dst_ns: [default] dst_pods: [details-v1-79f774bdb9] conn: TCP {'dst_ports': '9080', 'paths': '/details(/[\\--9A-Z_a-z]+)?', 'hosts': 'demo.localdev.me'}
    src_ns: [istio-system] src_pods: [*] dst: 0.0.0.0/0 conn: All connections
    src_ns: [istio-system] src_pods: [*] dst: ::/0 conn: All connections
    src_ns: [istio-system] src_pods: [*] dst_ns: [default] dst_pods: [*] conn: All but TCP
    src_ns: [istio-system] src_pods: [*] dst_ns: [default] dst_pods: [app in (details,reviews)] conn: All connections
    src_ns: [istio-system] src_pods: [*] dst_ns: [istio-system] dst_pods: [*] conn: All connections