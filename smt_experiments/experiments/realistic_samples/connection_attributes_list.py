from smt_experiments.experiments.realistic_samples.connection_attributes import ConnectionAttributes

N_PEERS = 1_000

CONNECTION_ATTR_LIST = [
    # 1: capture-all communication
    ConnectionAttributes(
        peers=[(0, N_PEERS)],
    ),
    # 2: capture all communications from certain ports
    ConnectionAttributes(
        peers=[(0, N_PEERS)],
        src_ports=[(0, 1_000), 1234, 4321],
        negate_src_ports=True,
        dst_ports=[(0, 1_000), 1234, 4321],
        negate_dst_ports=True
    ),
    # 3: an examples with a specific request
    ConnectionAttributes(
        peers=[(0, 40), 42, 123, (200, 400), 444, 666],
        src_ports=[443],
        dst_ports=[443],
        methods=['GET'],
        paths=['/server/request'],
        hosts=['/us/*'],
    ),
    # 4. another example with a specific request
    ConnectionAttributes(
        peers=[(0, 40), 42, 123, (250, 400), 666, (700, 999)],
        src_ports=[443, 444],
        dst_ports=[443, 444],
        methods=['GET', 'PUT', 'POST', 'DELETE'],
        paths=['/server/request', '/server/update', '/server2/*'],
        hosts=['/us/*', '/canada/*'],
    ),



]