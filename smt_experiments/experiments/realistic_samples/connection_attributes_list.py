from smt_experiments.experiments.realistic_samples.connection_attributes import ConnectionAttributes

N_PEERS = 1_000
MAX_PORT = 2 ** 16

COMPLEX_CONNECTION_ATTR_LIST = [
    # 1: capture-all communication with GET
    ConnectionAttributes(
        methods=['GET']
    ),
    # 2: capture all communications from certain ports
    ConnectionAttributes(
        src_ports=[(0, 1_000), 1234, 4321],
        negate_src_ports=True,
        dst_ports=[(0, 1_000), 1234, 4321],
        negate_dst_ports=True
    ),
    # 3: an examples with a specific request
    ConnectionAttributes(
        src_ports=[443],
        dst_ports=[443],
        methods=['GET'],
        paths=['/server/request'],
        hosts=['/us/*'],
    ),
    # 4. another example with a specific request
    ConnectionAttributes(
        src_ports=[443, 444],
        dst_ports=[443, 444],
        methods=['GET', 'PUT', 'POST', 'DELETE'],
        paths=['/server/request', '/server/update', '/server2/*'],
        hosts=['/us/*', '/canada/*'],
    ),
    # 5:
    ConnectionAttributes(
        src_ports=[(1024, 2048), (4000, 6000)],
        dst_ports=[(1024, 4000), (400, 600), 5555],
        methods=['GET', 'PUT'],
        paths=['/server2/*', '*/update'],
        negate_paths=True,
        hosts=['/canada/*', '/us/*', '/my/funny/cat'],
    ),
    # 6:
    ConnectionAttributes(
        src_ports=[(1024, 2048), (4000, 6000), 6002, 6007],
        dst_ports=[(1024, 4000), (400, 600), 5555, 17, 42],
        negate_dst_ports=True,
        methods=['GET', 'DELETE'],
        paths=['/server2/update', '*/update', '*/request', '/server3/fun'],
        hosts=['/canada/*', '/us/*', '/my/funny/cat'],
        negate_hosts=True,
    ),
    # 7:
    ConnectionAttributes(
        src_ports=[i for i in range(0, MAX_PORT, 100)],
        dst_ports=[(0, MAX_PORT // 3), (2 * (MAX_PORT // 3), MAX_PORT)],
        paths=['/server2/*', '*/update', '*/request', '/server3/fun', '/server1/not/fun'],
    ),
    # 8:
    ConnectionAttributes(
        src_ports=[11, 111, 1, 22, 2, 222, (1024, 2048), (4000, 6000), 6002, 6007],
        dst_ports=[(1024, 4000), (400, 600), 5555, 17, 42, 11, 1],
        paths=['/server2/*', '*/update', '/server3/fun'],
        hosts=['/canada/*', '/my/funny/cat'],
    ),
    # 9:
    ConnectionAttributes(
        src_ports=[(1024, 1048), (2024, 2048), (4000, 5005), 6002, 6007],
        dst_ports=[1, 2, 3, 123, (1024, 4000), (400, 600), 5555, 17, 42],
        methods=['GET', 'DELETE', 'PUT'],
        paths=['*/fun', '/server/*', '/server1/*'],
        negate_paths=True,
        hosts=['/canada/*', '/us/newyork/*', '/france/paris/*'],
    ),
    # 10:
    ConnectionAttributes(
        src_ports=[(1024, 2048), (4000, 6000), 6002, 6007],
        dst_ports=[(1024, 4000), (400, 600), 5555, 17, 42],
        negate_dst_ports=True,
        methods=['PUT', 'DELETE', 'CONNECT'],
        paths=['*/update', '*/request', '/server3/*'],
        hosts=['/my/funny/cat'],
    ),
]

SIMPLE_CONNECTION_ATTR_LIST = [
    # 1.
    ConnectionAttributes(
        src_ports=[(30000, 32767)],
        dst_ports=[(30000, 32767)],
    ),
    # 2.
    ConnectionAttributes(
        src_ports=[9050],
        dst_ports=[9000],
    ),
    # 3.
    ConnectionAttributes(
        src_ports=[5555],
        dst_ports=[5555],
    ),
    # 4.
    ConnectionAttributes(
        src_ports=[3456],
    ),
    # 5.
    ConnectionAttributes(
        dst_ports=[6543],
    ),
    # 6.
    ConnectionAttributes(
        src_ports=[(0, 1024)],
        negate_src_ports=True,
        dst_ports=[(0, 1024)],
        negate_dst_ports=True
    ),
    # 7.
    ConnectionAttributes(
        methods=['GET'],
        paths=['/info*']
    ),
    # 8.
    ConnectionAttributes(
        methods=['POST'],
        paths=['/data']
    ),
    # 9.
    ConnectionAttributes(
        methods=['GET', 'HEAD'],
        hosts=['*.example.com'],
        paths=['/admin*'],
        negate_paths=True
    ),
]
