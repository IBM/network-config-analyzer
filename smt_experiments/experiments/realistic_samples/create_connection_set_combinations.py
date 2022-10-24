def _get_allow_deny_combinations_indices(n_items: int):
    """A combination is a pair of lists, one is the allow_list, and the second is the deny list.
    yields two lists, first is the allow_list, the second is the deny_list."""
    # singleton: for each item i, allow_list=[x] and deny_list=[]
    for i in range(n_items):
        allow_list = [i]
        deny_list = []
        yield allow_list, deny_list

    # allow only - items from 0 to i are allowed
    for i in range(1, n_items):
        allow_list = [j for j in range(i+1)]
        deny_list = []
        yield allow_list, deny_list

    # allow and deny - items from 0 to i are allowed, and i+1 to n_items-1 are denied
    for i in range(n_items - 1):
        allow_list = [j for j in range(i+1)]
        deny_list = [j for j in range(i+1, n_items)]
        yield allow_list, deny_list

    # allow and deny - items from 0 to i are denied, and i+1 to n_items-1 are allowed
    for i in range(n_items - 1):
        allow_list = [j for j in range(i+1, n_items)]
        deny_list = [j for j in range(i+1)]
        yield allow_list, deny_list

    # allow only - even indices
    allow_list = [i for i in range(0, n_items, 2)]
    deny_list = []
    yield allow_list, deny_list

    # allow only - odd indices
    allow_list = [i for i in range(1, n_items, 2)]
    deny_list = []
    yield allow_list, deny_list

    # allow and deny - even are allowed, odd are denied
    allow_list = [i for i in range(0, n_items, 2)]
    deny_list = [i for i in range(1, n_items, 2)]
    yield allow_list, deny_list

    # allow and deny - odd are allowed, even are denied
    allow_list = [i for i in range(1, n_items, 2)]
    deny_list = [i for i in range(0, n_items, 2)]
    yield allow_list, deny_list


def get_allow_deny_combinations(connection_attr_list: list):
    n_items = len(connection_attr_list)
    for allow_list_indices, deny_list_indices in _get_allow_deny_combinations_indices(n_items):
        allow_list = [connection_attr_list[i] for i in allow_list_indices]
        deny_list = [connection_attr_list[i] for i in deny_list_indices]
        yield allow_list, deny_list


def example():
    counter = 0
    from smt_experiments.experiments.realistic_samples.connection_attributes_list import COMPLEX_CONNECTION_ATTR_LIST
    n_items = len(COMPLEX_CONNECTION_ATTR_LIST)
    print(f'n_items={n_items}')
    for allow_list, deny_list in _get_allow_deny_combinations_indices(n_items):
        print(f'allow_list={allow_list}')
        print(f'deny_list={deny_list}')
        counter += 1
    print(f'counter={counter}')
    print(f'n_pairs={counter * (counter - 1) // 2}')


if __name__ == '__main__':
    example()
