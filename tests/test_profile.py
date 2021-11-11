import cProfile
import pstats
import re
import nca
from nca import nca_main
#cProfile.run('re.compile("foo|bar")')
cProfile.run(r'nca_main(["--scheme", r"C:\Users\847978756\npv\npv_new_repo\network-config-analyzer\tests\istio_testcases\example_policies\bookinfo-demo\bookinfo-test-request-attrs-scheme.yaml"])', 'res8.txt')
p = pstats.Stats('res8.txt')
p.strip_dirs().sort_stats(-1).print_stats()
