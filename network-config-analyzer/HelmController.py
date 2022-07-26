#
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
Utility class to control HELM
"""


"""
run_and_get_output - activate command line commands (like helm)

HELM cmd exmaple: helm template <name>(ncatest) <path of chart>(.\prometheus) 
results to screen: 
wrote .\test_nca_helm_integrity\prometheus/charts/kube-state-metrics/templates/serviceaccount.yaml
wrote .\test_nca_helm_integrity\prometheus/templates/alertmanager/serviceaccount.yaml
wrote .\test_nca_helm_integrity\prometheus/templates/node-exporter/serviceaccount.yaml
etc...


Todo:
1. see if helm can search for chart files in a local directory (and not a repo)
2. make a function that gets all helm dirs (those that has the Chart and Values files.
3. activate helm and get the files from stdout to a list of files, and keep a list of yaml files that was templates
4. add those files to the normal yaml parsing job
5. make a function that gives a warining when {{ file is found, unless it is in the helm list
6. make tests that resolve helm files and extract the correct topology, with stand alone files.




"""
