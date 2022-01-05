# NCA Tekton Tasks

This directory contains two Tekton Tasks, producing [connectivity reports](#netpol-report-task) and [connectivity-diff reports](#netpol-diff-task).
These Tasks are part of a wider attempt to provide [shift-left automation for generating and maintaining Kubernetes Network Policies](https://np-guard.github.io/).

## <a name="netpol-report-task"></a>k8s-netpol-report

This Task produces cluster-connectivity reports for your K8s-based application. It will first extract the cluster's connectivity graph by scanning your repository for YAML files containing endpoint resources (e.g., Deployments) or connectivity resources (Kubernetes NetworkPolicies). It will then summarize the cluster connectivity in either a consice textual report or a graphical representation.

An example connectivity report (in md format):

|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|||||||
||[default]|[app in (checkoutservice,frontend,recommendationservice)]|[default]|[productcatalogservice]|TCP 3550|
||[default]|[app in (checkoutservice,frontend)]|[default]|[shippingservice]|TCP 50051|
||[default]|[frontend]|[default]|[checkoutservice]|TCP 5050|
||[default]|[cartservice]|[default]|[redis-cart]|TCP 6379|
||[default]|[app in (checkoutservice,frontend)]|[default]|[currencyservice]|TCP 7000|
||[default]|[app in (checkoutservice,frontend)]|[default]|[cartservice]|TCP 7070|
|||ip block: 0.0.0.0/0|[default]|[frontend]|TCP 8080|
||[default]|[checkoutservice]|[default]|[emailservice]|TCP 8080|
||[default]|[frontend]|[default]|[recommendationservice]|TCP 8080|
||[default]|[loadgenerator]|[default]|[frontend]|TCP 8080|
||[default]|[frontend]|[default]|[adservice]|TCP 9555|

### Install the Task

```
kubectl apply -f https://raw.githubusercontent.com/IBM/network-config-analyzer/master/tekton/netpol-report-task.yaml
```

### Parameters
* **deployment-path**: The path in the 'source' workspace where deployment yamls are.  (_default:_ `.`)
* **netpol-path**: The path in the 'source' workspace where the NetworkPolicy yamls are stored (_default:_ `.`)
* **output-format**: Connectivity report format: either "md", "yaml", "csv", "dot" or "txt" (_default:_ `md`)
* **output-dir**: The directory under 'source' workspace to write connectivity report file into (_default:_ `netpol-report-output-dir`)

### Workspaces
* **source**: A [Workspace](https://github.com/tektoncd/pipeline/blob/main/docs/workspaces.md) containing the application YAMLs to analyze.

### Results
* **connectivity-report-file**: Path in 'sources' workspace of the connectivity report file.

### Platforms

The Task can be run on `linux/amd64`.

### Usage

This TaskRun runs the Task to obtain a connectivity report for a previously checked-out app.

```yaml
apiVersion: tekton.dev/v1beta1
kind: TaskRun
metadata:
  name: report-connectivity
spec:
  taskRef:
    name: k8s-netpol-report
  workspaces:
  - name: source
    persistentVolumeClaim:
      claimName: my-source
```

For a more complete example, see [this PiplineRun](netpol-report-plr.yaml).

## <a name="netpol-diff-task"></a>k8s-netpol-diff
This Task produces a semantic diff of the expected connectivity in a given Kubernetes cluster, as dictated by resource-defining YAML files in a GitHub repository. The action will compare the connectivity before and after commits which change the cluster's endpoints (e.g., Deployments) or its NetworkPolicies. The reported diff is particularly useful for **reviewing changes** to cluster configuration, as their effect on connectivity may be hard to figure out just by looking at textual file diffs.

An example diff output (in md format):
|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|Added connections||||||
||[demo]|[ui]|[demo]|[query-service]|TCP 8080|
||[demo]|[cli-service]|[demo]|[ui]|All connections|
|Removed connections||||||
||[demo]|[ui]|[demo]|[query-service]|UDP 8080|
||[demo]|ip block: 0.0.0.0/0|[demo]|[query-service]|All connections|

### Install the Task

```
kubectl apply -f https://raw.githubusercontent.com/IBM/network-config-analyzer/master/tekton/netpol-diff-task.yaml
```

### Parameters
* **old-deployment-path**: The path in the 'old' workspace where deployment yamls are.  (_default:_ `.`)
* **old-netpol-path**: The path in the 'old' workspace where the NetworkPolicy yamls are stored (_default:_ `.`)
* **new-deployment-path**: The path in the 'new' workspace where deployment yamls are.  (_default:_ `.`)
* **new-netpol-path**: The path in the 'new' workspace where the NetworkPolicy yamls are stored (_default:_ `.`)
* **output-format**: Connectivity report format: either "md", "yaml" or "txt" (_default:_ `md`)
* **output-dir**: The directory under 'new' workspace to write connectivity diff file into. (_default:_ `netpol-diff-output-dir`)

### Workspaces
* **old**: A [Workspace](https://github.com/tektoncd/pipeline/blob/main/docs/workspaces.md) containing the old application YAMLs to analyze.
* **new**: A [Workspace](https://github.com/tektoncd/pipeline/blob/main/docs/workspaces.md) containing the new application YAMLs to analyze.

### Results
* **connectivity-diff-file**: Path in 'new' workspace of the connectivity diff file.

### Platforms

The Task can be run on `linux/amd64`.

### Usage

This TaskRun runs the Task to obtain a connectivity report for a previously checked-out app.

```yaml
apiVersion: tekton.dev/v1beta1
kind: TaskRun
metadata:
  name: report-connectivity
spec:
  taskRef:
    name: k8s-netpol-diff
  workspaces:
  - name: old
    persistentVolumeClaim:
      claimName: my-old-source
  - name: new
    persistentVolumeClaim:
      claimName: my-new-source
```

For a more complete example, see [this PiplineRun](netpol-diff-plr.yaml).
