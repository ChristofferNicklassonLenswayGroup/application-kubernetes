# Kubernetes Opspack (BETA)

Kubernetes is an open-source system for automating deployment, scaling and management of containerised applications that was originally designed by Google.

## What You Can Monitor

Monitors the performance and system health of your Kubernetes environment (BETA)

## Service Checks

| Service Check | Description |
|:------------- | :------------- |
|Node Status|Nodes which are ready, whether they are out of disk, whether they have memory pressure and whether they have disk pressure |
|Pods Status|The state of all pods |
|File Descriptors|Number of open file descriptors |
|Http Requests Stats|Total number of HTTP requests made and HTTP latency |
|Process Cpu Seconds|Total user and system CPU time spent in seconds |
|Etcd Helper Stats|Contains: Etcd Helper Cache Hits, Etcd Helper Cache Miss, Etcd Helper Cache Hit Percentage |
|Node Memory Stats|Provides: Percentage of memory in use, memory capacity and total memory available |

## Setup Kubernetes for Monitoring

If you are using http to connect to your Kubernetes API, set up a proxy to connect to the Kubernetes API server by using one of the following commands:

Gives access to everything:

```kubectl proxy --port=8080 --address='0.0.0.0' --accept-hosts='^*$'```

Gives access to only your network (Recommended):

```kubectl proxy --port=8080 --address='0.0.0.0'--accept-hosts='^192\.168\.*'```

![Setup Kubernetes for Monitoring](/docs/img/setup_kubernetes_for_monitoring.png?raw=true)

## Setup and Configuration

To configure and utilize this Opspack, you simply need to add the 'Application - Kubernetes' Opspack to your Opsview Monitor system.

#### Step 1: Add the host template

![Add Host Template](/docs/img/add_kubernetes_host.png?raw=true)

#### Step 2: Add and configure variables required for this host

* KUBERNETES_PORT - Port to access Kubernetes API

![Add Port Variable](/docs/img/add_kubernetes_port_variable.png?raw=true)

* KUBERNETES_NODE - multivariable for each Node within the cluster you want to monitor

![Add Node Variable](/docs/img/add_kubernetes_node_variable.png?raw=true)

* KUBERNETES_CREDENTIALS  - Authentication scheme (either http or https), Certificate Authority, Client Certificate, Client Key

![Add Credentials Variable](/docs/img/add_kubernetes_credentials_variable.png?raw=true)

#### Step 3: Reload and the system will now be monitored

![View Host Service Checks](/docs/img/view_kubernetes_service_checks.png?raw=true)
