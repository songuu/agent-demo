package main

import rego.v1

pod_spec := input.spec.template.spec if {
	input.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}
}

pod_spec := input.spec.jobTemplate.spec.template.spec if {
	input.kind == "CronJob"
}

all_containers := array.concat(
	object.get(pod_spec, "initContainers", []),
	object.get(pod_spec, "containers", []),
)

deny contains message if {
	pod_spec
	object.get(pod_spec.securityContext, "runAsNonRoot", false) != true
	message := sprintf("%s/%s must set pod runAsNonRoot=true", [input.kind, input.metadata.name])
}

deny contains message if {
	some container in all_containers
	security_context := object.get(container, "securityContext", {})
	object.get(security_context, "allowPrivilegeEscalation", true) != false
	message := sprintf(
		"%s/%s container %s must disable privilege escalation",
		[input.kind, input.metadata.name, container.name],
	)
}

deny contains message if {
	some container in all_containers
	security_context := object.get(container, "securityContext", {})
	object.get(security_context, "readOnlyRootFilesystem", false) != true
	message := sprintf(
		"%s/%s container %s must use a read-only root filesystem",
		[input.kind, input.metadata.name, container.name],
	)
}

deny contains message if {
	some container in all_containers
	not contains(container.image, "@sha256:")
	message := sprintf(
		"%s/%s container %s must use an immutable sha256 image digest",
		[input.kind, input.metadata.name, container.name],
	)
}

deny contains message if {
	object.get(pod_spec, "hostNetwork", false)
	message := sprintf("%s/%s must not use the host network", [input.kind, input.metadata.name])
}
