# secretagent
Homebrew lookup of AWS Secrets and injection into K8s pods' env during pod creation

This is a mini-https server that ties into the creation stages of Kubernetes pods. Kuberentes will make a pod creation request that this server will intercept and mutate if conditions are met, or will simply pass the request through if it doesn't find anything to indicate a pod definition patch is intended.

Expects to run as a deployment or daemonset in a cluster. One or multiple instances of SecretAgent will work fine so long as they are not overloaded. This CAN become a bottleneck if you're careless with its use. A valid certificate and IRSA rights (or another local form of AWS auth) to the intended AWS Secrets are also expected.

Secrets will be defined in micro-service deployments, etc., in the form "ASM_STORED_SECRET_" + "/your/secret/path" (variable) + "?" + "desiredKey" (variable). This process will discard the AWS_STORED_SECRET_ prefix, seek the Secret at /your/secret/path and place a GET request, discard the "?" delimiter, and utilize the desiredKey to determine which value to return and inject into your pod's definition. Any number of Secrets may be injected in this process.

This mutating webhook was designed in a fairly predictable environment with known aws profile and region. In order to make this accessible to the general public, it is expected that AWS_PROFILE and AWS_DEFAULT_REGION are established in this container's envinronment. Otherwise you may search for these envvars in the .go file and replace them with whatever works for you.
