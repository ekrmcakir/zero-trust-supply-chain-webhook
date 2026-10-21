# Zero-Trust Software Supply Chain Security Architecture

This document details the architectural design, verification lifecycle, cryptographic trust models, and threat prevention mechanisms implemented in `zero-trust-supply-chain-webhook`.

---

## 1. High-Level Architecture

The platform establishes an end-to-end cryptographic trust chain from source code commit through CI/CD artifact creation down to Kubernetes cluster runtime admission.

```mermaid
flowchart TD
    subgraph Developer & CI/CD Pipeline
        Dev[Developer Git Commit] --> Build[GitHub Actions Build]
        Build --> Syft[Syft / CycloneDX: Generate SBOM]
        Build --> Trivy[Trivy / Grype: Vulnerability Scan]
        Build --> CosignSign[Cosign: Keyless / ECDSA Signing]
        Syft --> InToto[in-toto Attestation Envelope]
        Trivy --> InToto
        InToto --> CosignAttest[Cosign: Attach Attestation to OCI]
        CosignSign --> Registry[(Enterprise OCI Registry\nGHCR / AWS ECR)]
        CosignAttest --> Registry
    end

    subgraph Kubernetes Control Plane
        KubeAPI[kube-apiserver\nAdmission Review]
        Webhook[Zero-Trust Admission Webhook\nGo Daemon on :8443 TLS]
        Kyverno[Kyverno ClusterPolicies]
        OPA[OPA Gatekeeper Constraints]
        Cache[(In-Memory LRU Cache\nTTL Expiring)]
        Rekor[(Sigstore Rekor / Fulcio\nTransparency Log)]
        Prom[Prometheus Metrics Exporter\n:9090/metrics]
    end

    subgraph Cluster Runtime
        PodAdmitted[Pod Scheduled & Admitted\nNon-Root, Drop ALL, ReadOnlyRootFS]
        PodRejected[Admission Blocked\n403 Forbidden with CVE Audit Message]
    end

    Registry --> Webhook
    KubeAPI <-->|AdmissionReview v1| Webhook
    Webhook <--> Cache
    Webhook -.->|Verify Transparency| Rekor
    Webhook --> Prom

    Webhook -->|Compliant & Signed| PodAdmitted
    Webhook -->|Unsigned / Untrusted / CVE > Threshold| PodRejected
```

---

## 2. Cryptographic Verification Sequence

Every incoming pod creation or update request traverses an optimized, multi-tier evaluation pipeline:

```mermaid
sequenceDiagram
    autonumber
    actor Kube as Kube-APIServer
    participant WH as Admission Webhook (:8443)
    participant Cache as Memory LRU Cache
    participant OCI as OCI Registry (GHCR/ECR)
    participant Crypto as ECDSA / Cosign Engine
    participant Policy as Hardening & SBOM Evaluator
    participant Metric as Prometheus Exporter

    Kube->>WH: POST /validate (AdmissionReview v1)
    Note over WH: Check Namespace Exclusions (kube-system)
    
    loop For each container image
        WH->>Policy: Check Registry Whitelist & :latest tag
        alt Untrusted Registry or :latest tag
            Policy-->>WH: Rejection Verdict (Reason: UNTRUSTED_REGISTRY)
            WH->>Metric: Inc(rejected, UNTRUSTED_REGISTRY)
            WH-->>Kube: 403 Forbidden (Detailed error)
        end

        WH->>Cache: Lookup Image Digest / Verification Status
        alt Cache Hit (Valid TTL)
            Cache-->>WH: Cached Verdict (Sub-millisecond latency)
        else Cache Miss
            WH->>OCI: Query OCI Referrers / Cosign Signature tag (.sig)
            OCI-->>WH: Cosign Signature & In-Toto Payload
            WH->>Crypto: Verify Signature (ECDSA P-256 / Ed25519)
            Crypto-->>WH: Signature Valid
            WH->>Policy: Evaluate SBOM & CVE Thresholds (Max Critical = 0)
            Policy-->>WH: Attestation Approved
            WH->>Cache: Store Result with TTL
        end
    end

    WH->>Policy: Validate Pod Security Context (RunAsNonRoot, ReadOnlyRootFS)
    Policy-->>WH: Hardening Validated
    WH->>Metric: Inc(admitted), Observe(duration)
    WH-->>Kube: 200 OK (Allowed: true)
```

---

## 3. Policy Engine Comparison

The platform provides dual operational pathways: a high-throughput **Native Go Admission Webhook daemon** and **declarative Kyverno / OPA Gatekeeper policies**.

| Capability | Native Go Webhook (`cmd/webhook`) | Kyverno (`policies/kyverno`) | OPA Gatekeeper (`policies/opa`) |
| :--- | :--- | :--- | :--- |
| **Performance & Latency** | **Sub-millisecond** with in-memory LRU caching | Fast (~5-15ms) | Standard (~10-25ms) |
| **Cosign Verification** | Native ECDSA / Ed25519 & Sigstore Keyless | Built-in `verifyImages` stanza | Via Rego extension / external data |
| **In-Toto SBOM Analysis** | Built-in JSON / in-toto predicate parser | Native attestation matching | Custom Rego rule parsing |
| **Audit vs. Enforce** | Configurable via `policy.mode` (`enforce`\|`audit`) | `validationFailureAction: Enforce` | `enforcementAction: deny\|dryrun` |
| **Metrics & Telemetry** | Native Prometheus histograms on `:9090` | Kyverno Prometheus metrics | Gatekeeper Prometheus metrics |
| **Resource Footprint** | Extremely lightweight (< 25MB RAM) | Standard Controller (< 150MB) | Standard Controller (< 200MB) |

---

## 4. Threat Matrix & Mitigations (SLSA Level 3 Alignment)

| Threat Vector | Attack Scenario | Prevention Mechanism in Webhook |
| :--- | :--- | :--- |
| **Supply Chain Tampering** | Attacker modifies image in transit or registry compromised | Cosign cryptographic signature verification validates image digest against tamper-proof key. |
| **Compromised Registry / Typosquatting** | Attacker deploys malicious image from unauthorized DockerHub repo | Strict **Registry Whitelisting** with wildcard matching blocks any non-approved OCI domain. |
| **Tag Mutability Attack** | Attacker overwrites `app:v1.0` or pushes malicious `:latest` | **Tag Immutability & Anti-Latest Enforcement** blocks mutable tags and mandates cryptographic SHA256 pinning. |
| **Known Exploitable CVEs** | Deployment of containers with known Log4j, OpenSSL, or kernel zero-days | **In-Toto Attestation Engine** parses scanner outputs (Trivy/Grype) and blocks images exceeding CVE thresholds. |
| **Container Breakout / Privilege Escalation** | Container runs as root, mounts root filesystem as writable, or requests `CAP_SYS_ADMIN` | **Pod Security Validator** enforces non-root execution (`runAsNonRoot: true`), `readOnlyRootFilesystem: true`, and dropping all capabilities (`drop: ["ALL"]`). |
