**CredSSP Credential Delegation**

Policy Scope, Server Authentication, and Windows Credential Handling

Research draft  
Andrew Petro


# Executive Summary

CredSSP enables an application to delegate a user's credentials from a client to a target server. Unlike constrained delegation, the protocol transfers reusable credential material so the target can establish a logon session or access resources in the user's context.

This research examined four practical boundaries: whether delegation is controlled by application code or caller privilege; how wildcard destination policy behaves; what the Windows Kerberos path treats as successful server authentication; and how delegated password material is represented on the network and exposed by the Windows server-side API.

**Central conclusion:** CredSSP security depends on the boundary being discussed. Policy authorization, protocol authentication, transport protection, credential transmission, and Windows server-side handling are related but distinct controls.

The experiments indicate that no special local privilege was required merely to invoke default-credential delegation. A bare wildcard policy entry matched arbitrary tested SPN values, including a service running on a non-domain-joined host. In the Kerberos test cases, delegation success tracked successful user-to-user authentication involving a server-side TGT for the requested principal. Decrypted network captures contained the user's actual password. Microsoft's Windows server implementation then returned that password through SSPI as a CredTrustedProtection value rather than plaintext.

These results do not establish that every third-party CredSSP server applies the same server-side protection. The protected representation is a Windows implementation control applied after the credential reaches the server, not a demonstrated protocol requirement.

For Additional details about the testing performed see the CredSSP_Research_draft.pdf document within the repository. 
