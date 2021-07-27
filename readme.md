# KILT Credential API (Draft Spec version 1.0)

## Definitions

### Extension

A browser extension that stores and uses the identities and credentials of the user. 
When the user visits a webpage, the extension injects its API in this webpage.

### dApp

Decentralized application. Examples of dApp in this specification are Attester and Verifier.
It is a website that can interact with the extension via the API it exposes.


## Setting up the communication session

### Types

`extensionId` references the extension on the `GlobalKilt` object but is not used by the dApp. `name` should be a human-readable string.

```typescript
interface GlobalKilt {
    [extensionId: string]: InjectedWindowProvider
}

interface InjectedWindowProvider {
    startSession: (
        dAppName: string, 
        dAppIdentity: IPublicIdentity, 
        nonce: string
    ) => Promise<PubSubSession>
    name: string
    version: string
    specVersion: '0.1.0'
}

interface PubSubSession {
    listen: (callback: (message: Message) => Promise<void>) => Promise<void>
    close: () => Promise<void>
    send: (message: Message) => Promise<void>
    identity: IPublicIdentity
    signedNonce: string
}
```


### DApp consumes the API exposed by extension 

The dApp can get all the available extensions via iterating over the `window.kilt` object.

```typescript
function getWindowExtensions(): InjectedWindowProvider[] {
    return Object.values(window.kilt || {});
}
```

The dApp should list all available extensions it can work with. 
The user selects the extension on this list, and the communication starts from there.

```typescript
async function startExtensionSession(
    extension: InjectedWindowProvider,
    dAppName: string,
    dAppIdentity: IPublicIdentity, 
    nonce: string
): Promise<PubSubSession> {
    try {
        const session = await extension.startSession(dAppName, dAppIdentity, nonce);
        
        // This verification must happen on the server side.
        Crypto.verify(nonce, session.signedNonce, session.identity.address);
        
        return session;
    } catch (error) {
        console.error(`Error initializing ${extension.name}: ${error.message}`);
        throw error;
    }
}
```

The nonce must be used only once. 
The dApp must store a copy of the nonce on the server-side to prevent tampering. 
The dApp must verify that the signature of signedNonce returned by extension matches its identity 
to prevent replay attacks.


### Extension injects its API into a webpage

```typescript
window.kilt as GlobalKilt = window.kilt || {};

window.kilt[extensionId] = {
    startSession: async (
        dAppName: string, 
        dAppIdentity: IPublicIdentity, 
        nonce: string
    ): Promise<PubSubSession> => {
        return { /*...*/ };
    },
    name,
    version,
    specVersion: '0.1.0'
} as InjectedWindowProvider;
```

The extension must perform the following tasks in `startSession`:
- follow steps in Well Known DID Configuration to confirm that the `dAppIdentity` is controlled by the same entity
  as the page origin
- generate a temporary keypair for encryption of messages of the current session
- use this keypair to sign the dApp-provided nonce

The extension should perform the following tasks in `startSession`:
- ensure that the user has previously authorized interaction with the provided DID
- otherwise, request user authorization for this interaction


### Processing the messages

Messages should be queued until the dApp calls `listen`.

The Promise should be resolved after the dApp or the extension have finished processing the message.
If they can't handle the received message, they can reject the Promise.


### Security concerns while setting up the session

Third-party code tampering with these calls is pointless:
- modifying the dAppIdentity will be detected by Well Known DID Configuration checks
- modifying the nonce will be detected by the dApp backend
- replaying responses from other valid identities will result in signedNonce mismatch
- pretending to be the extension will fail on the next step:
  MitM will not be able to sign the message sent to extension with a DID matching the origin. 


## Messaging Protocol

#### Error

|||
|-|-|
| direction | `Extension <-> dApp` |
| message_type | `ERROR` |
| description | General error, which should abort and reset the current workflow/protocol |
| encryption | any |

content:

```typescript
interface IError {
    code: number
    reason: string
}
```

> Error codes will be provided at a later time. For now, when receiving an error, the extension and dApp should reset. // @tjwelde


### Attestation Workflow

1. **Attester proposes credential**

|||
|-|-|
| direction | `dApp -> Extension` |
| message_type | `SUBMIT_TERMS`|

content:

```typescript
interface ISubmitTerms {
    cType: string
    claim: Partial<IClaim>
    delegationId?: string
    legitimations?: IAttestedClaim[]
    // quote?: IQuoteAttesterSigned
    //prerequisites?: {
    //    ctype: string
    //    trustedAttesters: string[]
    //    required: boolean
    //}[]
}
```

> The interface basically is the SubmitTerms message type, but I wasn't sure whether quotes and prerequisite claims are relevant for this use case. Prerequisite claims may better be handled via nested [Verification Workflows](#Verification-Workflow) after the extension submitted the RequestForAttestation. // @rflechtner 

> `prerequisites` is just an information for the user, that there will be a verification flow happening after the `request for attestation`, where the attester asks for credentials of specific ctypes to authenticate the user. // @tjwelde 

> For now we leave `prerequisites` out and see how applications use the verification flow and watch out for usefulness. // @tjwelde 

example_content:

```json
{
    "cType": "kilt:ctype:0x5366521b1cf4497cfe5f17663a7387a87bb8f2c4295d7c40f3140e7ee6afc41b",
    "claim": {
        "cTypeHash": "0xd8ad043d91d8fdbc382ee0ce33dc96af4ee62ab2d20f7980c49d3e577d80e5f5",
        "contents": {
            "grade": 12,
            "passed": true
        }
    },
    "delegationId": "4tEpuncfo6HYdkH8LKg4KJWYSB3mincgdX19VHivk9cxSz3F"
}
```

2. **Extension requests credential**

Only send with active consent of the user.

|||
|-|-|
| direction | `Extension -> dApp` |
| message_type | `REQUEST_CREDENTIAL`|
| encryption | authenticated |

content: `IRequestForAttestation`

```typescript
interface IRequestForAttestation {
    claim: IClaim
    claimNonceMap: Record<Hash, string>
    claimHashes: Hash[]
    claimerSignature: string
    delegationId: IDelegationBaseNode['id'] | null
    legitimations: IAttestedClaim[]
    rootHash: Hash
}
```

3. **Optional: Attester requests prerequisite credentials**

One or more instances of the [Verification Workflow](#Verification-Workflow) may happen before attestation of the credential, if the Attester needs to see prerequisite credentials.

4. **Attester submits credential**

|||
|-|-|
| direction | `dApp -> Extension` |
| message_type | `ATTESTED_CREDENTIAL`|
| encryption | authenticated |

content: `IAttestedClaim`

```typescript
interface IAttestedClaim {
    request: IRequestForAttestation
    attestation: {
        claimHash: string
        cTypeHash: ICType['hash']
        owner: IPublicIdentity['address']
        delegationId: IDelegationBaseNode['id'] | null
        revoked: boolean
    }
}
```

5. **Attester rejects attestation**

Send [Error type](#Error) message 

### Verification Workflow

Repeat for multiple required credentials.

1. **DApp requests credential**

*Entrypoint*

|   |   |
| -------- | -------- |
| direction | `dApp -> Extension`|
| message_type | `REQUEST_CREDENTIAL` |
| encryption | authenticated |

content:

```typescript
interface IRequestCredential {
    cTypes: {
        [key: string]: {
            trustedAttesters: string[]
            requiredAttributes: string[]
        }
    }
}   
```

example_content:

```json
{
    "cTypes": {
        "kilt:ctype:0x5366521b1cf4497cfe5f17663a7387a87bb8f2c4295d7c40f3140e7ee6afc41b": {
            "trustedAttesters": [
                "did:kilt:5CqJa4Ct7oMeMESzehTiN9fwYdGLd7tqeirRMpGDh2XxYYyx"
            ],
            "requiredAttributes": [
                "name"
            ]
        }
    }
}
```

2. **Extension sends credential**

Only send with active consent of the user.
This closes the thread.

|||
|-|-|
| direction | `Extension -> dApp` |
| message_type | `SUBMIT_CREDENTIAL`|
| encryption | authenticated |

content: 

```typescript
interface ISubmitCredential {
    credential: IAttestedClaim
}
```


## Security considerations

The strong encryption used in the communication prevents the class of attacks on the communication protocol itself, 
however several other attack surfaces remain. Discarding all of them by putting the full responsibility on the user
will risk slowing down the growth of the ecosystem: users will have to invest unreasonable efforts to use it safely.


### Malware

Not much can be done if some malware has full control over user’s computer. 

*Conclusion:* protection against keyloggers with disc and/or network traffic access is out of scope of this specification.


### Evil extensions

Extensions are limited by the API the browsers provide to them, but the control over network requests 
combined with the capability to inject code in the runtime makes the resistance futile. 

*Conclusion:* protection against the evil extensions is also out of scope of this specification.


### Phishing and social engineering

DApps can be malicious. A typo in the URI or a search request might lead the user to the dApp that should not be trusted.

In the real world the trust relies on the societal mechanisms and is usually distributed from centralized sources.
An example of that on the internet are the Extended Validation SSL certificates signed by Certification Authorities 
from a hard-coded list. This approach does not translate directly into the decentralized blockchain ecosystem. 

Every verifier can list their trusted attesters, thus delegating them the trust. One downside here is that the list will
likely be quite long, and making the user to choose from it would result in the poor user experience. More serious issue
is that the verifier itself might be a part of the malicious network and thus cannot be trusted.

*Conclusion:* a decentralized solution to determine the high trustworthiness of an identity is required. 
Some mechanisms specific to the KILT network might work for indicating trustworthiness.
Since the KILT Coin balance of an identity is publicly available, 
confirming that the dApp owns a large amount of coins also provides some signal of serious intentions.


### Man-in-the-middle

A significant fraction of websites embeds third-party scripts, advertisement being the most common source. 
Malicious actors have already used this path to inject malicious code in the runtime of the page. 
This runtime is the only medium for communication between the dApp and the extension, 
so the evil code has a way to position itself as a man-in-the-middle.
Messages that are encrypted and signed are invulnerable to such attacks, 
as the MitM can neither modify, nor read them, nor inject its own messages into the stream.

*Countermeasures:* 

The extension needs to confirm the public key of the dApp out of band.
The tamper-proof mechanism for that is defined in the
[Well Known DID Configuration specification](https://identity.foundation/.well-known/resources/did-configuration/).

Replay attacks will be prevented by the participants responding to the challenges provided by the other party and/or 
by quoting in the message plaintext of some unique ID of the previous message.


### Privacy

The identifiers, including DIDs, should not be exposed to dApps without user consent.

*Countermeasures:* even during the consequent visits to a dApp approved by the user, 
the exposure of the DIDs should happen at the latest possible moment.
This communication happens via the encrypted messages, so the DIDs are safe from MitM attacks.


### Keeping the private key encrypted

The extensions store the private keys on disk in an encrypted form. 
It is likely that even when the extension runs in the browser, 
the lifetime of unencrypted private keys in the RAM is short.

*Countermeasures:* given that the extension needs the private key to decode a message from dApp,
we recommend using a one-per-page-load temporary key pair to encrypt the messages,
not the keypairs of real identities. 

The private keys are still needed to sign certain types of messages, 
they should be removed from the RAM after that.
