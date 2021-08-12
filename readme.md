# KILT Credential API (Draft Spec version 1.0)

## Definitions

### Extension

A browser extension that stores and uses the identities and credentials of the user. 
When the user visits a webpage, the extension injects its API into this webpage.

### dApp

Decentralized application – a website that can interact with the extension via the API it exposes.
The example dApps in this specification are Attester and Verifier.


## Specification of requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and
"OPTIONAL" in this document are to be interpreted as described in RFC 2119.


## Setting up the communication session

### Types

`extensionId` references the extension on the `GlobalKilt` object but is not used by the dApp. `name` SHOULD be a human-readable string.

```typescript
interface GlobalKilt {
    [extensionId: string]: InjectedWindowProvider
}

interface InjectedWindowProvider {
    startSession: (
        dAppName: string, 
        dAppIdentity: IPublicIdentity, 
        challenge: UUID
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
    signedChallenge: string
}
```


### DApp consumes the API exposed by extension 

The dApp MUST create the `window.kilt` object as early as possible to indicate its support of the API to the extension.

```typescript
window.kilt = {}
```

The dApp can get all available extensions by iterating over the `window.kilt` object.

```typescript
function getWindowExtensions(): InjectedWindowProvider[] {
    return Object.values(window.kilt || {});
}
```

The dApp should list all available extensions it can work with. 
The user selects an extension from this list, and the communication starts from there.

```typescript
async function startExtensionSession(
    extension: InjectedWindowProvider,
    dAppName: string,
    dAppIdentity: IPublicIdentity, 
    challenge: UUID
): Promise<PubSubSession> {
    try {
        const session = await extension.startSession(dAppName, dAppIdentity, challenge);
        
        // This verification must happen on the server-side.
        Crypto.verify(challenge, session.signedChallenge, session.identity.address);
        
        return session;
    } catch (error) {
        console.error(`Error initializing ${extension.name}: ${error.message}`);
        throw error;
    }
}
```

The `challenge` MUST be used only once. 
The dApp MUST store a copy of the `challenge` on the server-side to prevent tampering. 
The dApp MUST verify that the signature of `signedChallenge` returned by the extension matches its identity 
to prevent replay attacks.


### Extension injects its API into a webpage

The extension MUST only inject itself into pages having the `window.kilt` object.

```typescript
(window.kilt as GlobalKilt)[extensionId] = {
    startSession: async (
        dAppName: string, 
        dAppIdentity: IPublicIdentity, 
        challenge: UUID
    ): Promise<PubSubSession> => {
        return { /*...*/ };
    },
    name,
    version,
    specVersion: '0.1.0'
} as InjectedWindowProvider;
```

The extension MUST perform the following tasks in `startSession`:
- follow steps in Well Known DID Configuration to confirm that the `dAppIdentity` is controlled by the same entity
  as the page origin
- generate a temporary keypair for encryption of messages of the current session
- use this keypair to sign the dApp-provided `challenge`

The extension SHOULD perform the following tasks in `startSession`:
- ensure that the user has previously authorized interaction with the provided DID
- otherwise, request user authorization for this interaction


### Processing the messages

Messages SHOULD be queued until the dApp calls `listen`.

The Promise SHOULD be resolved after the dApp or extension has finished processing the message.
If they can't handle the received message, they can reject the Promise.


### Security concerns while setting up the session

Third-party code tampering with these calls is pointless:
- modifying the `dAppIdentity` will be detected by Well Known DID Configuration checks
- modifying the `challenge` will be detected by the dApp backend
- replaying responses from other valid identities will result in a `signedChallenge` mismatch
- pretending to be the extension will fail on the next step:
  MitM will not be able to encrypt the message sent to the extension with the authentication 
  of a DID that matches the origin. 


## Messaging Protocol

### Data types

Definitions of data types, if not provided here, can be found in 
[the KILTProtocol SDK documentation](https://kiltprotocol.github.io/sdk-js/globals.html).


### Encryption - TODO

This section is a placeholder for the documentation on how the messages are encrypted.

Each message sent using the `PubSubSession` is protected using authenticated encryption based on the keypairs of communicating parties.
This prevents third parties, for example MitM attackers, from reading and/or modifying the contents of the messages,
as well from injecting their own messages in the session.

Consequently, the dApp can decode messages from the extension only on the server-side,
since its private key is only available there. The extension can decode messages from the dApp
only in its background script, so that its private key remains outside of reach of 3rd parties.


### Rejections

|||
|-|-|
| direction | `extension <-> dApp` |
| message_type | `'reject'` |

Rejection messages signal the intentional cancelling of an individual step in the flow.

Rejection messages are generic. What is being rejected is defined by the order of messages: 
the rejection message rejects the last message the other party (OP) has sent.
If OP has not yet sent a message, or OP’s last message does not imply a response, 
or OP has already received the response, then OP MUST ignore the rejection message.
With this approach we intend to reduce the complexity (otherwise we would need to have multiple types of messages, 
to define how they should reference whatever they are rejecting, and how to process messages arriving out of order).

The interaction is mostly driven from the dApp UI, which also has more screen estate compared to extensions. 
In the multi-step flow, the user might want to cancel either an individual step or the whole flow. 
Providing and explaining both options in the limited space might be challenging, 
so the extension SHOULD provide means to cancel an individual step, while the dApp SHOULD provide both options. 
The user also always has the last resort of simply closing the dApp page.

The extension SHOULD report the closure of the popup (by the user or because of the switch to another app)
as a cancellation, not an error.

On receiving an error or a rejection from the dApp, the extension SHOULD offer options to retry and to cancel. 
On receiving an error or a rejection from the extension, the dApp SHOULD highlight the option to cancel the flow 
and MAY offer an option to trigger a retry. However, cancelling a step SHOULD NOT automatically cancel the flow, 
since we expect many actions to be trial and error explorations of possibilities, as in the following example.

When the attester requests credentials from the user via the nested verification workflow, 
their CTypes are compared using hashes, which the user cannot conveniently do manually in advance. 
The user’s train of thought could be: "They want some kind of credential, let’s see if mine would suit them. 
Okay, it did not, so I cannot provide what they want, but I do not want to cancel the whole flow."

In a different scenario, the extension MAY try to detect the trustworthiness of the dApp 
by requesting from it some credentials, and the dApp MAY reject these requests. 
The extension MAY use the results of this exchange to indicate to the user its level of confidence 
in the trustworthiness of the dApp, for example, as the browsers do for SSL and EV certificates.

```typescript
interface IRejection {
    /** Optional machine-readable type of the rejection */
    name?: string
    
    /** Optional human-readable description of the rejection */
    message?: string
}
```


### Errors

|||
|-|-|
| direction | `extension <-> dApp` |
| message_type | `'error'` |

Error messages signal unintentional programming errors which happened during the processing of the incoming messages
or when constructing a response message.

If an error happened while setting up the communication session, the session SHOULD be aborted or restarted.
After the session has started, errors SHOULD NOT be thrown, only sent as messages to guarantee authenticity.
So the call of `send()` SHOULD NOT throw errors. The same applies to the `callback` provided to the `listen()` call.

There is a chance that encrypted authenticated error messages cannot be generated, because the code 
running in the context of the dApp webpage cannot reach the components capable of encryption. 
For example, if the computer is offline, the dApp javascript will not be able to communicate 
with the dApp backend which has access to the encryption keys. This is anticipated, so it’s not a bug, 
but rather an operational error. Such situation SHOULD be handled on the dApp side,
instead of passing this error to the extension. The breakdown in the communication between different scripts
of the extension is also possible, but this rather indicates a real programming error without a good option
to handle it.

```typescript
interface IError {
    /** Optional machine-readable type of the error */
    name?: string

    /** Optional human-readable description of the error */
    message?: string
}
```


### Attestation Workflow

#### 1. Attester proposes credential

|||
|-|-|
| direction | `dApp -> extension` |
| message_type | `'submit-terms'` |

The processing of the optional field `quote` is currently unspecified. 

If the attester requires payment to issue this credential, the `quote` MUST be present.
If the attester does not require payment to issue this credential, the `quote` MUST NOT be present.

DApp and extension MAY start verification workflows before this event.
The extension MAY start verification workflows after this event.

```typescript
interface ISubmitTerms {
    cType: string
    claim: Partial<IClaim>
    delegationId?: IDelegationBaseNode['id']
    legitimations?: IAttestedClaim[]
    quote?: IQuoteAttesterSigned
}

const exampleTerms: ISubmitTerms = {
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


#### 2. Extension requests credential

The extension MUST only send the request with active consent of the user.

If the `quote` was provided, and the user has entered the password to decrypt the private key for signing the request,
the extension SHOULD temporarily cache either the password or the unencrypted private key, 
so that the user does not need to enter it again when the payment needs to be transferred.

|||
|-|-|
| direction | `extension -> dApp` |
| message_type | `'request-attestation'` |

```typescript
interface IRequestForAttestation {
    claim: IClaim
    claimNonceMap: Record<Hash, string>
    claimHashes: Hash[]
    claimerSignature: string
    delegationId?: IDelegationBaseNode['id']
    legitimations: IAttestedClaim[]
    rootHash: Hash
}
```

The dApp MAY start verification workflows after this event.

However, the attester MUST perform checks that the complete data necessary for actual attestation is in place
and properly formatted before sending the `'request-payment'` message or requesting the user to pay via other means.
If any of the checks have failed, the attester MUST NOT request the payment via any means.


#### 3. Optional: Attester requests payment

This specification does not prescribe the means of payment.

The attester MUST NOT send this message if it does not require payment to issue this credential.
The attester MUST NOT send this message if the payment happens via the attester website.

This attester MAY send this message if it wants the user to transfer payment in KILT Coins by themselves 
without interrupting the flow.

The extension MAY start verification workflows after this event.

Upon receiving the `'request-payment'` message the extension SHOULD show the user the interface 
to authorize the transfer of the payment to the attester.
The previously provided `quote` contains the amount to be paid (`cost.gross`) 
and the recipient address (`attesterAddress`).

|||
|-|-|
| direction | `dApp -> extension` |
| message_type | `'request-payment'` |

```typescript
interface IRequestForPayment {
    /** same as the `rootHash` value of the `'request-attestation'` message */
    claimHash: Hash
}
```


#### 4. Optional: Extension confirms payment

After the user has authorized the payment and it has been transferred, the extension MUST confirm the transfer
to the attester by sending the `'confirm-payment'` message.

|||
|-|-|
| direction | `extension -> dApp` |
| message_type | `'confirm-payment'` |

```typescript
interface IPaymentConfirmation {
    /** same as the `rootHash` value of the `'request-attestation'` message */
    claimHash: Hash
    
    /** the hash of the payment transaction */
    txHash: Hash
    
    /** the hash of the block which includes the payment transaction */
    blockHash: Hash
}
```


#### 5. Attester submits credential

|||
|-|-|
| direction | `dApp -> extension` |
| message_type | `'submit-attestation'` |

```typescript
interface IAttestation {
    claimHash: Hash
    cTypeHash: ICType['hash']
    owner: IPublicIdentity['address']
    delegationId?: IDelegationBaseNode['id']
    revoked: boolean
}
```


### Verification Workflow

This workflow MAY be started independently. It also MAY be nested and deeply nested in the middle of ongoing 
Attestation Workflows and Verification Workflows. The meaning of starting a nested workflow is: 
"to answer your request (or to continue to the next step in the current workflow) 
I need an additional credential from you".

Repeat for multiple required credentials.


#### 1. DApp or extension requests credential

|||
|-|-|
| direction | `dApp <-> extension`|
| message_type | `'request-credential'` |

Multiple CTypes MAY be requested here only if they can be used interchangeably. For example, if the verifier needs
credentials for email address and phone number, they need to run one workflow requesting a credential
for email address (with one or more email address CTypes), and afterwards another requesting a credential for phone number
(with one or more phone number CTypes).

The `challenge` MUST be used only once. 
The dApp MUST store a copy of the `challenge` on the server-side to prevent tampering. 

DApp and extension MAY start verification workflows after this event.

```typescript
interface IRequestCredential {
    cTypes: {
        [cTypeId: string]: {
            trustedAttesters?: string[]
            requiredAttributes: string[]
        }
    }
    challenge: UUID
}   

const exampleRequest: IRequestCredential = {
    "cTypes": {
        "kilt:ctype:0x5366521b1cf4497cfe5f17663a7387a87bb8f2c4295d7c40f3140e7ee6afc41b": {
            "trustedAttesters": [
                "did:kilt:5CqJa4Ct7oMeMESzehTiN9fwYdGLd7tqeirRMpGDh2XxYYyx"
            ],
            "requiredAttributes": [
                "name"
            ]
        }
    },
    "challenge": "f7546f31-bd3a-464c-bb43-9d622968c3a4"
}
```

#### 2. Extension or dApp sends credential

The extension MUST only send the credential with active consent of the user.
The `challenge` from the previous message MUST be signed using the private key 
of the identity which owns the credential. This prevents replay attacks 
by confirming the ownership of this identity.

The dApp MUST verify in the backend that the signature of `signedChallenge`
returned by the extension matches its identity to prevent replay attacks.

|||
|-|-|
| direction | `extension <-> dApp` |
| message_type | `'submit-credential'`|

```typescript
interface ISubmitCredential {
    credential: IAttestedClaim
    signedChallenge: string
}
```


## Security considerations

The strong encryption used in the communication prevents the class of attacks on the communication protocol itself, 
however several other attack surfaces remain. Ignoring all of them by placing full responsibility on the user
will risk slowing down the growth of the ecosystem: users will have to invest unreasonable efforts to use it safely.


### Malware

Not much can be done if some malware has full control of the user’s computer. 

*Conclusion:* protection against keyloggers with disc and/or network traffic access is outside the scope of this specification.


### Evil extensions

Extensions are limited by the API that browsers provide to them, but control over network requests 
combined with the capability to inject code in the runtime makes resistance futile. 

*Conclusion:* protection against evil extensions is also outside the scope of this specification.


### Phishing and social engineering

DApps can be malicious. A typo in the URI or a search request might lead the user to a dApp that should not be trusted.

In the real world, trust relies on societal mechanisms and is usually distributed from centralized sources.
An example from the internet is the Extended Validation SSL certificates signed by Certification Authorities 
from a hard-coded list. This approach does not translate directly into the decentralized blockchain ecosystem. 

Every verifier can list their trusted attesters, thus delegating them trust. One downside to this solution is that the list 
will likely be quite long, and making the user choose from it would result in a poor user experience. A more serious issue 
with this approach is that the verifier itself might be a part of a malicious network and thus cannot be trusted.

*Conclusion:* a decentralized solution to determine the high trustworthiness of an identity is required. 
Some mechanisms specific to the KILT network might work for indicating trustworthiness.
Since the KILT Coin balance of an identity is publicly available, 
confirming that the dApp owns a large amount of coins also provides some signal of serious intentions.


### Man-in-the-middle

A significant fraction of websites embed third-party scripts, advertisement being the most common source. 
Malicious actors have already used this path to inject malicious code in the runtime of the page. 
This runtime is the only medium for communication between the dApp and the extension, 
so the evil code has a way to position itself as a man-in-the-middle.
Messages that are encrypted and authenticated are invulnerable to such attacks, 
as the MitM can neither modify nor read them. Nor can it inject its own messages into the stream.

*Countermeasures:* 

The extension needs to confirm the public key of the dApp out of band.
The tamper-proof mechanism for that is defined in the
[Well Known DID Configuration specification](https://identity.foundation/.well-known/resources/did-configuration/).

Replay attacks will be prevented by participants responding to challenges provided by the other party and/or 
by including some unique ID of the previous message in the response.


### Privacy

The identifiers, including DIDs, should not be exposed to dApps without user consent.

*Countermeasures:* even during consequent visits to a dApp approved by the user, 
the exposure of the DIDs should happen at the latest possible moment.
This communication happens via encrypted messages, so the DIDs are safe from MitM attacks.


### Keeping the private key encrypted

The extensions store the private keys on disk in an encrypted form. 
It is likely that even when the extension runs in the browser, 
the lifetime of unencrypted private keys in the RAM is short.

*Countermeasures:* given that the extension needs the private key to decode a message from dApp,
we recommend using a one-per-page-load temporary key pair to encrypt the messages,
not the keypairs of real identities. 

The private keys are still needed to sign certain requests, 
but should be removed from the RAM after signing them.
