# KILT Credential API (Spec version 4.0)

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.

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

```typescript
interface GlobalKilt {
    /** `extensionId` references the extension on the `GlobalKilt` object but is not used by the dApp */
    [extensionId: string]: InjectedWindowProvider

    /** Container for meta-information about the dApp */
    meta: {
        /** Versions of the various specifications this dApp adheres to */
        versions: {
            /** MUST equal the version of this specification the dApp adheres to */
            credentials: '4.0'
        }
    }
}

interface InjectedWindowProvider {
    startSession: (
        /** human-readable name of the dApp */
        dAppName: string,

        /** URI of the key agreement key of the dApp DID to be used to encrypt the session messages */
        dAppEncryptionKeyUri: string,

        /** 24 random bytes as hexadecimal */
        challenge: string
    ) => Promise<PubSubSession>

    /** human-readable name of the extension */
    name: string

    /** version of the extension */
    version: string

    /** MUST equal the version of this specification the extension adheres to */
    specVersion: '4.0'
}

interface PubSubSession {
    /** Configure the callback the extension must use to send messages to the dApp. Overrides previous values. */
    listen: (callback: EncryptedMessageCallback) => Promise<void>

    /** send the encrypted message to the extension */
    send: EncryptedMessageCallback

    /** close the session and stop receiving further messages */
    close: () => Promise<void>

    /** URI of the key agreement key of the temporary DID the extension will use to encrypt the session messages */
    encryptionKeyUri: string

    /** bytes as hexadecimal */
    encryptedChallenge: string

    /** 24 bytes nonce as hexadecimal */
    nonce: string
}

interface EncryptedMessageCallback {
    (message: EncryptedMessage): Promise<void>
}

interface EncryptedMessage {
    /** URI of the key agreement key of the receiver DID used to encrypt the message */
    receiverKeyUri: string

    /** URI of the key agreement key of the sender DID used to encrypt the message */
    senderKeyUri: string

    /** ciphertext as hexadecimal */
    ciphertext: string

    /** 24 bytes nonce as hexadecimal */
    nonce: string
}
```


### DApp consumes the API exposed by extension

The dApp MUST create the `window.kilt` object as early as possible to indicate its support of the API to the extension.
This object MUST contain non-enumerable property `meta` being an object with a property `versions`,
which is in turn an object containing property `credentials` with the value of string `'4.0'`.

```typescript
window.kilt = {}
Object.defineProperty(window.kilt, 'meta', {
    value: { versions: { credentials: '4.0' } },
    enumerable: false
})
```

The dApp can afterwards get all available extensions by iterating over the `window.kilt` object.

```typescript
function getWindowExtensions(): InjectedWindowProvider[] {
    return Object.values(window.kilt);
}
```

The dApp should list all available extensions it can work with.
The user selects an extension from this list, and the communication starts from there.

```typescript
async function startExtensionSession(
    extension: InjectedWindowProvider,
    dAppName: string,
    dAppEncryptionKeyUri: string,
    challenge: string
): Promise<PubSubSession> {
    try {
        const session = await extension.startSession(dAppName, dAppEncryptionKeyUri, challenge);

        // Resolve the `session.encryptionKeyUri` and use this key and the nonce
        // to decrypt `session.encryptedChallenge` and confirm that it’s equal to the original challenge.
        // This verification must happen on the server-side.

        return session;
    } catch (error) {
        console.error(`Error initializing ${extension.name}: ${error.message}`);
        throw error;
    }
}
```

The `challenge` MUST be used only once.
The dApp MUST store a copy of the `challenge` on the server-side to prevent tampering.
The dApp MUST decrypt the `encryptedChallenge` returned by the extension and ensure that
it matches the original challenge to prevent replay attacks.


### Extension injects its API into a webpage

The extension MUST only inject itself into pages having the `window.kilt` object.
The extension MAY inspect the value of `window.kilt.meta.versions.credentials` object
and alter its behavior depending on the specification version the dApp uses.
The absence of this value indicates that the dApp uses the Credentials specification version below 3.0.

```typescript
(window.kilt as GlobalKilt).myKiltCredentialsExtension = {
    startSession: async (
        dAppName: string,
        dAppEncryptionKeyUri: string,
        challenge: string
    ): Promise<PubSubSession> => {
        return { /*...*/ };
    },
    name: 'My KILT credentials extension',
    version: '0.0.1',
    specVersion: '4.0'
} as InjectedWindowProvider;
```

The extension MUST perform the following tasks in `startSession`:
- follow steps in Well Known DID Configuration to confirm that the DID of the `dAppEncryptionKeyUri` is controlled by the same entity
  as the page origin
- generate a temporary DID and a keypair for encryption of messages of the current session
- generate a nonce of 24 random bytes
- use the temporary keypair, the dApp public key, and the nonce to encrypt the dApp-provided `challenge`
  with `x25519-xsalsa20-poly1305`

The extension SHOULD perform the following tasks in `startSession`:
- protect against Denial-of-Service attacks where the dApp floods the extension with requests
- ensure that the user has previously authorized interaction with the provided DID
- otherwise, request user authorization for this interaction


### Processing the messages

Messages SHOULD be queued until the dApp calls `listen`.

The promise SHOULD be resolved after the dApp or extension has finished processing the message.
A response message SHOULD only be sent after the promise is resolved.


### Security concerns while setting up the session

Third-party code tampering with these calls is pointless:
- modifying the `dAppEncryptionKeyUri` will be detected by Well Known DID Configuration checks
- modifying the `challenge` will be detected by the dApp backend
- replaying responses from other valid identities will result in a `encryptedChallenge` mismatch
- pretending to be the extension will fail on the next step:
  MitM will not be able to encrypt the message sent to the extension with the authentication
  of a DID that matches the origin.


## Messaging Protocol

### Data types

Some of the data types are not provided inside this specification.
Refer to the [kilt-extension-api](https://github.com/KILTprotocol/kilt-extension-api) and the [SDK](https://github.com/KILTprotocol/sdk-js) for a definition.

* [IQuote](https://github.com/KILTprotocol/kilt-extension-api/blob/4c0c2f93958ab72b59b72057a6e9b6aedb5fccef/src/types/Quote.ts#L18)
* [IQuoteAttesterSigned](https://github.com/KILTprotocol/kilt-extension-api/blob/4c0c2f93958ab72b59b72057a6e9b6aedb5fccef/src/types/Quote.ts#L30)
* [IQuoteAgreement](https://github.com/KILTprotocol/kilt-extension-api/blob/4c0c2f93958ab72b59b72057a6e9b6aedb5fccef/src/types/Quote.ts#L38)
* [VerifiablePresentation](https://kiltprotocol.github.io/sdk-js/interfaces/core_src.Types.VerifiablePresentation.html)
* [KiltCredentialV1](https://kiltprotocol.github.io/sdk-js/interfaces/core_src.Types.KiltCredentialV1.html)

### Metadata

```typescript
interface Message {
    body: {
        /** type of the message, referred as `message_type` below */
        type: string

        /** message data */
        content: object
    }

    /** timestamp of the message construction, number of milliseconds elapsed since the UNIX epoch */
    createdAt: number

    /** DID URI of the sender */
    sender: string

    /** DID URI of the receiver */
    receiver: string

    /** message ID, a random string  */
    messageId: string

    /** ID of the message this message responds to */
    inReplyTo?: string

    /** A list of message IDs of previous messages. When this message B is a response to the message A,
     *  B.references = [...A.references, A.inReplyTo] */
    references?: string[]
}
```


### Encryption

Each message sent using the `PubSubSession` is protected using authenticated encryption based on the keypairs of communicating parties.
This prevents third parties, for example MitM attackers, from reading and/or modifying the contents of the messages,
as well from injecting their own messages in the session.

Consequently, the dApp can decode messages from the extension only on the server-side,
since its private key is only available there. The extension can decode messages from the dApp
only in its background script, so that its private key remains outside of reach of 3rd parties.

To encrypt the message the sender MUST convert it to JSON and use the `x25519-xsalsa20-poly1305` algorithm
with the private key of the sender, the public key of the recipient, and 24 random bytes as a nonce.
The encrypted message contains the ciphertext, the URIs of the keys used, and the nonce.

To decrypt the message the recipient MUST resolve the key URIs to keys, then use `x25519-xsalsa20-poly1305`
with the private key of the recipient, the public key of the sender, and the nonce to restore the JSON from the ciphertext.
After parsing this JSON the recipient MUST ensure that the `sender` field contains the DID of the other party.


### Rejections

|              |                      |
| ------------ | -------------------- |
| direction    | `extension <-> dApp` |
| message_type | `'reject'`           |

Rejection messages signal the intentional cancelling of an individual step in the flow.

Rejection messages are generic. The message field `inReplyTo` contains the `messageId` of the message being rejected.
If the other party (OP) has not sent such a message, or this message does not imply a response,
or OP has already received the response, then OP MUST ignore the rejection message.
The parties SHOULD only send a rejection message for the latest message received.

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
interface Rejection {
    /** optional machine-readable type of the rejection */
    name?: string

    /** optional human-readable description of the rejection */
    message?: string
}
```


### Errors

|              |                      |
| ------------ | -------------------- |
| direction    | `extension <-> dApp` |
| message_type | `'error'`            |

Error messages signal unintentional programming errors which happened during the processing of the incoming messages
or when constructing a response message.

If an error happened while setting up the communication session, the session SHOULD be aborted or restarted.
After the session has started, errors SHOULD NOT be thrown, only sent as messages to guarantee authenticity.
So the call of `send()` SHOULD NOT throw errors and SHOULD NOT reject the promise it has returned.
The same applies to the `callback` provided to the `listen()` call.

There is a chance that encrypted authenticated error messages cannot be generated, because the code
running in the context of the dApp webpage cannot reach the components capable of encryption.
For example, if the computer is offline, the dApp javascript will not be able to communicate
with the dApp backend which has access to the encryption keys. This is anticipated, so it’s not a bug,
but rather an operational error. Such situations SHOULD be handled on the dApp side
instead of passing this error to the extension. A breakdown in communication between different scripts
of the extension is also possible, but this rather indicates a real programming error without a good option
to handle it.

```typescript
interface Error {
    /** optional machine-readable type of the error */
    name?: string

    /** optional human-readable description of the error */
    message?: string
}
```


### Attestation Workflow

#### 1. Attester proposes credential

|              |                     |
| ------------ | ------------------- |
| direction    | `dApp -> extension` |
| message_type | `'submit-terms'`    |

Because of the anticipated multitude of various CTypes, the extension is not expected to provide a UI
to create and fill in the claims. The role of the extension is to let the user authorize and sign off
on the claims prepared by the attester.

The attester SHOULD provide a UI to create and fill in the details of the claim.

The processing of the optional field `quote` is currently unspecified.

If the attester requires payment to issue this credential, the `quote` MUST be present.
If the attester does not require payment to issue this credential, the `quote` MUST NOT be present.

DApp and extension MAY start verification workflows before this event.
The extension MAY start verification workflows after this event.

```typescript
interface SubmitTerms {
    /** CTypes for the proposed credential.
     * In most cases this will be just one, but in the case of nested ctypes, this can be multiple.
     *  @link https://kiltprotocol.github.io/sdk-js/interfaces/types_src.ICType.html */
    cTypes: ICType[]

    claim: {
        /** Hash of the CType */
        cTypeHash: string

        /** contents of the proposed credential */
        contents: object

        /** optional DID URI the credential will be issued for */
        subject?: string
    }

    /** optional attester-signed binding
     *  @link https://github.com/KILTprotocol/kilt-extension-api/blob/4c0c2f93958ab72b59b72057a6e9b6aedb5fccef/src/types/Quote.ts#L30 */
    quote?: IQuoteAttesterSigned

    /** optional ID of the DelegationNode of the attester */
    delegationId?: string

    /** optional array of credentials of the attester
     *  @link https://kiltprotocol.github.io/sdk-js/interfaces/core_src.Types.VerifiablePresentation.html */
    legitimations?: VerifiablePresentation
}
```


#### 2.a Extension requests credential

The extension MUST only send the request with active consent of the user.
This is the first step where the user’s DID is revealed to the dApp.

The previous message in the flow - `'submit-terms'` - contains the `claim` with an optional `subject` field containing a DID URI.
This `subject` value being provided means that the attester is willing to issue the credential for this specific DID.
If the `'submit-terms'` message included an unknown DID or none at all as `subject`, the extension MUST ask the user to choose the DID for which the credential will be issued.
Otherwise, the extension SHOULD NOT offer the choice, but still MUST get the user’s consent to use this DID.

The extension MUST generate the `salt` values according to the [KiltAttestationProofV1 specification](https://github.com/KILTprotocol/spec-KiltCredentialV1/blob/main/ProofTypes/KiltAttestationProofV1.md#salt) and provide them in the `request-attestation` message.

The chosen or confirmed DID URI will be submitted as the `subject` field of the `claim` in the `'request-attestation'` message.
The attester MUST only issue a credential to this DID.
The attester MUST use the provided `salt` values for the proof of the credential.
The attester MAY reject the request if this DID is different from the `subject` in the previous `'submit-terms'` message.


|              |                         |
| ------------ | ----------------------- |
| direction    | `extension -> dApp`     |
| message_type | `'request-attestation'` |

```typescript
interface RequestAttestation {
    claim: {
        /** Hash of the CType */
        cTypeHash: string

        /** contents of the proposed credential */
        contents: object

        /** The salts to use for the KiltAttestationProofV1
         * @link https://github.com/KILTprotocol/spec-KiltCredentialV1/blob/main/ProofTypes/KiltAttestationProofV1.md#salt */
        salt: string[]

        /** DID URI to issue the credential for */
        subject: string

        /** optional ID of the DelegationNode of the attester to be used in the attestation */
        delegationId?: string

        /** optional array of credentials of the attester to include in the attestation
         *  @link https://kiltprotocol.github.io/sdk-js/interfaces/core_src.Types.VerifiablePresentation.html */
        legitimations: VerifiablePresentation
    },
    /** quote agreement signed by the claimer
     *  @link https://github.com/KILTprotocol/kilt-extension-api/blob/4c0c2f93958ab72b59b72057a6e9b6aedb5fccef/src/types/Quote.ts#L38 */
    quote?: IQuoteAgreement
}
```

The dApp MAY start verification workflows after this event.

However, the attester MUST perform checks that the complete data necessary for actual attestation is in place
and properly formatted before sending the `'request-payment'` message or requesting the user to pay via other means.
If any of the checks have failed, the attester MUST NOT request the payment via any means.

#### 2.b Extension rejects credential

The user might not agree to the terms that the attester proposed.
If the user rejects the terms, the extension MUST send a [rejection message](#rejections), referencing the `submit-terms` message in the `in-reply-to` field of the message object.

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

|              |                     |
| ------------ | ------------------- |
| direction    | `dApp -> extension` |
| message_type | `'request-payment'` |

```typescript
/** This message is empty. It should be associated to the terms and quote using the `in-reply-to` field.
 */
type RequestForPayment = null
```


#### 4.a Optional: Extension confirms payment

After the user has authorized the payment and it has been transferred, the extension MUST confirm the transfer
to the attester by sending the `'confirm-payment'` message.

|              |                     |
| ------------ | ------------------- |
| direction    | `extension -> dApp` |
| message_type | `'confirm-payment'` |

```typescript
interface PaymentConfirmation {
    /** hash of the payment transaction */
    txHash: string

    /** hash of the block which includes the payment transaction */
    blockHash: string
}
```

#### 4.b Optional: Extension rejects payment

The extension MUST send a [rejection message](#rejections) if the user cancels or rejects the payment.


#### 5.a Attester submits credential

If the attester successfully verified the claim, they SHOULD send a `submit-credential` message.
This message contains the attested credential.
To build the credential, the attester will generate the salts which are used in the selective disclosure scheme.
These salts MUST be used only once and be generated using a cryptographic random generator.

|              |                       |
| ------------ | --------------------- |
| direction    | `dApp -> extension`   |
| message_type | `'submit-credential'` |

```typescript
/** The content of the message is the attested credential.
 * @link https://kiltprotocol.github.io/sdk-js/interfaces/core_src.Types.KiltCredentialV1.html */
type SubmitCredential = KiltCredentialV1
```

#### 5.b Attester rejects credential

In case the attester does not approve the attestation request, no information about this appears on the blockchain.
The extension can only get this information directly from the attester.
A rejection message could be useful to help the user to remove the corresponding credential from the extension.

Once the decision not to approve the attestation request has been made, the attester SHOULD send a [rejection message](#rejections).
If the corresponding credential is stored in the extension, on receiving this message the extension MUST mark it as rejected and SHOULD offer the user the option to remove it.


### Verification Workflow

This workflow MAY be started independently. It also MAY be nested and deeply nested in the middle of ongoing
Attestation Workflows and Verification Workflows. The meaning of starting a nested workflow is:
"to answer your request (or to continue to the next step in the current workflow)
I need an additional credential from you".

Repeat for multiple required credentials.

#### 1. DApp or extension requests credential

|              |                        |
| ------------ | ---------------------- |
| direction    | `dApp <-> extension`   |
| message_type | `'request-credential'` |

Multiple CTypes MAY be requested here only if they can be used interchangeably.
For example, if the verifier needs credentials for email address and phone number, they need to run one workflow requesting a credential
for email address (with one or more email address CTypes), and afterwards another requesting a credential for phone number
(with one or more phone number CTypes).

The sender MAY request a credential issued for a particular DID by providing it in the optional message field `subject`.
If the extension received a message with this field, it MUST ask the user to choose only from the credentials issued for
this DID.
If the `subject` field is absent, all possible credentials can be used.

The `challenge` MUST be used only once.
The dApp MUST store a copy of the `challenge` on the server-side to prevent tampering.

DApp and extension MAY start verification workflows after this event.

```typescript
interface RequestCredential {
    cTypes: [
        {
            /** The hash of the CType */
            cTypeHash: string

            /** optional list of DIDs of attesters trusted by this verifier */
            trustedAttesters?: string[]

            /** list of credential attributes which MUST be included when submitting the credential */
            requiredProperties: string[]
        }
    ]

    /** Optional DID URI the credential should be issued to */
    subject?: string

    /** 24 random bytes as hexadecimal */
    challenge: string
}

const exampleRequest: RequestCredential = {
    "cTypes": [
        {
            "cTypeHash": "0x5366521b1cf4497cfe5f17663a7387a87bb8f2c4295d7c40f3140e7ee6afc41b",
            "trustedAttesters": [
                "did:kilt:5CqJa4Ct7oMeMESzehTiN9fwYdGLd7tqeirRMpGDh2XxYYyx"
            ],
            "requiredProperties": [
                "name"
            ]
        }
    ],
    "challenge": "9f1ceac971cce4c61505974f411a9db432949531abe10dde"
}
```

#### 2. Extension or dApp sends credential

The extension MUST only send the credential with active consent of the user.
This is the first step where the user’s DID is revealed to the dApp.

The `challenge` from the previous message MUST be used to create the [verifiable presentation](https://www.w3.org/TR/vc-data-model/#presentations-0)
with the private key of the identity which owns the credential.
This prevents replay attacks by confirming the ownership of this identity.

|              |                       |
| ------------ | --------------------- |
| direction    | `extension <-> dApp`  |
| message_type | `'submit-credential'` |

```typescript
/** A verifiable presentation.
 *  @link https://kiltprotocol.github.io/sdk-js/interfaces/core_src.Types.VerifiablePresentation.html */
type SubmitCredential = VerifiablePresentation
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
