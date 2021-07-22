# KILT Credential API (Draft Spec version 1.0)

## DApp side

```javascript
window.kilt = window.kilt || {}
```

The dapp can get all the available extensions via iterating over the `window.kilt` object.

```typescript
function getWindowExtensions (originName: string) {
  return Promise.all(
    Object.entries(window.kilt).map(([name, { enable, version, specVersion }]) =>
      Promise.all([
        Promise.resolve({ name, version, specVersion }),
        enable(originName).catch((error: Error): void => {
          console.error(`Error initializing ${name}: ${error.message}`);
        })
      ])
    )
  );
}
```

## Extension (Provider) side

```typescript
interface Injected {
  specVersion: '0.1.0'
  startSession: () => Promise<PubSubSession>
}
```

```typescript
interface PubSubSession {
    listen: (cb: (message: Message) => Promise<void>) => Promise<void>
    close: () => Promise<void>
    send: (message: Message) => Promise<void>
}
```

Messages should be queued, before someone calls `listen`.

If the browser, or the extension can't handle the received message, they can reject the Promise.
The Promise should be resolved, when the server has processed the message.

```typescript
interface InjectedWindowProvider {
  enable: (origin: string) => Promise<Injected>;
  version: string;
  specVersion: string
}
```

How to inject your extension

```typescript
interface GlobalKilt {
  [key: string]: InjectedWindowProvider
}

window.kilt as GlobalKilt = window.kilt || {};

window.kilt[name] = {
    enable: (origin: string) => {
        // Extension enables itself
    },
    version,
    specVersion
};
```

origin is just a name, the dapp can use.

enable function give the extension the possibility to intialize itself (maybe ask the user for permission to communicate with the page) and the URL of the page (which can be directly accessed by the extension) can be checked against an internal whitelist/blacklist.

The dapp should list all available extensions it can work with.

The user selects the extension on this list and the communication starts from there.

## Messaging Protocol

Connecting Party = Attester / Verifier (Browser/Server)
User Agent = Claimer (Browser Extension)

### General

It is recommended, that users can allow the extension to use the keys for x minutes, so that the users doesn't have to enter his/her password everytime a message (even an error message) is sent.

#### Error

ThreadId should be added, whenever available. This closes the Thread.

|||
|-|-|
| direction | `Extension -> Browser | Browser -> Extension` |
| message_type | `ERROR` |
| description | General error, which should abort and reset the current workflow/protocol |
| encryption | any |

payload:

```typescript
interface {
    code: number
    reason: string
    threadId?: ThreadId
}
```

> Error codes will be provided at a later time. For now, when receiving an error, the user agent and connecting party should reset. // @tjwelde

#### ThreadId

A thread id is agreed on by both parties by one of them sending the first half and the other one appending a second part after a `;`.
Allowed IDs are base64 encoded strings.

```typescript
type ThreadId = SinglePartyThreadId | MultyPartyThreadId

Extension: SinglePartyThreadId = "123"
Server: MultyPartyThreadId = "123;890"
```

### Handshake Workflow

1. **Introduce Connecting Party**

*Entrypoint*

|||
|-|-|
| direction | `Browser -> Extension` |
| message_type | `SEND_DID` |
|encryption | false |

payload: `string`
example_payload: `did:kilt:1235`

2. **User Agent Requests Authentication**

|||
|-|-|
|direction | `Extension -> Browser` |
|message_type | `REQUEST_AUTHENTICATION` |
|encryption| anonymous|

payload

```typescript
interface {
    ctype: string,
    trustedAttesters: string[],
    temporaryEncryptionKey: string
    threadId: string
}   
```

example_payload:

```json
{
    "ctype": "kilt:ctype:0x5366521b1cf4497cfe5f17663a7387a87bb8f2c4295d7c40f3140e7ee6afc41b",
    "trustedAttesters": [
        "did:kilt:123abcd"
    ],
    "temporaryEncryptionKey": "0x342352523423abce",
    "threadId": "jh2g524g5kuy43g235"
}
```

3. **Connecting Party Authenticates with DID**

Message includes a counter-challenge for the user agent to sign.

|||
|-|-|
| direction | `Browser -> Extension` |
| message_type | `SUBMIT_AUTHENTICATION` |
| encryption | authenticated (to temporary key) |
payload:

```typescript
interface { 
    credential: AttestedClaim
    threadId: ThreadId
}
```

example
```json
{ 
    "credential": {},
    "threadId": "jh2g524g5kuy43g235;2342342jh"
}
```

> signing the challenge is not strictly necessary bc the message is authenticated/signed // @rflechtner 

> Might be very good to indicate that from this point on, the user agent (and the claimer) is 100% sure to be talking to a legit attester/verifier, so it is finally possible to reveal his DID (next step).

### Attestation Workflow

1. **Attester Proposes Credential**

|||
|-|-|
| direction | `Browser -> Extension` |
| message_type | `SUBMIT_TERMS`|

payload:

```typescript
interface {
    ctype: string
    claim: Partial<IClaim>
    delegationId?: string
    legitimations?: IAttestedClaim[]
    // quote?: IQuoteAttesterSigned
    //prerequisites?: {
    //    ctype: string
    //    trustedAttesters: string[]
    //    required: boolean
    //}[]
    threadId: ThreadId
}
```

> The interface basically is the SubmitTerms message type, but I wasn't sure whether quotes and prerequisite claims are relevant for this use case. Prerequisite claims may better be handled via nested [Verification Workflows](#Verification-Workflow) after the user agent submitted the RequestForAttestation. // @rflechtner 

> `prerequisites` is just an information for the user, that there will be a verification flow happening after the `request for attestation`, where the attester asks for credentials of specific ctypes to authenticate the user. // @tjwelde 

> For now we leave `prerequisites` out and see how applications use the verification flow and watch out for usefulness. // @tjwelde 

example payload:

```json
{
    "ctype": "kilt:ctype:0x5366521b1cf4497cfe5f17663a7387a87bb8f2c4295d7c40f3140e7ee6afc41b",
    "claim": {
        "grade": 12,
        "passed": true
    },
    "delegationId": "0x123",
    "threadId": "jh2g524g5kuy43g235;2342342jh"
}
```

2. **Claimer Requests Credential**

Only send with active consent of the user.

|||
|-|-|
| direction | `Extension -> Browser` |
| message_type | `REQUEST_CREDENTIAL`|
| encryption | authenticated |

payload:`IRequestForAttestation`

```typescript
interface IRequestForAttestation {
  claim: IClaim
  claimNonceMap: Record<Hash, string>
  claimHashes: Hash[]
  claimerSignature: string
  delegationId: IDelegationBaseNode['id'] | null
  legitimations: IAttestedClaim[]
  rootHash: Hash
  threadId: ThreadId
}
```

3. **Optional: Attester Requests Prerequisite Credentials**

One or more instances of the [Verification Workflow](#Verification-Workflow) may happen before attestation of the credential, if the Attester needs to see prerequisite credentials.

4. **Attester Submits Credential**

|||
|-|-|
| direction | `Browser -> Extension` |
| message_type | `ATTESTED_CREDENTIAL`|
| encryption | authenticated |

payload: `IAttestedClaim`

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
    threadId: ThreadId
}
```

5. **Attester Rejects Attestation**

Send [Error type](#Error) message 

### Verification Workflow

*Prerequisite:* Authentication has finished via [Handshake Workflow](#Handshake-Workflow)

Repeat for multiple required credentials.

1. **Connecting Party Requests Credential**

*Entrypoint*

|   |   |
| -------- | -------- |
| direction | `Browser -> Extension`|
| message_type | `REQUEST_CREDENTIAL` |
| encryption | authenticated |

payload:

```typescript
interface {
    ctypes: {
        [key: string]: {
            trustedAttesters: string[]
            requiredAttributes: string[]
        }
    }
    threadId: ThreadId
}   
```

example payload:

```json
{
    "ctypes": {
        "kilt:ctype:0x5366521b1cf4497cfe5f17663a7387a87bb8f2c4295d7c40f3140e7ee6afc41b": {
            "trustedAttesters": [
                "did:kilt:123abcd"
            ],
            "requiredAttributes": [
                "name"
            ]
        }
    },
    "threadId": "jh2g524g5kuy43g235;2342342jh"
}
```

2. **User Agent Sends Credential**

Only send with active consent of the user.
This closes the thread.

|||
|-|-|
| direction | `Extension -> Browser` |
| message_type | `SUBMIT_CREDENTIAL`|
| encryption | authenticated |

payload: 
```typescript
interface {
    credential: IAttestedClaim
    threadId: ThreadId
}
```
