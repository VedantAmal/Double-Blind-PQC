# Double-Blind PQC Diagrams

Here are the fixed Mermaid.js diagrams. Render these using the [Mermaid Live Editor](https://mermaid.live/) and export them as PNGs. In Overleaf, upload the PNGs and use `\includegraphics{filename.png}` under the respective placeholders in your `paper.tex` file.

## Diagram 1: System Architecture Overview
Place this diagram right above the **"Step 1: Initiation and Identity Assertion"** section (in Overleaf, search for `% PLACEHOLDER POINT 1`).

```mermaid
graph TD
    classDef client fill:#0f172a,stroke:#3b82f6,stroke-width:2px,color:#e2e8f0;
    classDef core fill:#1e293b,stroke:#8b5cf6,stroke-width:2px,color:#e2e8f0;
    classDef transport fill:#334155,stroke:#10b981,stroke-width:2px,color:#e2e8f0;

    A["VPN Initiator Client"]:::client <--> B("Double-Blind Interface"):::core
    D["VPN Responder Client"]:::client <--> C("Double-Blind Interface"):::core
    
    subgraph "Application Space (Initiator)"
        B <--> E["PQC Cryptographic Core <br/> ML-KEM & ML-DSA"]:::core
        E <--> F["MTU Fragmentation Wrapper"]:::transport
    end

    subgraph "Internet Transport Layer"
        F == "UDP Sockets <br/> MTU <= 1500 B" ==> G["MTU Fragmentation Wrapper"]:::transport
    end

    subgraph "Application Space (Responder)"
        G <--> H["PQC Cryptographic Core <br/> ML-KEM & ML-DSA"]:::core
        H <--> C
    end
```

## Diagram 2: Handshake Sequence Diagram
Place this diagram right after **Algorithm 1: Double-Blind Handshake & Encapsulation** (in Overleaf, search for `% PLACEHOLDER POINT 2`). If no placeholder is found explicitly, place it directly underneath algorithm 1.

```mermaid
sequenceDiagram
    participant I as Initiator (Alice)
    participant R as Responder (Bob)
    
    Note over I,R: Setup: Exchange Long-Term Dilithium-3 Identity PKs
    
    I->>I: Generate Kyber-768 Ephemeral Keypair (PK_k, SK_k)
    I->>I: Sign (PK_k + Nonce_A) with Dilithium SK_sig
    I->>R: Transmit [PK_k, Nonce_A, Signature] (Fragmented)
    
    Note over R: Receives and reconstructs payload fragments
    R->>R: Verify Signature using Initiator's PK_sig
    
    alt Signature Valid
        R->>R: Kyber-768 Encapsulate(PK_k) -> Shared Secret (SS), Ciphertext (CT)
        R->>R: Sign (CT + Nonce_B) with Dilithium SK_sig
        R->>I: Transmit [CT, Nonce_B, Signature] (Fragmented)
    else Signature Invalid
        R-->>I: Drop Connection
    end
    
    Note over I: Receives and reconstructs payload fragments
    I->>I: Verify Signature using Responder's PK_sig
    I->>I: Kyber-768 Decapsulate(CT, SK_k) -> Shared Secret (SS)
    
    Note over I,R: AES-256-GCM Symmetric Tunnel Established using SS
```

## Diagram 3: MTU Fragmentation Logic Flowchart
Place this diagram right after **Algorithm 2: Deterministic MTU Payload Extractor** (in Overleaf, search for `% PLACEHOLDER POINT 3`).

```mermaid
flowchart TD
    A["Raw Encrypted Data Payload"] --> B{"Length > 1000 Bytes?"}
    
    B -- No --> C["Add Single Header <br/> MSG_ID | 0 | 1"]
    C --> D["Send via UDP Socket"]
    
    B -- Yes --> E["Calculate Total Fragments N <br/> = ceil(Length / 1000)"]
    E --> F["Generate Random 2-Byte MSG_ID"]
    F --> G["Initialize Iterator i=0"]
    
    G --> H["Slice Payload <br/> from i*1000 to (i+1)*1000"]
    H --> I["Append Header <br/> MSG_ID | i | N"]
    I --> J["Send UDP Packet"]
    
    J --> K{"i == N - 1?"}
    K -- No --> L["Increment i++"]
    L --> H
    K -- Yes --> M(["Transmission Complete"])
```
