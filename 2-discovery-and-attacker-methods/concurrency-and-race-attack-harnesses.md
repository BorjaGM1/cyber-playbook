# Step 4: Concurrency, Single-Packet & Race Attack Harnesses

## 1. Mental Model (Why Sequential Tests Never Catch Double-Spends)

A race condition (Time-of-Check to Time-of-Use, or TOCTOU) only manifests when two or more requests execute their database `SELECT` (or in-memory state check) inside the **critical window** $\Delta t$ before the first request commits its `UPDATE` or `INSERT`.

In a local test environment, $\Delta t$ is often only **0.5ms to 5ms**. If an attacker script sends requests in a standard loop—or even `Promise.all(urls.map(u => fetch(u)))` where TCP connections, TLS handshakes, and DNS lookups happen lazily—requests arrive at the server staggered by 5–25ms and execute serially, completely missing the bug.

To deterministically discover race conditions, you need two techniques:
1. **Barrier-Synchronized / Single-Packet HTTP Bursts (Black-Box / Local Server):** Pre-establish $N$ warm keep-alive connections (or multiplex $N$ HTTP/2 streams), send the headers and body up to the final byte, hold all $N$ requests at an in-process synchronization barrier, and flush the final byte of all $N$ requests in the **exact same microsecond**.
2. **Deterministic Thread Permutation with `shuttle` / `loom` (White-Box Rust):** For concurrent Rust data structures, connection pools, PTY multiplexers, or in-memory state stores, replace `std::thread` / `tokio::spawn` in tests with `shuttle` to systematically explore thousands of thread interleavings deterministically.

---

## 2. Target Inventory for Race Attacks

Run the barrier race harness against every endpoint that touches any of these 7 state transitions:

| Target Operation | Setup Before Barrier Burst | Burst ($N = 25$ Simultaneous Requests) | Conservation Invariant to Assert After Burst |
|------------------|----------------------------|----------------------------------------|----------------------------------------------|
| **1. Wallet / Credit Spend** | `balance = 10`, action `cost = 10` | `25 × POST /api/credits/spend { cost: 10 }` | ` successes === 1`, `final_balance === 0` (never `< 0`) |
| **2. Single-Use Coupon / Gift Card** | Coupon `PROMO50` (`max_uses = 1`) | `25 × POST /api/coupons/redeem { code: "PROMO50" }` | `successes === 1`, `credits_added === 50` (never `> 50`) |
| **3. Plan Resource / Seat Quota** | Free plan (`max_projects = 2`), currently `1` project | `25 × POST /api/projects { name: "p_i" }` | `successes === 1`, `COUNT(projects) === 2` |
| **4. Single-Use Invite / Magic Link** | 1 valid invite token `inv_123` | `25 × POST /api/invites/accept { token: "inv_123" }` | `successes === 1`, `COUNT(org_members) === 1` |
| **5. Idempotency Key Deduplication** | `balance = 100`, `cost = 10` | `25 × POST /api/charge` with **same** `Idempotency-Key: k1` | Side-effect runs **once**, `final_balance === 90` |
| **6. Webhook Event Replay** | Signed payload `evt_001` | `25 × POST /api/webhooks/stripe` with payload `evt_001` | Side-effect runs **once**, `COUNT(processed_events) === 1` |
| **7. Revoke-vs-Use Race** | Active API key `sk_live_A` | `1 × DELETE /api/keys/A` raced with `24 × GET /api/data` | Zero `200 OK` responses with timestamp after revocation commit |

---

## 3. Reference Implementation: Barrier-Synchronized Last-Byte HTTP Burst (`race-harness.mjs`)

This standalone Node.js script pre-opens $N$ TCP connections to the local target, writes the entire HTTP request **except the final byte of the body**, waits at a barrier until every socket is flushed to the kernel buffer, and then writes the final byte across all $N$ sockets in a tight synchronous loop (`TCP_NODELAY`), achieving sub-millisecond arrival jitter:

```javascript
// race-harness.mjs — Sub-Millisecond Last-Byte Barrier Race Harness
import net from "node:net";

/**
 * Fires `concurrency` raw HTTP/1.1 POST requests using the Last-Byte Synchronization technique:
 * 1. Opens `concurrency` TCP sockets with `setNoDelay(true)`.
 * 2. Sends HTTP headers + all body bytes EXCEPT the final byte `}` across all sockets.
 * 3. Waits 50ms so the OS kernel delivers the partial requests to the target server's HTTP parser.
 * 4. Sends the final byte `}` on all sockets in a synchronous loop so all handlers wake simultaneously!
 */
export async function fireBarrierSynchronizedBurst({
  host = "127.0.0.1",
  port = 4100,
  path,
  headers = {},
  bodyPayloads, // Array of JSON strings (length = concurrency)
}) {
  const concurrency = bodyPayloads.length;
  const sockets = [];

  // Step 1: Open all TCP sockets and send everything except the last byte:
  await Promise.all(
    bodyPayloads.map(
      (bodyStr, idx) =>
        new Promise((resolve, reject) => {
          const bodyBuf = Buffer.from(bodyStr, "utf8");
          const prefixBuf = bodyBuf.subarray(0, bodyBuf.length - 1);
          const lastByteBuf = bodyBuf.subarray(bodyBuf.length - 1);

          const headerLines = [
            `POST ${path} HTTP/1.1`,
            `Host: ${host}:${port}`,
            `Content-Type: application/json`,
            `Content-Length: ${bodyBuf.length}`,
            `Connection: close`,
            ...Object.entries(headers).map(([k, v]) => `${k}: ${typeof v === "function" ? v(idx) : v}`),
            "",
            "",
          ].join("\r\n");

          const sock = net.createConnection({ host, port }, () => {
            sock.setNoDelay(true);
            sock.write(Buffer.concat([Buffer.from(headerLines, "utf8"), prefixBuf]), () => {
              sockets.push({ sock, lastByteBuf, idx });
              resolve();
            });
          });
          sock.on("error", reject);
        })
    )
  );

  // Step 2: Barrier pause — ensure all partial requests are parked in the server's socket buffers:
  await new Promise((r) => setTimeout(r, 60));

  // Step 3: Release the barrier! Write the final byte to all sockets synchronously:
  const responsePromises = sockets.map(
    ({ sock, lastByteBuf, idx }) =>
      new Promise((resolve) => {
        const chunks = [];
        sock.on("data", (c) => chunks.push(c));
        sock.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          const statusMatch = /^HTTP\/1\.[01]\s+(\d{3})/.exec(raw);
          const status = statusMatch ? Number(statusMatch[1]) : 0;
          const body = raw.split("\r\n\r\n")[1] ?? "";
          resolve({ idx, status, body });
        });
        sock.write(lastByteBuf);
      })
  );

  return Promise.all(responsePromises);
}
```

---

## 4. Reference Implementation: Deterministic Thread Permutation in Rust (`shuttle`)

For Rust services with concurrent state, lock-free structures, or connection pools, network-level HTTP bursts are supplemented by **deterministic scheduler fuzzing** using [`shuttle`](https://github.com/awslabs/shuttle), which controls thread scheduling at every atomic/lock boundary:

```rust
#[cfg(test)]
mod concurrency_tests {
    use shuttle::sync::{Arc, Mutex};
    use shuttle::{check_random, thread};

    #[test]
    fn test_atomic_credit_reservation_never_double_spends_under_any_schedule() {
        // Shuttle explores 500 random thread interleavings deterministically:
        check_random(
            || {
                let wallet_balance = Arc::new(Mutex::new(10_i64));
                let committed_spends = Arc::new(Mutex::new(0_usize));

                let mut handles = Vec::new();
                for _ in 0..5 {
                    let bal = Arc::clone(&wallet_balance);
                    let spends = Arc::clone(&committed_spends);
                    handles.push(thread::spawn(move || {
                        // Critical section must hold the lock across BOTH check and decrement
                        // (equivalent to a single SQL `UPDATE ... WHERE balance >= 10`):
                        let mut guard = bal.lock().unwrap();
                        if *guard >= 10 {
                            *guard -= 10;
                            *spends.lock().unwrap() += 1;
                            true
                        } else {
                            false
                        }
                    }));
                }

                for h in handles {
                    let _ = h.join().unwrap();
                }

                let final_balance = *wallet_balance.lock().unwrap();
                let total_spends = *committed_spends.lock().unwrap();

                // Conservation Invariant I3:
                assert_eq!(total_spends, 1, "Double-spend detected!");
                assert_eq!(final_balance, 0, "Negative or corrupted balance!");
            },
            500,
        );
    }
}
```
