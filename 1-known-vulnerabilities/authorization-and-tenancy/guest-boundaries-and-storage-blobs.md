# Guest Boundaries, Revocation Latency & Private Storage Blobs

## 1. Attack Transcript

`Guest G` is invited only to `Project Public` in `Org 1`. A secret attachment exists on an issue in `Project Secret`.

```bash
# 1. Workspace-wide directories: the guest is "in the org" so the org-level check passes
$ curl -s -H "Authorization: Bearer $G" https://app.example.com/api/orgs/org-1/members
[{"id":"u1","email":"cfo@example.com","role":"owner"}, {"id":"u2","email":"counsel@example.com","role":"member"}, …]

# 2. Attachment by UUID: no parent-resource authorization
$ curl -s -D- -H "Authorization: Bearer $G" https://app.example.com/api/files/8d5f0c1a-0000-4000-8000-00000000d004
HTTP/1.1 200 OK
content-type: image/svg+xml
<svg …>flag{CANARY_BLOB_991}</svg>

# 3. Stale access after removal: owner removes G from Project Public at t0
$ curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $G" https://app.example.com/api/attachments/<public-attachment>   # t0 + 2s
200
$ curl -s -o /dev/null -w "%{http_code}\n" "<presigned URL issued yesterday, X-Amz-Expires=604800>"                                 # t0 + 3 days
200
```

## 2. Spot the Bug

```typescript
export async function listWorkspaceMembers(actor: { orgId: string }) {
  return db.query("SELECT id, email, role FROM users WHERE org_id = $1", [actor.orgId]);
}

export async function downloadAttachment(attachmentId: string, bucket: R2Bucket) {
  const meta = await db.queryOne("SELECT r2_key, mime_type FROM attachments WHERE id = $1", [attachmentId]);
  if (!meta) return new Response("Not Found", { status: 404 });

  const obj = await bucket.get(meta.r2_key);
  if (!obj) return new Response("Not Found", { status: 404 });

  return new Response(obj.body, {
    headers: { "content-type": meta.mime_type },
  });
}

export async function presignAttachment(attachmentId: string, s3: S3Client) {
  const meta = await db.queryOne("SELECT s3_key FROM attachments WHERE id = $1", [attachmentId]);
  return getSignedUrl(s3, new GetObjectCommand({ Bucket: "uploads", Key: meta.s3_key }), { expiresIn: 604800 });
}
```

<details>
<summary>Reveal the bugs</summary>

1. `listWorkspaceMembers` serves any actor in the org, including project guests.
2. `downloadAttachment` looks up the blob by UUID alone (no tenant, no parent issue/project check) and echoes a user-controlled `Content-Type` inline (stored XSS via `image/svg+xml` or `text/html`).
3. `presignAttachment` also skips authorization and issues a seven-day URL that outlives the guest's access.
4. All three use the global `db` handle, so nothing in the types prevents the omission.

</details>

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I2 — Strict Tenancy & Capability Isolation` (OWASP ASVS `v5.0.0-5.3.1`, `5.3.2`, `7.4.2`, `8.2.2`).
- **Mechanism:** Two boundary failures routinely affect multi-user workspaces:
  1. **Guest Boundary Creep & Stale Access:** Applications introduce a restricted role (such as a `ProjectGuest`, `SingleChannelGuest`, or `ExternalCollaborator`) who belongs to `Org A` for foreign-key convenience (`org_members.role = 'guest'`), but should only see the specific project(s) they are granted. Any endpoint that checks `actor.orgId === org.id` without checking `actor.role !== 'guest'` (or verifying project membership) leaks the entire organization's member directory, teams, labels, webhooks, and billing metadata to the guest. Furthermore, when the guest is removed from the project, cached tokens or child-object URLs often continue working.
  2. **Unscoped Object Storage Blobs (S3 / R2 / GCS / Local Disk):** Applications check authorization when creating an issue or comment, but serve attachments via `GET /api/attachments/:blobKey` (or via public/long-lived presigned bucket URLs) by looking up `blobKey` alone without verifying that the caller **currently** has read access to the parent resource (`issue_id` / `project_id`) that owns the attachment.
- **Why it survives review:** a guest is represented as a boolean or a role string on the same object as a full member, so "is in the org" and "may see the workspace" look identical to the type checker.

### Where It Hides

- Workspace-level metadata endpoints (`GET /api/orgs/:orgId/members`, `GET /api/teams`, `GET /api/webhooks`, `GET /api/labels`) that check only `isMemberOfOrg(user, orgId)` and forget that a `ProjectGuest` is technically in the org table.
- Attachment download endpoints (`GET /api/files/:fileId`) that check `file.org_id === actor.orgId` (or nothing at all, relying on UUID unguessability) instead of verifying access to `file.issue_id` $\to$ `issue.project_id`.
- Presigned S3/R2 URLs generated with 7-day expirations (`X-Amz-Expires=604800`), which remain downloadable days after a guest or employee is terminated.
- Local or cloud storage keys constructed using user-supplied filenames (`uploads/${orgId}/${req.file.name}`), enabling path traversal (`../../other-org/secret.pdf`) or stored XSS when the browser renders an uploaded `.html` or `.svg` inline.

## 4. Hardened Pattern

### 4.1 Two scope types, not one type with a flag

Workspace-wide endpoints must be **uncallable** with a guest scope. Both classes are minted only by the auth layer (see [`../../strategy/scoped-db.md`](../../strategy/scoped-db.md) for the minting module and for why TypeScript needs a lint rule behind the types).

```typescript
export class FullMemberScope {
  readonly kind = "member" as const;
  readonly #brand = true;
  /* constructed only by scopeFromVerifiedSession */
  readonly tenantId!: string;
  readonly actorId!: string;
  readonly role!: "owner" | "member";
}

export class ProjectGuestScope {
  readonly kind = "guest" as const;
  readonly #brand = true;
  readonly tenantId!: string;
  readonly actorId!: string;
  readonly allowedProjectIds!: ReadonlySet<string>;
}

export type TenantScope = FullMemberScope | ProjectGuestScope;

// Compile error if a ProjectGuestScope is passed:
export async function listWorkspaceMembers(scope: FullMemberScope, db: ScopedDb) {
  return db.select("members").select(["members.id", "members.display_name"]).execute();
}
```

A guest-visible people picker is a *different function* (`listProjectParticipants(scope: TenantScope, projectId)`) that returns only participants of projects in `allowedProjectIds`.

### 4.2 Attachment access = parent-resource authorization, through the scoped handle

```typescript
export async function downloadAttachment(db: ScopedDb, attachmentId: string, bucket: R2Bucket): Promise<Response> {
  // Visibility is evaluated through the scope: tenant + deleted_at + (guest) project predicate on the
  // attachment's OWN project_id (the project it was uploaded in) AND the parent issue's current project.
  const meta = await db.named<{ r2_key: string; safe_filename: string }>("visibleAttachment", { attachment_id: attachmentId });

  const row = meta[0];
  if (!row) return notFound();                                     // missing, other tenant, hidden project, moved: one response

  const obj = await bucket.get(row.r2_key);
  if (!obj) return notFound();

  return new Response(obj.body, {
    status: 200,
    headers: {
      "content-type": "application/octet-stream",
      "content-disposition": `attachment; filename="${row.safe_filename.replace(/[^a-zA-Z0-9._-]/g, "_")}"`,
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; sandbox",
      "cache-control": "private, no-store",
    },
  });
}
```

```sql
-- RAW_QUERIES.visibleAttachment (CI-parsed; :tenant and :allowed_projects are bound by ScopedDb)
SELECT a.r2_key, a.safe_filename
  FROM attachments a
  JOIN issues i
    ON i.id = a.issue_id
   AND i.tenant_id = a.tenant_id
   AND i.deleted_at IS NULL
 WHERE a.id = :attachment_id
   AND a.tenant_id = :tenant
   AND a.deleted_at IS NULL
   AND (:allowed_projects::uuid[] IS NULL
        OR (a.project_id = ANY(:allowed_projects::uuid[]) AND i.project_id = ANY(:allowed_projects::uuid[])))
```

An attachment uploaded while the issue lived in `Project Secret` (so `a.project_id` is Secret) stays hidden from a guest of `Project Public` after the issue moves, because the guest must hold **both** the attachment's recorded project and the issue's current project.

### 4.3 Presigned URLs only after the check, with a short TTL

```typescript
export async function presignDownload(db: ScopedDb, attachmentId: string, s3: S3Client): Promise<string | null> {
  const [row] = await db.named<{ s3_key: string; safe_filename: string }>("visibleAttachment", { attachment_id: attachmentId });
  if (!row) return null;                                           // caller returns 404
  return getSignedUrl(
    s3,
    new GetObjectCommand({
      Bucket: "uploads",
      Key: row.s3_key,
      ResponseContentDisposition: `attachment; filename="${row.safe_filename}"`,
      ResponseContentType: "application/octet-stream",
    }),
    { expiresIn: 60 }                                              // <= 60 seconds; revocation latency == TTL
  );
}
```

Preferred where possible: stream through the authenticated gateway so revocation is immediate and the URL never leaves your origin.

## 5. Residual Edge Cases

- **Revocation SLO, not zero.** A presigned URL issued at `t` is valid until `t + TTL`. With `TTL = 60s` the documented guest-revocation latency for blob bytes is 60 s; state it in the authorization matrix (`v5.0.0-8.1.1`) and test within it. Read replicas and KV caches add their own lag; see [`cache-and-derived-data.md`](cache-and-derived-data.md).
- **Moves and re-parenting.** Moving an issue between projects must re-evaluate attachments, comments and history; attribute child rows to the project they were written in ([`side-door-data-leaks.md`](side-door-data-leaks.md)).
- **Thumbnails, previews and derived files** (resized images, PDF text extraction, OCR, embeddings) are separate objects with separate keys; they must inherit the parent's authorization and be deleted with it.
- **Public share links.** If a feature intentionally exposes a blob via token, record it in the intended-exposure list so oracles do not flag it, give the token a TTL, scope it to a single object and make it revocable.
- **Content types.** Allow inline rendering only for a short allowlist of raster image types verified by magic bytes; everything else is `attachment` + `nosniff` + `sandbox`.
- **Export/ZIP of a project** is an attachment read surface; run the same visibility join per file.
- **Storage listing APIs.** Never expose bucket list/prefix operations to the browser, and never share one bucket credential across tenants without per-tenant key prefixes.

## 6. How to Discover It Automatically

### A. Static Code Search
```bash
# 1. Find all R2 / S3 / filesystem `.get(` or `getSignedUrl` calls and inspect their auth join:
rg -n -C 10 '\.get\(.*key|getSignedUrl|createPresignedPost' src/

# 2. Find all routes that check `org_id` without checking guest project restrictions:
rg -n 'org_id' src/ | rg -v 'guest|canAccessProject|visible_'

# 3. Long-lived presigned URLs:
rg -n 'expiresIn\s*:\s*([6-9][0-9]|[0-9]{3,})|X-Amz-Expires=([6-9][0-9]|[0-9]{3,})' src/
```

```yaml
# rules/storage-get-without-scope.yml (Semgrep)
rules:
  - id: bucket-get-without-visible-attachment
    languages: [typescript]
    severity: ERROR
    message: Blob reads must follow a ScopedDb visibility lookup of the owning resource.
    patterns:
      - pattern: $BUCKET.get($KEY)
      - pattern-not-inside: |
          const $ROW = await $DB.named("visibleAttachment", ...);
          ...
```

### B. Dynamic Attacker Test (Guest Lifecycle & Blob Canary Matrix)
1. **Plant Blob Canary:** Have `Owner A` upload a file containing `flag{CANARY_BLOB_991}` attached to an issue in `Project Secret` (inside `Org 1`). Record `attachmentId` and storage key.
2. **Test 1 — Same-Org Guest Isolation:** Authenticate as `Guest G` (who is invited **only** to `Project Public` inside `Org 1`).
   - Request `GET /api/attachments/{attachmentId}` $\to$ Assert `404 Not Found` and zero canary bytes.
   - Request workspace-wide routes (`GET /api/members`, `GET /api/teams`, `GET /api/webhooks`) $\to$ Assert `Guest G` sees only scoped/permitted data and never private workspace secrets.
3. **Test 2 — Issue Move Revocation:**
   - Have `Owner A` upload `flag{CANARY_BLOB_MOVE}` to an issue inside `Project Public` (where `Guest G` can read it).
   - Verify `Guest G` can download `GET /api/attachments/{id2}` (`200 OK`).
   - Have `Owner A` move that issue from `Project Public` to `Project Secret`.
   - Immediately replay `GET /api/attachments/{id2}` as `Guest G` $\to$ Assert `404 Not Found`.
   - Reverse case: upload to `Project Secret`, move to `Project Public`; the pre-move attachment must stay `404` for `G`.
4. **Test 3 — Guest Removal Immediate Revocation (within the documented SLO):**
   - Remove `Guest G` from `Project Public`.
   - Replay `GET /api/projects/{projectPublicId}` and `GET /api/attachments/{anyPublicAttachment}` using `Guest G`'s still-unexpired session cookie and API key $\to$ Assert `404` / `401` within the SLO.
   - Replay any presigned URL issued before removal after `TTL + skew` $\to$ Assert denied.
5. **Test 4 — Content safety:** Upload `<svg onload=…>` and an `.html` file as attachments; assert download headers include `attachment`, `nosniff` and `sandbox`.
6. Run the query-log oracle on the sweep ([`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)); the attachment lookup must carry the actor-bound tenant and guest-project predicates. Cross-surface parity is covered by [`../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md`](../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md).

## 7. How to Eliminate the Bug Class by Construction

1. **Split `WorkspaceMemberScope` from `ProjectGuestScope` in Types:** Do not represent a project guest with a boolean flag on a full member struct. Represent workspace-wide endpoints as requiring `FullMemberScope`, so passing a `TenantScope` that might be a guest fails to compile unless narrowed or explicitly scoped to `allowedProjectIds` (code in Section 4.1; mint site and lint in [`../../strategy/scoped-db.md`](../../strategy/scoped-db.md)).
2. **Key Object Storage by Internal UUIDs Only (`tenants/{tenant_uuid}/blobs/{blob_uuid}`):** Never include user-supplied filenames in S3/R2/disk paths (`ASVS v5.0.0-5.3.2`), never make buckets publicly readable, and stream downloads through an authenticated gateway (or issue presigned URLs with TTL $\le 60$ seconds only after checking parent-resource access).
3. **Make the blob read impossible without a visibility row:** wrap the bucket client so `get(key)` accepts only a `VisibleBlob` value produced by `ScopedDb` (a branded type), and ban direct bucket access in request code with the import-boundary lint.
