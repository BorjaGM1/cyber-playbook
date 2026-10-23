# Guest Boundaries, Revocation Latency & Private Storage Blobs

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I2 — Strict Tenancy & Capability Isolation` (OWASP ASVS `v5.0.0-5.3.1`, `5.3.2`, `7.4.2`, `8.2.2`).
- **Mechanism:** Two boundary failures routinely affect multi-user workspaces:
  1. **Guest Boundary Creep & Stale Access:** Applications introduce a restricted role (such as a `ProjectGuest`, `SingleChannelGuest`, or `ExternalCollaborator`) who belongs to `Org A` for foreign-key convenience (`org_members.role = 'guest'`), but should only see the specific project(s) they are granted. Any endpoint that checks `actor.orgId === org.id` without checking `actor.role !== 'guest'` (or verifying project membership) leaks the entire organization's member directory, teams, labels, webhooks, and billing metadata to the guest. Furthermore, when the guest is removed from the project, cached tokens or child-object URLs often continue working.
  2. **Unscoped Object Storage Blobs (S3 / R2 / GCS / Local Disk):** Applications check authorization when creating an issue or comment, but serve attachments via `GET /api/attachments/:blobKey` (or via public/long-lived presigned bucket URLs) by looking up `blobKey` alone without verifying that the caller **currently** has read access to the parent resource (`issue_id` / `project_id`) that owns the attachment.

---

## 2. Where It Hides

- Workspace-level metadata endpoints (`GET /api/orgs/:orgId/members`, `GET /api/teams`, `GET /api/webhooks`, `GET /api/labels`) that check only `isMemberOfOrg(user, orgId)` and forget that a `ProjectGuest` is technically in the org table.
- Attachment download endpoints (`GET /api/files/:fileId`) that check `file.org_id === actor.orgId` (or nothing at all, relying on UUID unguessability) instead of verifying access to `file.issue_id` $\to$ `issue.project_id`.
- Presigned S3/R2 URLs generated with 7-day expirations (`X-Amz-Expires=604800`), which remain downloadable days after a guest or employee is terminated.
- Local or cloud storage keys constructed using user-supplied filenames (`uploads/${orgId}/${req.file.name}`), enabling path traversal (`../../other-org/secret.pdf`) or stored XSS when the browser renders an uploaded `.html` or `.svg` inline.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — UUID-Only Blob Download & Org-Wide Guest Leak)

```typescript
// VULNERABLE 1: Any guest in the org can list every member, email, and team in the workspace.
export async function listWorkspaceMembersVulnerable(actor: { orgId: string }) {
  return db.query("SELECT id, email, role FROM users WHERE org_id = $1", [actor.orgId]);
}

// VULNERABLE 2: Serves attachment from R2/S3 by UUID alone (or org_id alone),
// without checking if the caller (e.g., a ProjectGuest) can access the parent issue's project,
// and serves user-controlled Content-Type inline (enabling Stored XSS via SVG/HTML).
export async function downloadAttachmentVulnerable(attachmentId: string, bucket: R2Bucket) {
  const meta = await db.queryOne("SELECT r2_key, mime_type FROM attachments WHERE id = $1", [attachmentId]);
  if (!meta) return new Response("Not Found", { status: 404 });

  const obj = await bucket.get(meta.r2_key);
  if (!obj) return new Response("Not Found", { status: 404 });

  return new Response(obj.body, {
    headers: { "content-type": meta.mime_type }, // XSS if image/svg+xml or text/html!
  });
}
```

### Hardened Pattern (TypeScript — Parent-Resource Auth Join + Safe Download Headers)

```typescript
export async function downloadAttachmentHardened(
  scope: TenantScope,
  attachmentId: string,
  bucket: R2Bucket
): Promise<Response> {
  // 1. Join the attachment to its parent issue and project, and enforce the caller's
  //    exact TenantScope (including live ProjectGuest membership check).
  const meta = await db.queryOne<{
    r2_key: string;
    safe_filename: string;
    project_id: string;
  }>(
    `SELECT a.r2_key, a.safe_filename, i.project_id
       FROM attachments a
       INNER JOIN issues i
               ON i.id = a.issue_id
              AND i.tenant_id = a.tenant_id
      WHERE a.id = $1
        AND a.tenant_id = $2`,
    [attachmentId, scope.tenantId]
  );

  // Return identical 404 whether the attachment doesn't exist, belongs to another tenant,
  // or belongs to a project inside the same tenant that this Guest cannot access.
  if (!meta || !scope.canAccessProject(meta.project_id)) {
    return new Response(JSON.stringify({ error: "Not Found" }), {
      status: 404,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }

  const obj = await bucket.get(meta.r2_key);
  if (!obj) {
    return new Response(JSON.stringify({ error: "Not Found" }), {
      status: 404,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }

  // 2. Serve with strict anti-XSS / anti-sniffing headers (ASVS v5.0.0-3.2.1 & 5.3.1):
  return new Response(obj.body, {
    status: 200,
    headers: {
      "content-type": "application/octet-stream",
      "content-disposition": `attachment; filename="${meta.safe_filename.replace(/[^a-zA-Z0-9._-]/g, "_")}"`,
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; sandbox",
      "cache-control": "private, no-store",
    },
  });
}
```

---

## 4. How to Discover It Automatically

### A. Static Code Search
```bash
# 1. Find all R2 / S3 / filesystem `.get(` or `getSignedUrl` calls and inspect their auth join:
rg -n -C 10 '\.get\(.*key|getSignedUrl|createPresignedPost' src/

# 2. Find all routes that check `org_id` without checking guest project restrictions:
rg -n 'org_id' src/ | rg -v 'guest|canAccessProject|visible_'
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
4. **Test 3 — Guest Removal Immediate Revocation:**
   - Remove `Guest G` from `Project Public`.
   - Immediately replay `GET /api/projects/{projectPublicId}` and `GET /api/attachments/{anyPublicAttachment}` using `Guest G`'s still-unexpired session cookie and API key $\to$ Assert `404` / `401`.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Split `WorkspaceMemberScope` from `ProjectGuestScope` in Types:** Do not represent a project guest with a boolean flag on a full member struct. Represent workspace-wide endpoints as requiring `FullMemberScope`, so passing a `TenantScope` that might be a guest fails to compile unless narrowed or explicitly scoped to `allowedProjectIds`.
2. **Key Object Storage by Internal UUIDs Only (`tenants/{tenant_uuid}/blobs/{blob_uuid}`):** Never include user-supplied filenames in S3/R2/disk paths (`ASVS v5.0.0-5.3.2`), never make buckets publicly readable, and stream downloads through an authenticated gateway (or issue presigned URLs with TTL $\le 60$ seconds only after checking parent-resource access).
