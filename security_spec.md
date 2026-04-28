# Security Specification - SentinelAI

## Data Invariants
- A `Report` must always be associated with a valid `userId`.
- Users can only read and write their own `UserProfile` and `Report` documents.
- The `isAiGenerated` and `riskLevel` fields are system-validated (though here determined by client-side Gemini calls, ideally handled via backend in production, we will protect them with rules).
- IDs must be valid alphanumeric strings.

## The Dirty Dozen Payloads (Target: Permission Denied)

1. **Identity Theft (Profile)**: Attempt to update another user's profile.
   ```json
   { "uid": "victim_uid", "email": "hacker@evil.com" }
   ```
2. **Identity Theft (Report)**: Attempt to read a report belonging to another user.
3. **Ghost Field Injection**: Adding `isAdmin: true` to a profile.
4. **ID Poisoning**: Using a 1MB string as a document ID.
5. **Unauthorized Listing**: Attempt to query all reports in the system without a user filter.
6. **Self-Promotion**: Setting `monitoringEnabled` on a non-existent user.
7. **Orphaned Report**: Creating a report with a `userId` that does not match the authenticated user.
8. **System Field Overwrite**: Changing a `Report` confidence score after it was created.
9. **Fake Verification**: Attempting to set `emailVerified` on a user object (which should be derived from auth).
10. **Malicious Platform Injection**: Adding a non-enum platform to `monitoredPlatforms`.
11. **Timestamp Spoofing**: Sending a future `createdAt` date.
12. **PII Leakage**: Attempting to fetch a user's full profile without being that user.

## Permissions Mapping
- `/users/{userId}`: `get`, `create`, `update` allowed if `request.auth.uid == userId`. `list` denied.
- `/reports/{reportId}`: `get`, `create`, `delete` allowed if `resource.data.userId == request.auth.uid`. `list` allowed if `resource.data.userId == request.auth.uid`.
