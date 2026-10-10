# PB-Enrich-Block-RDP (Logic App, Consumption)

Sanitized export of the playbook's code view. The AbuseIPDB key and subscription ID have been removed.

## Flow
1. **Trigger:** Microsoft Sentinel incident (managed identity connection)
2. **Entities - Get IPs** from the incident
3. **For each IP** (concurrency 1):
   - HTTP GET `https://api.abuseipdb.com/api/v2/check` (`Key` header = SecureString parameter `AbuseIPDBKey`, `maxAgeInDays=90`)
   - Parse JSON → **Add comment** to the incident (score, reports, ISP, usage type, country, Tor, last reported)
   - **Condition** `abuseConfidenceScore >= 50`
     - **True:** severity High, tag `AbuseIPDB-High`, GET NSG rule `SOAR-Block` → `union()` existing + new IP → PUT rule back (ARM REST, managed identity) → comment "Auto-response: blocked…"
     - **False:** tag `AbuseIPDB-Low`

## Redeploying
- Replace `<SUBSCRIPTION-ID>` and set `AbuseIPDBKey` as a SecureString parameter (never commit it).
- Recreate the `azuresentinel` API connection (managed identity).
- Give the Logic App's system-assigned identity **Microsoft Sentinel Responder** and **Network Contributor** on the resource group.
- Create the NSG rule `SOAR-Block` first: Deny, priority 100 (above the RDP allow), placeholder sources `192.0.2.1,192.0.2.2`.
- In Sentinel, grant playbook permissions on the resource group and add an automation rule: *When incident is created* + *Analytic rule name contains "(SOAR)"* → *Run playbook*.
