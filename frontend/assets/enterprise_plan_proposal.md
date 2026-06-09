# Proposal: ShieldIQ Enterprise Plan

Adding an **Enterprise Plan** to ShieldIQ is a strategic move to address corporate security needs. Organizations have different requirements compared to individual users: they need centralized visibility, custom integrations, compliance guarantees, and scalable access.

---

## 1. Plan Variation & Differentiation

To understand how the Enterprise plan fits into the existing ShieldIQ ecosystem, here is how it compares to the consumer and prosumer plans:

| Feature / Limit | Free Web Scanner | Shield IQ Pro | Shield Plus | Shield Enterprise (New) |
| :--- | :--- | :--- | :--- | :--- |
| **Pricing** | Always Free | ~$3.99 / month | ~$9.99 / month | **Custom / Per-Seat** (e.g. $5/seat/mo) |
| **Target Audience** | Casual/Guest Users | Power Users & Freelancers | Individuals & Families | **Corporations & Teams** |
| **Manual Scans** | 3 per day | Unlimited | Unlimited | Unlimited |
| **Document/PDF Scans** | Basic (limited size) | Advanced | Unlimited | Unlimited (Bulk uploading allowed) |
| **How it Runs** | Web-only | Web-only | Background App (SMS/WhatsApp) | Background App + API + Team Chat Bots |
| **Admin Controls** | None | None | None | **Admin Portal (SSO, Seat Management)** |
| **Privacy & Logging** | Basic History (stored) | Full History & Export | Full History & Export | **Zero-Retention Option / GDPR Compliance** |
| **Security Metrics** | None | None | None | **Aggregated Threat Analytics Dashboard** |
| **Integrations** | None | None | None | **Slack / MS Teams / Google Workspace** |

---

## 2. Real-World Business Example: Apex Financial Services

Here is a concrete example of how an organization would use **ShieldIQ Enterprise** to protect their company. You can share this exact scenario with your team:

### The Client Profile
*   **Company Name:** Apex Financial Services (250 employees)
*   **Problem:** Employees frequently receive sophisticated phishing texts (SMS), WhatsApp messages, and LinkedIn messages claiming to be from IT Support or the HR department asking them to reset credentials or verify payroll details.

### How ShieldIQ Enterprise Resolves This (Step-by-Step)

#### 1. Easy Deploy (SSO)
The IT Admin connects ShieldIQ to their identity provider (e.g., Okta or Microsoft Azure AD). All 250 employees are automatically provisioned with ShieldIQ accounts in seconds without having to manually sign up or enter credit card info.

#### 2. The Slack Security Bot
Apex Financial uses Slack. The IT department installs the **ShieldIQ Slack Bot**. 
*   An HR employee receives a suspicious WhatsApp message on their personal phone: *"Urgent: Update your bank details before 5 PM to receive your bonus: portal-apex-hr.com"*.
*   Instead of ignoring it or accidentally clicking, the employee copies the message text and types in Slack:
    `/shield-scan Urgent: Update your bank details...`
*   The ShieldIQ Bot instantly responds inside Slack: 
    > ⚠️ **HIGH RISK (95/100) detected.** This looks like a credential harvesting attempt targeting your company domain. Do not click.

#### 3. Real-Time Security Team Escalation
Because it was scanned by an Apex employee and flagged as **HIGH RISK**, ShieldIQ's backend triggers an webhook. 
*   An alert is sent to a private channel `#security-alerts` where Apex's Security Response Team hangs out:
    > 🚨 **Targeted Phishing Detected:** An employee in the HR department scanned a credential-phishing message targeting `portal-apex-hr.com`.
*   The IT team immediately blocks `portal-apex-hr.com` on the company's DNS server, protecting the other 249 employees who might receive the same link.

#### 4. The Aggregated Admin Dashboard
At the end of the month, the CISO (Chief Information Security Officer) logs into the **ShieldIQ Admin Console** and downloads a threat report. They see:
*   Total scans by team members: **1,240 scans**
*   Phishing attacks neutralized: **18**
*   Employee engagement rate: **92%**
*   *Note: Because of ShieldIQ's zero-retention compliance, the actual content of the messages is deleted, keeping corporate data completely secure and GDPR-compliant, while still providing high-level telemetry.*

---

## 3. Recommended Next Steps
1.  **Add the Enterprise Plan to the Pricing Section** on the homepage (`index.html`) and checkout pages to test interest.
2.  **Mock up the Admin Threat Dashboard** as a premium design demo to showcase to prospective enterprise clients.
3.  **Draft the Database Migrations** for corporate account models to prepare the backend for multi-tenancy.
