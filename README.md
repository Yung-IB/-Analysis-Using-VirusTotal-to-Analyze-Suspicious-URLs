# Threat Intelligence Analysis of Suspicious Domains using VirusTotal

This report details a threat intelligence analysis of three suspicious domains—`17ebook.com`, `aladel.net`, and `clicnews.com`—using the VirusTotal platform. The objective was to assess the potential security risks posed by these domains, including associations with malware, phishing, or other malicious activities.

This analysis serves as a practical demonstration of using a threat intelligence aggregator to perform due diligence and risk assessment on unknown URLs.

***

### 🛠️ Methodology

The analysis was conducted using several core features within the VirusTotal platform to build a comprehensive threat profile for each domain.

* **URL Scanning:** Each domain was submitted to the VirusTotal URL scanner to aggregate detection results from over 90 security vendors and reputation services.
* **Threat Intelligence Exploration:** The "Relations" and "Graph" features were used to visualize the domains' associations with other domains, IPs, and known malware hashes.
* **Behavioral Analysis:** The domains were analyzed for suspicious behaviors such as malicious redirects, file downloads, or communication with known command-and-control servers.

***

### 📊 Findings Summary

The analysis revealed varying levels of risk associated with each domain.

| Domain | Detections | Assessed Risk | Key Finding |
| :--- | :---: | :---: | :--- |
| **`17ebook.com`** | 11/97  | High | Associated with malware distribution and suspicious IP addresses. |
| **`aladel.net`** | 9/97  | Medium | Utilized suspicious redirects, a common tactic in phishing campaigns. |
| **`clicnews.com`** | 0/97  | Low / Suspicious | Showed unusual domain associations in its graph view, warranting caution. |

***

### 📜 Risk Assessment and Recommendations

**Potential Impact:**
* Interaction with `17ebook.com` could lead to malware infections.
* Redirects from `aladel.net` could be leveraged in phishing attacks, potentially leading to credential theft.

**Recommendations:**

* **Immediate Actions:**
    * **Block Malicious Domains:** Immediately block access to `17ebook.com` and `aladel.net` at the network perimeter (firewall, web filter).
    * **Alert Users:** Notify users of the potential risks associated with these domains.
    * **Quarantine Systems:** Any systems known to have interacted with these domains should be quarantined and scanned for indicators of compromise.

* **Long-Term Mitigation:**
    * **Enhance Web Filtering:** Implement robust URL reputation services to proactively block known malicious domains.
    * **Improve Endpoint Protection:** Use advanced endpoint security with behavioral analysis to prevent infections originating from malicious sites.
    * **Conduct Security Awareness Training:** Educate users on identifying and avoiding suspicious URLs and phishing attempts.
