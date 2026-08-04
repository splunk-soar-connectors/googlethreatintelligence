# Integration Overview

Supercharge your Splunk SOAR with Google Threat Intelligence, unifying unparalleled threat analysis directly within your security operations. This app provides context-rich reputation and deep analysis for indicators by fusing three powerful sources: the vast, real-time crowdsourced intelligence of VirusTotal, the frontline breach expertise and actor tracking of Mandiant, and the global threat visibility from Google's own network. Go beyond simple lookups by ingesting curated threat signals from Mandiant-driven Attack Surface Management and Digital Threat Monitoring, along with Google's real-time IOC streams, to automate response with unmatched context and confidence.

# Explanation of Data Ingestion

This integration supports four types of data ingestion: **IOC Stream**, **DTM Alerts**, **ASM Issues**, and **RS Alerts**. If an ingestion type is not selected while configuring asset, data ingestion will not occur. Only one data ingestion type can be configured per asset. To configure multiple data ingestions, set up multiple assets.

The below details describes the configuration and usage of the GTI integration for Splunk SOAR, focusing on the four on-poll ingestion types: **IOC Stream**, **DTM Alerts**, **ASM Issues**, and **RS Alerts**.

______________________________________________________________________

## On-Poll Configuration

### Poll Now Feature

The **Poll Now** action retrieves the most recent 1 hour of data for all four ingestion types: **IOC Stream**, **DTM Alerts**, **ASM Issues**, and **RS Alerts**.

**Important Notes:**

- The *Poll Now* feature **ignores** the following parameters: **Source ID**, **Maximum containers**, and **Maximum artifacts**.
- It does **not** store a checkpoint file, meaning it will always pull the most recent 1 hour of data regardless of previous ingestions.
- When using *Poll Now* for **IOC Stream**, duplicate artifacts may be ingested into the current day's container if those artifacts already exist, since SOAR does **not** automatically remove duplicates.

### Scheduled / Interval Polling

**Recommended Ingestion Interval:**\
Set the ingestion interval to 1 hour for optimal performance and timely data updates. Please note that using very short intervals may negatively impact data ingestion efficiency and the overall performance of your instance.

**Limit Parameter:**\
The `limit` parameter controls the maximum number of records ingested per poll. The maximum allowed value is **1000**; if a higher or invalid value is set, it will be ignored and **1000** will be used. This parameter applies to all four ingestion types.

**Lookback Days Parameter:**\
The `lookback_days` parameter determines how many days back the integration will look for data during the initial poll. The maximum allowed value is **5**; if a higher or invalid value is set, it will be ignored and **5** will be used. Days are calculated as the absolute day difference from the current time.

______________________________________________________________________

## IOC Stream

- **Parameters:**

  - **Descriptors Only:** Includes only object descriptors, not full VT objects (boolean, default: false).
  - **Filter:** Filter string to filter IOCs (string). This is a recommended option for the IOC Stream data ingestion type to filter relevant IOCs and reduce noise.
    **Note:** This field is shared with the **RS Alerts** ingestion type, which uses a different filter syntax; see the [Relevance System Alerts](#relevance-system-alerts) section for details.

- **Container Creation:**\
  All IOC Stream data for a given UTC day will be ingested into a single container. A new container is created each day (UTC-based).

______________________________________________________________________

## DTM Alerts

- **Parameters:**

  - **Monitor ID:** Filter alerts by the specified monitor ID(s). Supports multiple comma-separated values (string).
  - **Status:** Filter alerts by status. Possible values: `new`, `read`, `escalated`, `in_progress`, `closed`, `no_action_required`, `duplicate`, `not_relevant`, `tracked_external`. Supports multiple comma-separated values (string).
  - **Alert Type:** Filter alerts by alert type. Possible values: `Compromised Credentials`, `Domain Discovery`, `Forum Post`, `Message`, `Paste`, `Shop Listing`, `Tweet`, `Web Content`. Supports multiple comma-separated values (string).
  - **Search:** Search alerts and triggering documents using a Lucene query with text values joined by AND/OR (string).
  - **Match Value:** Filter alerts by specified match value. Supports multiple comma-separated values (string).
  - **Tags:** Filter alerts by tags. Supports multiple comma-separated values (string).
  - **Severity:** Filter alerts by specified severity. Possible values: `high`, `medium`, `low`. Supports multiple comma-separated values (string).
  - **MScore GTE:** Filter alerts with mscores greater than or equal to the given value (numeric, 0 to 100).

- **Status Mapping of DTM Alerts:**

  | DTM Alert Status | SOAR Container Status |
  |----------------------|----------------------|
  | New | New |
  | Read | Open |
  | Escalated | Open |
  | In Progress | Open |
  | Closed | Closed |
  | No Action Required | Closed |
  | Duplicate | Closed |
  | Not Relevant | Closed |
  | Tracked External | Closed |

- **Severity Mapping of DTM Alerts:**

  | DTM Alert Severity | SOAR Container Severity |
  |--------------------|------------------------|
  | High | High |
  | Medium | Medium |
  | Low | Low |

  The connector matches these values to enabled Splunk SOAR severity names. If a stock name is not enabled, High maps to the highest-ranked enabled severity, Medium maps to the enabled default (or the middle-ranked severity if no default is identified), and Low maps to the lowest-ranked enabled severity. Missing and unrecognized DTM severity values map to the highest-ranked enabled severity.

- **Container Creation:**\
  Each DTM alert will result in the creation of a separate container. One artifact will be created inside the container and will have certain important fields from alert visible inside the artifact. To get complete details about the alert, download the artifact JSON.

- **Container Updates:**\
  Containers or artifacts will **not** be updated if the alert is updated in GTI after ingestion.

- **Closing DTM Alerts in GTI:**\
  When a DTM alert container is closed in Splunk SOAR, the playbook provided in this [repository](https://github.com/virusTotal/gti-soar-playbooks/tree/main/Splunk%20SOAR) automatically closes the corresponding alert in GTI.

______________________________________________________________________

## ASM Issues

- **Parameters:**

  - **Search String:** Search string (fields `last_seen_after`, `last_seen_before`, and `first_seen_after` will be ignored). This is a recommended option for the ASM Issues data ingestion type to filter relevant issues and reduce noise (string).
  - **Project ID:** Project ID (string).

- **Status Mapping of ASM Issues:**

  | ASM Issue Status | SOAR Container Status |
  |---------------------|----------------------|
  | Open | Open |
  | Triaged | Open |
  | In Progress | Open |
  | Closed | Closed |
  | Mitigated | Closed |
  | Resolved | Closed |
  | Duplicate | Closed |
  | Out of Scope | Closed |
  | Benign | Closed |
  | Risk Accepted | Closed |
  | False Positive | Closed |
  | Unable to Reproduce | Closed |
  | Tracked Externally | Closed |

- **Severity Mapping of ASM Issues:**

  | ASM Issue Severity | SOAR Container Severity |
  |--------------------|------------------------|
  | 1 | High |
  | 2 | High |
  | 3 | Medium |
  | 4 | Low |
  | 5 | Low |

- **Container Creation:**\
  Each ASM issue will result in the creation of a separate container. One artifact will be created inside the container and will have certain important fields from issue visible inside the artifact. To get complete details about the issue, download the artifact JSON.

- **Container Updates:**\
  Fields of artifacts inside the container will be updated **only if** the `last_seen` value of the issue changes in GTI. If there are any other updates but the `last_seen` field hasn't changed, the artifact will not be updated.

- **Closing ASM Issues in GTI:**\
  When an ASM issue container is closed in Splunk SOAR, the playbook provided in this [repository](https://github.com/virusTotal/gti-soar-playbooks/tree/main/Splunk%20SOAR) automatically closes the corresponding issue in GTI.

______________________________________________________________________

## Relevance System Alerts

- **Parameters:**

  - **Project ID (RS Alerts):** The GCP project ID associated with your RS alerts (string, **required**). RS Alerts ingestion will fail if this field is not configured.

  - **Filter:** Shared with IOC Stream. For Relevance System Alerts, this field accepts filter expression in the documentation [here](https://gtidocs.virustotal.com/reference/list-alerts) to narrow down alerts. `audit.update_time` conditions are **automatically removed** from the filter as the integration manages time-windowing internally using the **Lookback Days** parameter. Do not include `audit.update_time` in the filter string, as it will be stripped before the API call.

    - **Example filters:**
      - `state = "NEW"`
      - `severityAnalysis.severityLevel = "SEVERITY_LEVEL_HIGH"`

  - **Limit:** Maximum number of RS alerts to ingest per poll (max: 1000).

  - **Lookback Days:** Number of days of historical data to retrieve during the initial poll (max: 5).

- **Status Mapping of RS Alerts:**

  | RS Alert State | SOAR Container Status |
  |----------------------|----------------------|
  | New | New |
  | Read | Open |
  | Triaged | Open |
  | Escalated | Open |
  | Resolved | Closed |
  | Benign | Closed |
  | False Positive | Closed |
  | Tracked Externally | Closed |
  | Not Actionable | Closed |
  | Duplicate | Closed |

- **Severity Mapping of Relevance System Alerts:**

  | RS Alert Severity | SOAR Container Severity |
  |--------------------|------------------------|
  | Severity Level Low | Low |
  | Severity Level Medium | Medium |
  | Severity Level High | High |

- **Container Creation:**\
  Each Relevance System Alert results in one container, identified by the alert's unique name (used as `source_data_identifier`). If the same alert is encountered in a subsequent poll, the existing container is reused and a new artifact is appended to it.

- **Container Updates:**\
  The container's status and severity are updated on every poll based on the current state and severity level of the alert in GTI. Containers for alerts in a terminal state (Resolved, Benign, False Positive, Tracked Externally, Not Actionable, Duplicate) are automatically tagged with `closed_on_gti`.

- **Closing RS Alert in GTI:**\
  When a RS alert container is closed in Splunk SOAR, the playbook provided in this [repository](https://github.com/virusTotal/gti-soar-playbooks/tree/main/Splunk%20SOAR) automatically updates the status of the corresponding issue in GTI to **Resolved**.

______________________________________________________________________

### Prerequisites for RS Alert Access

Access to The Relevance System requires an active Google Threat Intelligence license. Your experience within the system will depend on your assigned role:

- **GTI Alerts Admin:** Required to set up the initial Organization Profile, configure integrations, and manage system-wide alert thresholds.
- **GTI Alerts User:** Designed for day-to-day analysts. Users can view dashboards, investigate alerts, change alert statuses, and provide feedback, but cannot change the core organizational configuration.

For more information, refer to the [Dark Web Intel documentation](https://gtidocs.virustotal.com/docs/dark-web-intel).

______________________________________________________________________

## Steps to Configure the Google Threat Intelligence Splunk SOAR Asset

Follow these steps to create an asset for the Splunk SOAR Platform:

1. **Log in to the Google Threat Intelligence Platform.**

1. **Obtain your API Key:**

   - From the Left Navbar/Menu, click **API Key**.
   - Access your API key.

1. **Obtain your Project ID:**

   - In the URL when accessing GTI Alerts, for example: `https://proactive.virustotal.com/alerts?...&project=projects%2F**your-project-id**`
   - The Project ID is `your-project-id`.

1. **Log in to your Splunk SOAR Platform.**

1. **Navigate to the Apps section:**

   - Navigate to the Home dropdown and select **Apps**.
   - Search for **Google Threat Intelligence** from the search box.

1. **Create a new asset:**

   - Click on the **CONFIGURE NEW ASSET** button.

1. **Configure Asset Info:**

   - Navigate to the **Asset Info** tab.
   - Enter the **Asset name** and **Asset description**.

1. **Configure Asset Settings:**

   - Navigate to the **Asset Settings** tab.
   - Paste the **API key** of your Google Threat Intelligence Platform.
   - Add the **Project ID** of your GTI instance in the **Project ID** parameter.

1. **Save the asset.**

1. **Test connectivity:**

   - Click the **TEST CONNECTIVITY** button to test the connectivity of the Splunk SOAR server to the Google Threat Intelligence.

______________________________________________________________________
