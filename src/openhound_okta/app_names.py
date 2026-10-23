"""Okta application names (``Application.name``, published as ``app_type``)."""

from enum import StrEnum


class AppName(StrEnum):
    """Okta application names the collector recognizes.

    Members are plain strings, so they compare equal to ``Application.name`` values.
    The comment above each member is the Okta Integration Network (OIN) catalog title.
    """

    # --- Hybrid-auth, sync and fully normalized OIN SAML apps ---

    # Active Directory (built-in, not in OIN)
    ACTIVE_DIRECTORY = "active_directory"
    # LDAP Interface (built-in, not in OIN)
    LDAP_INTERFACE = "ldap_interface"
    # Okta Org2Org
    OKTA_ORG2ORG = "okta_org2org"
    # Jamf Pro - Admin Console (SAML)
    JAMF_SAML = "jamfsoftwareserver"
    # Jamf Pro (SWA)
    JAMF_SWA = "casper"
    # GitHub Enterprise Cloud - Organization
    GITHUB_CLOUD = "githubcloud"
    # GitHub Enterprise Managed User
    GITHUB_ENTERPRISE_MANAGED_USER = "githubenterprisemanageduser"
    # 1Password Enterprise Password Manager
    ONE_PASSWORD_BUSINESS = "1password_business"
    # Snowflake
    SNOWFLAKE = "snowflake"
    # Microsoft Office 365
    OFFICE365 = "office365"
    # Asana
    ASANA = "asana"
    # Miro (formerly RealtimeBoard)
    MIRO = "realtime_board"
    # Palo Alto Networks GlobalProtect
    PALO_ALTO_GLOBALPROTECT = "panw_globalprotect"
    # Slack
    SLACK = "slack"
    # Zoom
    ZOOM = "zoomus"

    # --- Apps commonly assigned in customer tenants ---

    # Salesforce.com
    SALESFORCE = "salesforce"
    # Salesforce Marketing Cloud
    SALESFORCE_MARKETING_CLOUD = "exacttarget"
    # ServiceNow User Directory (UD)
    SERVICENOW_UD = "servicenow_ud"
    # Workday
    WORKDAY = "workday"
    # Splunk Enterprise
    SPLUNK_ENTERPRISE = "splunk"
    # Splunk Cloud
    SPLUNK_CLOUD = "splunkcloud"
    # NetSuite
    NETSUITE = "netsuite"
    # Databricks
    DATABRICKS = "databricks"
    # Atlassian Confluence Server
    CONFLUENCE_SERVER = "confluence_onprem"
    # Atlassian Cloud
    ATLASSIAN_CLOUD = "atlassian"
    # Datadog
    DATADOG = "datadog"
    # Zendesk
    ZENDESK = "zendesk"
    # Zapier SAML
    ZAPIER = "zapier"
    # AWS Account Federation
    AWS_ACCOUNT_FEDERATION = "amazon_aws"
    # AWS IAM Identity Center
    AWS_IAM_IDENTITY_CENTER = "amazon_aws_sso"
    # monday.com
    MONDAY = "mondaycom"
    # Google Workspace
    GOOGLE_WORKSPACE = "google"
    # Google Cloud Platform
    GOOGLE_CLOUD_PLATFORM = "cloudconsole"
    # Oracle IAM
    ORACLE_IAM = "oracleenterprisemanager"
    # Oracle Cloud Infrastructure IAM
    ORACLE_CLOUD_INFRASTRUCTURE_IAM = "oraclecloudinfrastructureiam"
    # Oracle Identity Cloud Service
    ORACLE_IDENTITY_CLOUD_SERVICE = "oracleics"
    # Oracle Hyperion EPM Cloud Services
    ORACLE_HYPERION_EPM_CLOUD = "oraclehyperionepmcloud"
    # Mimecast Personal Portal v3
    MIMECAST_PERSONAL_PORTAL = "mimecastppv3"
    # Box
    BOX = "boxnet"
    # Proofpoint Protection Server
    PROOFPOINT = "proofpoint"
    # Delinea Secret Server
    DELINEA_SECRET_SERVER = "secret_serversaml"
    # Keeper Password Manager and Digital Vault
    KEEPER = "keepersecurity"
    # Qualys Guard
    QUALYS_GUARD = "qualys-guard"
    # CyberArk Password Vault Web Access
    CYBERARK_PVWA = "cyberarkpvwa"
    # SharePoint (On-Premise)
    SHAREPOINT_ON_PREMISE = "sharepoint_onpremise"
    # Terraform Cloud
    TERRAFORM_CLOUD = "terraformcloud"
    # Artifactory (Okta's key really is "teachscape")
    ARTIFACTORY = "teachscape"
    # VMware Carbon Black Cloud
    CARBON_BLACK_CLOUD = "carbonblack_psc"
