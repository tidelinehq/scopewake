"""Build scopewake/data/saas_ai_catalogue.json.

Rules (see docs/vendor-catalogue.md):
- A fact is only filled when it was read from the vendor's own documentation; the source URL and check date go with it.
- Anything not checked stays "unverified". Product identity (names, domains) is matching configuration, not a claim
  about AI behaviour.
- Re-check monthly; bump VERSION; run `scopewake catalogue-diff old.json new.json` and keep the output as the change log.
"""
import json
from pathlib import Path

VERSION = "2026.10.26-v0"
CHECKED = "2026-10-26"
U = "unverified"
OUT = Path(__file__).resolve().parents[1] / "scopewake" / "data" / "saas_ai_catalogue.json"


def F(name, default_on=U, training=U, providers=U, admin=U, sources=(), notes=""):
    f = {"name": name, "default_on": default_on, "customer_data_training": training, "model_providers": providers,
         "admin_can_disable": admin, "sources": list(sources), "notes": notes}
    f["checked"] = CHECKED if sources else ""
    return f


def P(pid, product, vendor, category, features, domains=(), idp=(), ext=(), shadow=False, vendor_aliases=()):
    return {"id": pid, "product": product, "vendor": vendor, "category": category, "shadow_ai": shadow,
            "vendor_aliases": list(vendor_aliases), "idp_names": list(idp), "domains": list(domains),
            "extension_names": list(ext), "extension_ids": [], "features": features}


MS_COPILOT = "https://learn.microsoft.com/en-us/microsoft-365/copilot/microsoft-365-copilot-privacy"
MS_CHAT = "https://learn.microsoft.com/en-us/copilot/privacy-and-protections"
SF = "https://help.salesforce.com/s/articleView?id=ai.generative_ai_trust_layer.htm&type=5"
SLACK = "https://slack.com/trust/data-management/privacy-principles"
ZOOM = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0057623"
ATL = "https://www.atlassian.com/trust/ai"
NOTION = "https://www.notion.com/help/notion-ai-security-practices"
GWS = "https://knowledge.workspace.google.com/admin/generative-ai/generative-ai-in-google-workspace-privacy-hub"
GEMINI_APPS = "https://support.google.com/gemini/answer/13594961"
GH = "https://copilot.github.trust.page/faq"
OAI = "https://openai.com/enterprise-privacy/"
ANT = "https://privacy.claude.com/en/articles/7996868-is-my-data-used-for-model-training"
CANVA = "https://www.canva.com/policies/ai-product-terms/"
GRAM = "https://www.grammarly.com/trust"
OTTER = "https://otter.ai/privacy-policy"
DEEPSEEK = "https://cdn.deepseek.com/policies/en-US/deepseek-privacy-policy.html"
PPLX = "https://www.perplexity.ai/hub/legal/privacy-notice"

PRODUCTS = [
    # ---------------- Collaboration and productivity suites
    P("microsoft-365-copilot", "Microsoft 365 Copilot", "Microsoft", "productivity suite", [
        F("Microsoft 365 Copilot (Word, Excel, Outlook, Teams, SharePoint)", training=False,
          providers=["OpenAI (Azure OpenAI)", "Anthropic"], admin=True, sources=[MS_COPILOT],
          notes="Vendor: prompts, responses and Microsoft Graph data aren't used to train foundation LLMs; admins choose "
                "whether Anthropic models power experiences and which agents are allowed."),
        F("Microsoft 365 Copilot Chat (web grounded, enterprise data protection)", training=False, sources=[MS_CHAT]),
    ], domains=["copilot.microsoft.com", "m365.cloud.microsoft", "copilot.cloud.microsoft"],
        idp=["Microsoft 365", "Office 365", "Microsoft Teams", "SharePoint Online", "Exchange Online", "Microsoft Copilot"],
        vendor_aliases=["Microsoft Corporation", "MSFT"]),
    P("microsoft-dynamics-365", "Dynamics 365", "Microsoft", "CRM / ERP",
      [F("Copilot in Dynamics 365")], idp=["Dynamics 365", "Dynamics CRM", "Microsoft Dynamics"],
      domains=["dynamics.com"], vendor_aliases=["Microsoft Corporation"]),
    P("microsoft-power-platform", "Power Platform", "Microsoft", "low-code",
      [F("Copilot Studio agents"), F("Copilot in Power Apps / Power Automate")],
      idp=["Power Apps", "Power Automate", "Copilot Studio", "Power Platform"],
      domains=["powerapps.com", "powerautomate.com", "copilotstudio.microsoft.com"], vendor_aliases=["Microsoft Corporation"]),
    P("microsoft-power-bi", "Power BI / Microsoft Fabric", "Microsoft", "analytics",
      [F("Copilot in Power BI and Fabric")], idp=["Power BI", "Microsoft Fabric"],
      domains=["powerbi.com", "fabric.microsoft.com"], vendor_aliases=["Microsoft Corporation"]),
    P("google-workspace", "Google Workspace", "Google", "productivity suite", [
        F("Gemini in Workspace (Gmail, Docs, Sheets, Meet) and the Gemini app",
          default_on="yes: the Gemini app is a core service turned on by default", training=False,
          providers=["Google (Gemini)"], admin=True, sources=[GWS],
          notes="Vendor: content not used for generative-model training outside your domain without permission."),
    ], idp=["Google Workspace", "G Suite", "Gmail", "Google Drive"], domains=["workspace.google.com"],
        vendor_aliases=["Google LLC", "Alphabet"]),
    P("zoom", "Zoom Workplace", "Zoom", "meetings", [
        F("Zoom AI Companion (summaries, meeting questions, smart recordings)", training=False, admin=True, sources=[ZOOM],
          notes="Vendor: audio, video, chat, screen sharing and attachments are not used to train Zoom's or third-party "
                "models; admins can enable or disable AI features for the account or groups."),
    ], idp=["Zoom", "Zoom Workplace", "Zoom Video Communications"], domains=["zoom.us", "zoom.com"],
        vendor_aliases=["Zoom Video Communications", "Zoom Communications"]),
    P("webex", "Webex", "Cisco", "meetings", [F("Cisco AI Assistant for Webex", admin="yes: user access to AI Assistant and AI features is managed in Control Hub",
                                     sources=["https://help.webex.com/en-us/article/9dofjcb/Customize-Cisco-AI-Assistant-and-AI-features-in-Control-Hub"])], idp=["Webex", "Cisco Webex"],
      domains=["webex.com"], vendor_aliases=["Cisco Systems"]),
    P("slack", "Slack", "Salesforce", "messaging", [
        F("Slack AI (summaries, search answers, recaps)",
          training="no, unless the customer gives affirmative opt-in consent",
          providers="third-party LLMs hosted in Slack's cloud provider (e.g. AWS) infrastructure", sources=[SLACK]),
        F("Slack global ML models (search ranking, suggestions; not generative)",
          training="yes, unless the customer opts out", sources=[SLACK],
          notes="Vendor offers an opt-out to exclude customer data from training Slack global models."),
    ], idp=["Slack"], domains=["slack.com"], vendor_aliases=["Slack Technologies", "Salesforce"]),
    P("atlassian", "Jira / Confluence (Atlassian Cloud)", "Atlassian", "work management", [
        F("Rovo and Atlassian AI features",
          default_on="yes for Rovo Search, Studio and Bookmarks (always on, part of the platform)",
          training="customer metadata may be used to fine-tune open-source models run within Atlassian's infrastructure",
          providers=["OpenAI", "Anthropic", "Google"],
          admin="partly: admins can activate or deactivate AI-powered Rovo features; Search, Studio and Bookmarks are always on",
          sources=[ATL]),
    ], idp=["Jira", "Confluence", "Atlassian", "Jira Service Management", "Trello", "Loom", "Bitbucket"],
        domains=["atlassian.net", "atlassian.com", "loom.com", "trello.com"], vendor_aliases=["Atlassian Corporation"]),
    P("notion", "Notion", "Notion Labs", "docs / wiki", [
        F("Notion AI", training="no, by default", sources=[NOTION]),
    ], idp=["Notion"], domains=["notion.so", "notion.com"]),
    P("miro", "Miro", "Miro", "whiteboard", [F("Miro AI")], idp=["Miro"], domains=["miro.com"]),
    P("box", "Box", "Box", "content management", [F("Box AI", training="no, not without the customer's explicit approval",
                           sources=["https://www.box.com/ai/trust"])], idp=["Box"], domains=["box.com"]),
    P("dropbox", "Dropbox", "Dropbox", "content management", [F("Dropbox Dash / Dropbox AI")], idp=["Dropbox"],
      domains=["dropbox.com"]),
    P("adobe-acrobat", "Adobe Acrobat / Document Cloud", "Adobe", "documents", [F("Acrobat AI Assistant")],
      idp=["Adobe Acrobat", "Adobe Document Cloud", "Adobe Creative Cloud", "Adobe"],
      domains=["acrobat.adobe.com", "documentcloud.adobe.com"], vendor_aliases=["Adobe Inc"]),
    P("adobe-firefly", "Adobe Firefly / Express", "Adobe", "creative", [F("Firefly generative features")],
      idp=["Adobe Express", "Adobe Firefly"], domains=["firefly.adobe.com", "express.adobe.com"], vendor_aliases=["Adobe Inc"]),
    P("docusign", "Docusign", "Docusign", "e-signature / agreements", [F("Docusign IAM AI (agreement analysis)")],
      idp=["DocuSign", "Docusign"], domains=["docusign.com", "docusign.net"]),
    P("canva", "Canva", "Canva", "design", [
        F("Canva Magic Studio", training="controlled by privacy settings; data may be used to improve AI services",
          providers="unnamed 'Technology Partners'", sources=[CANVA]),
    ], idp=["Canva"], domains=["canva.com"]),
    P("figma", "Figma", "Figma", "design", [F("Figma AI")], idp=["Figma"], domains=["figma.com"]),
    P("asana", "Asana", "Asana", "work management", [F("Asana AI / AI Studio")], idp=["Asana"], domains=["asana.com"]),
    P("monday", "monday.com", "monday.com", "work management", [F("monday AI")], idp=["monday.com"],
      domains=["monday.com"]),
    P("smartsheet", "Smartsheet", "Smartsheet", "work management", [F("Smartsheet AI")], idp=["Smartsheet"],
      domains=["smartsheet.com"]),
    P("airtable", "Airtable", "Airtable", "work management", [F("Airtable AI")], idp=["Airtable"],
      domains=["airtable.com"]),
    # ---------------- CRM, service, HR, finance
    P("salesforce", "Salesforce", "Salesforce", "CRM", [
        F("Agentforce / Einstein generative AI", training=False, providers=["OpenAI"], sources=[SF],
          notes="Vendor (Einstein Trust Layer): data isn't retained by third-party LLMs and isn't used for their training; "
                "OpenAI is the provider named on the page."),
    ], idp=["Salesforce", "Sales Cloud", "Service Cloud", "Financial Services Cloud", "Marketing Cloud", "Tableau CRM"],
        domains=["salesforce.com", "force.com", "my.salesforce.com"], vendor_aliases=["salesforce.com inc"]),
    P("servicenow", "ServiceNow", "ServiceNow", "IT service management", [F("Now Assist", notes="Data-sharing for model improvement has an opt-out in Now Assist Admin > Settings > "
                                       "Data sharing (per a ServiceNow community answer, not yet confirmed in product docs).")],
      idp=["ServiceNow"], domains=["service-now.com", "servicenow.com"]),
    P("workday", "Workday", "Workday", "HR / finance", [F("Workday AI and agents",
                                       training="yes for contributed data categories; some features require opting in, and "
                                                "Universal MSA customers can opt out by support request",
                                       sources=["https://doc.workday.com/admin-guide/en-us/workday-ai/ai-data-contributions/manage-workday-ai-data-contributions-for-universal.html",
                                                "https://doc.workday.com/admin-guide/en-us/workday-ai/ai-data-contributions/reference--machine-learning-data-contributions.html"])], idp=["Workday"],
      domains=["workday.com", "myworkday.com"]),
    P("sap-successfactors", "SAP SuccessFactors", "SAP", "HR", [F("Joule copilot")],
      idp=["SuccessFactors", "SAP SuccessFactors"], domains=["successfactors.com", "sapsf.com"], vendor_aliases=["SAP SE"]),
    P("sap-concur", "SAP Concur", "SAP", "expenses", [F("Concur AI features / Joule")], idp=["Concur", "SAP Concur"],
      domains=["concursolutions.com"], vendor_aliases=["SAP SE"]),
    P("sap-ariba", "SAP Ariba", "SAP", "procurement", [F("Joule in Ariba")], idp=["Ariba", "SAP Ariba"],
      domains=["ariba.com"], vendor_aliases=["SAP SE"]),
    P("oracle-fusion", "Oracle Fusion Cloud Applications", "Oracle", "ERP / HCM", [F("AI agents in Fusion Applications")],
      idp=["Oracle Fusion", "Oracle Cloud", "Oracle HCM", "Oracle ERP"], domains=["oraclecloud.com"],
      vendor_aliases=["Oracle Corporation"]),
    P("coupa", "Coupa", "Coupa", "procurement", [F("Coupa Navi / AI agents")], idp=["Coupa"], domains=["coupahost.com", "coupa.com"]),
    P("zendesk", "Zendesk", "Zendesk", "customer service", [F("Zendesk AI agents and copilot",
                                               training="no for generative AI (pre-trained models; third parties don't train on inputs); "
                                                        "proprietary classification models may be trained on customer data as the customer instructs",
                                               sources=["https://support.zendesk.com/hc/en-us/articles/5729714731290-Zendesk-AI-Data-Use-Information",
                                                        "https://support.zendesk.com/hc/en-us/articles/9196781863578-AI-Trust-at-Zendesk"])], idp=["Zendesk"],
      domains=["zendesk.com"]),
    P("freshworks", "Freshworks (Freshdesk, Freshservice)", "Freshworks", "customer / IT service",
      [F("Freddy AI")], idp=["Freshdesk", "Freshservice", "Freshworks"], domains=["freshdesk.com", "freshservice.com", "freshworks.com"]),
    P("hubspot", "HubSpot", "HubSpot", "CRM / marketing", [F("Breeze AI")], idp=["HubSpot"], domains=["hubspot.com"]),
    P("intercom", "Intercom", "Intercom", "customer service", [F("Fin AI agent")], idp=["Intercom"],
      domains=["intercom.com", "intercom.io"]),
    P("genesys", "Genesys Cloud", "Genesys", "contact centre", [F("Genesys AI (copilot, virtual agents)")],
      idp=["Genesys Cloud", "Genesys", "PureCloud"], domains=["mypurecloud.com", "genesys.com"]),
    P("nice-cxone", "NICE CXone", "NICE", "contact centre", [F("Enlighten AI")], idp=["NICE CXone", "inContact"],
      domains=["niceincontact.com", "nicecxone.com"]),
    P("gong", "Gong", "Gong", "revenue intelligence", [F("Gong AI (call recording and analysis)")], idp=["Gong"],
      domains=["gong.io"]),
    P("linkedin", "LinkedIn Recruiter / Sales Navigator", "Microsoft", "recruiting / sales",
      [F("AI-assisted messaging and search")], idp=["LinkedIn Recruiter", "LinkedIn Sales Navigator", "LinkedIn Learning"],
      domains=[], vendor_aliases=["LinkedIn Corporation", "Microsoft Corporation"]),
    P("workiva", "Workiva", "Workiva", "reporting", [F("Workiva AI")], idp=["Workiva"], domains=["workiva.com"]),
    P("uipath", "UiPath", "UiPath", "automation", [F("UiPath Autopilot / agents")], idp=["UiPath", "UiPath Automation Cloud"],
      domains=["uipath.com"]),
    P("pega", "Pega", "Pegasystems", "process automation", [F("Pega GenAI")], idp=["Pega", "Pega Cloud"],
      domains=["pega.com", "pegacloud.net"]),
    P("appian", "Appian", "Appian", "process automation", [F("Appian AI")], idp=["Appian"], domains=["appiancloud.com"]),
    P("ncino", "nCino", "nCino", "banking platform", [F("nCino Banking Advisor")], idp=["nCino"], domains=["ncino.com"]),
    P("temenos", "Temenos (SaaS)", "Temenos", "core banking", [F("Temenos generative AI features")], idp=["Temenos"],
      domains=["temenos.com"]),
    P("lseg-workspace", "LSEG Workspace", "London Stock Exchange Group", "market data",
      [F("AI features in Workspace")], idp=["LSEG Workspace", "Refinitiv", "Eikon"], domains=["refinitiv.com", "lseg.com"],
      vendor_aliases=["LSEG", "Refinitiv"]),
    P("bloomberg", "Bloomberg Terminal", "Bloomberg", "market data", [F("Bloomberg AI document insights")],
      idp=["Bloomberg"], domains=[], vendor_aliases=["Bloomberg L.P."]),
    # ---------------- Data, analytics, engineering, security
    P("github-copilot", "GitHub Copilot", "GitHub (Microsoft)", "developer", [
        F("GitHub Copilot Business / Enterprise", training=False, providers=["Anthropic", "Google"], sources=[GH],
          notes="Vendor trust centre: Business/Enterprise data isn't used to train models; other model providers may "
                "be selectable and are not listed here until checked."),
    ], idp=["GitHub", "GitHub Enterprise", "GitHub Copilot"], domains=["github.com", "githubcopilot.com"],
        ext=["GitHub Copilot"], vendor_aliases=["GitHub Inc", "Microsoft Corporation"]),
    P("snowflake", "Snowflake", "Snowflake", "data platform", [F("Snowflake Cortex AI")], idp=["Snowflake"],
      domains=["snowflakecomputing.com"]),
    P("databricks", "Databricks", "Databricks", "data platform", [F("Databricks Assistant / Mosaic AI")],
      idp=["Databricks"], domains=["databricks.com", "cloud.databricks.com"]),
    P("tableau", "Tableau Cloud", "Salesforce", "analytics", [F("Tableau Agent / Pulse")], idp=["Tableau", "Tableau Cloud"],
      domains=["online.tableau.com"], vendor_aliases=["Salesforce"]),
    P("datadog", "Datadog", "Datadog", "observability", [F("Bits AI")], idp=["Datadog"], domains=["datadoghq.com"]),
    P("splunk", "Splunk Cloud", "Cisco", "observability / SIEM", [F("Splunk AI Assistant")], idp=["Splunk"],
      domains=["splunkcloud.com"], vendor_aliases=["Splunk Inc", "Cisco Systems"]),
    P("crowdstrike", "CrowdStrike Falcon", "CrowdStrike", "security", [F("Charlotte AI")],
      idp=["CrowdStrike", "Falcon"], domains=["crowdstrike.com"]),
    P("microsoft-security-copilot", "Microsoft Security Copilot", "Microsoft", "security", [F("Security Copilot")],
      idp=["Security Copilot", "Microsoft Defender", "Microsoft Sentinel"], domains=["securitycopilot.microsoft.com"],
      vendor_aliases=["Microsoft Corporation"]),
    P("palo-alto-cortex", "Palo Alto Networks Cortex / Prisma", "Palo Alto Networks", "security",
      [F("Cortex AI features / Prisma AIRS")], idp=["Cortex XSIAM", "Cortex XDR", "Prisma Cloud", "Prisma Access"],
      domains=["paloaltonetworks.com"]),
    P("okta", "Okta", "Okta", "identity", [F("Okta AI features")], idp=["Okta Admin Console"], domains=[]),
    P("zscaler", "Zscaler", "Zscaler", "network security", [F("Zscaler AI features")],
      idp=["Zscaler", "ZIA", "ZPA"], domains=["zscaler.net", "zscaler.com"]),
    P("cursor", "Cursor", "Anysphere", "developer", [F("Cursor AI editor and agents")], idp=["Cursor"],
      domains=["cursor.com", "cursor.sh"], shadow=True),
    # ---------------- Standalone AI assistants (often shadow AI)
    P("chatgpt", "ChatGPT", "OpenAI", "AI assistant", [
        F("ChatGPT Business / Enterprise", training="no, not by default", providers=["OpenAI"],
          admin="admin feature and access controls available", sources=[OAI]),
        F("ChatGPT Free / Plus (personal accounts)",
          notes="Training defaults for personal accounts not yet checked against vendor docs."),
    ], idp=["ChatGPT", "ChatGPT Enterprise", "OpenAI"], domains=["chatgpt.com", "chat.openai.com", "openai.com"],
        ext=["ChatGPT"], shadow=True, vendor_aliases=["OpenAI LLC", "OpenAI OpCo"]),
    P("claude", "Claude", "Anthropic", "AI assistant", [
        F("Claude for Work (Team / Enterprise) and API", training="no, not by default", providers=["Anthropic"],
          sources=[ANT]),
        F("Claude Free / Pro / Max (personal accounts)",
          notes="Training defaults for personal accounts not yet checked against vendor docs."),
    ], idp=["Claude", "Anthropic"], domains=["claude.ai", "anthropic.com", "claude.com"], ext=["Claude"], shadow=True,
        vendor_aliases=["Anthropic PBC"]),
    P("gemini-consumer", "Gemini (personal Google accounts)", "Google", "AI assistant", [
        F("Gemini Apps", training="yes, conversations may be used to improve models and reviewed by humans unless Keep Activity is off",
          providers=["Google (Gemini)"], sources=[GEMINI_APPS]),
    ], domains=["gemini.google.com", "bard.google.com", "aistudio.google.com", "notebooklm.google.com"], shadow=True,
        vendor_aliases=["Google LLC"]),
    P("copilot-consumer", "Microsoft Copilot (personal accounts)", "Microsoft", "AI assistant",
      [F("Copilot consumer app")], domains=[], shadow=True, vendor_aliases=["Microsoft Corporation"]),
    P("perplexity", "Perplexity", "Perplexity AI", "AI search", [
        F("Perplexity consumer", training="yes, prompts may be used to improve AI models", sources=[PPLX],
          notes="Vendor: this notice doesn't apply to Enterprise and API offerings, where Perplexity acts as a service provider."),
    ], idp=["Perplexity", "Perplexity Enterprise"], domains=["perplexity.ai"], ext=["Perplexity"], shadow=True),
    P("deepseek", "DeepSeek", "DeepSeek", "AI assistant", [
        F("DeepSeek chat and app", training="yes, with a user right to opt out", sources=[DEEPSEEK],
          notes="Vendor privacy policy: personal data is processed and stored in the People's Republic of China."),
    ], domains=["deepseek.com", "chat.deepseek.com"], shadow=True),
    P("grok", "Grok", "xAI", "AI assistant", [F("Grok")], domains=["grok.com", "x.ai"], shadow=True),
    P("mistral", "Le Chat", "Mistral AI", "AI assistant", [F("Le Chat")], domains=["chat.mistral.ai", "mistral.ai"],
      shadow=True),
    P("meta-ai", "Meta AI", "Meta", "AI assistant", [F("Meta AI")], domains=["meta.ai"], shadow=True),
    P("poe", "Poe", "Quora", "AI assistant", [F("Poe multi-model chat")], domains=["poe.com"], shadow=True),
    P("character-ai", "Character.AI", "Character Technologies", "AI assistant", [F("Character chat")],
      domains=["character.ai"], shadow=True),
    P("midjourney", "Midjourney", "Midjourney", "image generation", [F("Image generation")], domains=["midjourney.com"],
      shadow=True),
    P("otter", "Otter.ai", "Otter.ai", "meeting notetaker", [
        F("Otter AI notetaker", training="yes, on de-identified recordings and transcripts", sources=[OTTER],
          notes="Vendor privacy policy: proprietary AI is trained on de-identified audio and transcriptions that may contain personal information."),
    ], idp=["Otter", "Otter.ai"], domains=["otter.ai"], ext=["Otter.ai"], shadow=True),
    P("fireflies", "Fireflies.ai", "Fireflies.ai", "meeting notetaker", [F("Fireflies notetaker")],
      idp=["Fireflies"], domains=["fireflies.ai"], ext=["Fireflies"], shadow=True),
    P("read-ai", "Read AI", "Read AI", "meeting notetaker", [F("Read AI notetaker")], domains=["read.ai"],
      ext=["Read AI"], shadow=True),
    P("tldv", "tl;dv", "tl;dv", "meeting notetaker", [F("tl;dv notetaker")], domains=["tldv.io"], ext=["tl;dv"],
      shadow=True),
    P("grammarly", "Grammarly", "Grammarly (Superhuman)", "writing assistant", [
        F("Grammarly generative AI", training="yes, unless 'Product Improvement and Training' is turned off",
          sources=[GRAM], notes="Whether Business/Enterprise defaults differ is not yet checked."),
    ], idp=["Grammarly", "Grammarly Business"], domains=["grammarly.com", "grammarly.io"], ext=["Grammarly"], shadow=True,
        vendor_aliases=["Grammarly Inc", "Superhuman"]),
    P("quillbot", "QuillBot", "Learneo", "writing assistant", [F("Paraphraser and AI writing")], domains=["quillbot.com"],
      ext=["QuillBot"], shadow=True),
    P("deepl", "DeepL", "DeepL", "translation", [F("DeepL Translator / Write")], idp=["DeepL", "DeepL Pro"],
      domains=["deepl.com"], ext=["DeepL"], shadow=True),
    P("jasper", "Jasper", "Jasper AI", "writing assistant", [F("Jasper")], domains=["jasper.ai"], ext=["Jasper"],
      shadow=True),
    P("monica", "Monica", "Monica", "browser AI assistant", [F("Monica sidebar assistant")], domains=["monica.im"],
      ext=["Monica"], shadow=True),
    P("merlin", "Merlin", "Foyer", "browser AI assistant", [F("Merlin sidebar assistant")], domains=["getmerlin.in"],
      ext=["Merlin"], shadow=True),
    P("huggingface", "Hugging Face", "Hugging Face", "AI models / chat", [F("HuggingChat, hosted models")],
      domains=["huggingface.co", "hf.co"], shadow=True),
    P("manus", "Manus", "Manus", "AI agent", [F("Manus agent")], domains=["manus.im"], shadow=True),
]


def main():
    ids = [p["id"] for p in PRODUCTS]
    assert len(ids) == len(set(ids)), "duplicate ids"
    cat = {"kind": "scopewake-saas-ai-catalogue", "version": VERSION, "checked_on": CHECKED,
           "rules": "Facts come from vendor documentation (source + date). Anything not checked is 'unverified'. "
                    "Absence from the catalogue does not mean an app has no AI features.",
           "products": PRODUCTS}
    OUT.write_text(json.dumps(cat, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    facts = [f[k] for p in PRODUCTS for f in p["features"] for k in ("default_on", "customer_data_training", "model_providers", "admin_can_disable")]
    print(f"{len(PRODUCTS)} products, {sum(len(p['features']) for p in PRODUCTS)} features, "
          f"{sum(1 for v in facts if v != U)}/{len(facts)} facts verified -> {OUT}")


if __name__ == "__main__":
    main()
