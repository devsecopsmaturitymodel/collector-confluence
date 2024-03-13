#!/usr/bin/env python3
import re
from os import environ

from pydantic_yaml import to_yaml_file
from atlassian import Confluence

from model import ConductionOfSimpleThreatModelingOnTechnicalLevel, \
    ConductionOfSimpleThreatModelingOnTechnicalLevelComponent, Link

"""
This example finds pages with specific labels.
* https://github.com/atlassian-api/atlassian-python-api/tree/master/examples/confluence

To collect meta-information for threat models:
* Team
* Title
* Date
* Participants
* Issues (e.g. links to JIRA)


<quote>
Information identifying the threat model typically includes the the following:
1. Application Name: The name of the application examined.
2. Application Version: The version of the application examined.
3. Description: A high level description of the application.
4. Document Owner: The owner of the threat modeling document.
5. Participants: The participants involved in the threat modeling process for this application.
6. Reviewer: The reviewer(s) of the threat model.
</quote>

Source: OWASP Foundation (2023-Nov): [Threat Modeling Process, Threat Model Information](https://owasp.org/www-community/Threat_Modeling_Process#threat-model-information).

See also: 
* Blog "Let's Talk About MedSec" (24 Apr 2022): [Threat Modeling Knowledge Bases and Templates](https://tmart234.github.io/threat-model-template/)
* Repo from [Izar Tarandach](https://owasp.org/www-board-candidates/2023/izar_tarandach): [izar/pytm](https://github.com/izar/pytm) : A Pythonic framework for threat modeling
"""

CONFLUENCE_URL = environ.get("CONFLUENCE_URL")  # example: "https://example.atlassian.net/wiki"
CONFLUENCE_LOGIN = environ.get("CONFLUENCE_LOGIN")  # example "username@example.com"
# create API tokens on https://id.atlassian.com/manage-profile/security/api-tokens
CONFLUENCE_PASSWORD = environ.get("CONFLUENCE_PASSWORD")  # example api-token
confluence = Confluence(
    url=CONFLUENCE_URL,
    username=CONFLUENCE_LOGIN,
    password=CONFLUENCE_PASSWORD,
    timeout=185,
)

if __name__ == "__main__":
    team_name = 'team-name'
    label = "threat-modeling"
    DATE_PATTERN = r'[Dd]ate:\s*(\d{4}-\d{2}-\d{2})'
    print(f"Confluence: Searching pages by label '{label}' ..")
    pages = confluence.get_all_pages_by_label(label=label, start=0, limit=10)
    print(f"Confluence: Found {len(pages)} pages:")
    tms = []
    for page in pages:
        # should find an ISO-date with label like `Date: 2022-11-29`
        tm_date = confluence.scrap_regex_from_page(page['id'], DATE_PATTERN)
        if tm_date is None:
            raise ValueError(f"Can not find required date on page using regex '{DATE_PATTERN}'!")
        tm_date = re.findall(DATE_PATTERN, tm_date[0])[0]
        # alternative way to read the wiki page content:
        # get_page_by_id(page_id, expand="body.storage")["body"]["storage"]["value"]
        print("*", tm_date, page["title"], CONFLUENCE_URL + page['_links']['tinyui'])
        # print(page)
        link = Link(title=page['title'], url=CONFLUENCE_URL + page['_links']['tinyui'])
        tm = ConductionOfSimpleThreatModelingOnTechnicalLevelComponent(date=tm_date, title=page['title'], links=[link])
        print("Adding Thread-Modelling:", tm)
        tms.append(tm)

    c = ConductionOfSimpleThreatModelingOnTechnicalLevel(components=tms)
    output_filename = f"{team_name}_application.yaml"
    with open(output_filename, 'wb') as f:
        to_yaml_file(f, c)
    print("YAML output written to file:", output_filename)
