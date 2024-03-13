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

PAGE_LABEL_TO_SEARCH = "threat-modeling"

ISO_DATE_PATTERN = r'(\d{4}-\d{2}-\d{2})'
LABELED_DATE_PATTERN = r'[Dd]ate:\s*' + ISO_DATE_PATTERN


def to_confluence_url(path):
    return CONFLUENCE_URL + path


def parse_threat_modeling(page):
    # print(page)
    # alternative way to read the wiki page content:
    # get_page_by_id(page_id, expand="body.storage")["body"]["storage"]["value"]

    # should find an ISO-date with label like `Date: 2022-11-29`
    body_dates = confluence.scrap_regex_from_page(page['id'], LABELED_DATE_PATTERN)
    if body_dates is None or len(body_dates) == 0:
        title_dates = re.findall(ISO_DATE_PATTERN, page['title'])
        if title_dates is None or len(title_dates) == 0:
            raise ValueError(f"Can not find *required threat-modeling date*, "
                             f"neither in _page body_ using regex `{LABELED_DATE_PATTERN}`, "
                             f"nor in _page title_ using regex `{ISO_DATE_PATTERN}`!")
        tm_date = title_dates[0]
    else:
        tm_date = re.findall(LABELED_DATE_PATTERN, body_dates[0])[0]

    return {'title': page['title'], 'url': to_confluence_url(page['_links']['webui']), 'date': tm_date}


def to_threat_modeling(page):
    meta = parse_threat_modeling(page)
    print(f"* {meta['date']}: {[meta['title']]}({meta['url']})")
    return ConductionOfSimpleThreatModelingOnTechnicalLevelComponent(
        date=meta['date'],
        title=meta['title'],
        links=[Link(title=meta['title'], url=meta['url'])])


if __name__ == "__main__":
    team_name = 'team-name'
    # mapping team-name or application name to confluence space,
    # example: MagicRecords to space MR (e.g. https://example.atlassian.net/wiki/spaces/MR/pages/3530358832)
    print(f"Confluence: Searching pages by label '{PAGE_LABEL_TO_SEARCH}' ..")
    pages = confluence.get_all_pages_by_label(label=PAGE_LABEL_TO_SEARCH, start=0, limit=100)
    print(f"Confluence: Found {len(pages)} pages:")
    tms = []
    for p in pages:
        try:
            tms.append(to_threat_modeling(p))
        except ValueError as e:
            print(f"WARNING: Skipping page [{p['title']}]({to_confluence_url(p['_links']['webui'])})", "because:", e)

    c = ConductionOfSimpleThreatModelingOnTechnicalLevel(components=tms)
    output_filename = f"{team_name}_application.yaml"
    to_yaml_file(output_filename, c)
    print("YAML output written to file:", output_filename)
