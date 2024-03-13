#!/usr/bin/env python3
import os
import re
from dataclasses import dataclass
from os import environ

from pydantic_yaml import to_yaml_file
from atlassian import Confluence

from model import ConductionOfSimpleThreatModelingOnTechnicalLevel, \
    ConductionOfSimpleThreatModelingOnTechnicalLevelComponent, Link

"""
This script finds Confluence wiki pages with specific labels.

To collect meta-information for conducted threat modelings:
* Team or Application
* Title
* Date
* Issues/Tickets (e.g. links to JIRA)
* Supplemental Docs (e.g. links to Miro)
* Participants
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
    # alternative way to retrieve the page content:
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

    space_name = page['_expandable']['space'].rsplit('/', 1)[1]  # space-name after last slash

    return {'title': page['title'],
            'url': to_confluence_url(page['_links']['webui']),
            'date': tm_date,
            'space': space_name}


def to_threat_modeling(page, space_mapping):
    meta = parse_threat_modeling(page)
    subject = space_mapping.get(meta['space'], Subject(application_name='_UNMAPPED_APP', team_name='_UNMAPPED_TEAM'))
    print(f"* {meta['date']}: {[meta['title']]}({meta['url']}), space `{meta['space']}` mapped to: {subject}")
    return (subject, ConductionOfSimpleThreatModelingOnTechnicalLevelComponent(
        date=meta['date'],
        title=meta['title'],
        links=[Link(title=meta['title'], url=meta['url'])]))


@dataclass
class Subject:
    """Subject for a threat-modeling, at least an application, which may be owned by a team."""
    application_name: str
    team_name: str = '_UNDEFINED_'


if __name__ == "__main__":
    out_path = 'out/'
    # map confluence space to application-name or team-name,
    # example: space MR to MagicRecords (e.g. https://example.atlassian.net/wiki/spaces/MR/pages/3530358832)
    space_to_application_map = {'MR': Subject(application_name='magic-records', team_name='magic-team'),
                                'EK': Subject(application_name='elastic-kube', team_name='elastic-kubernauts'),
                                'BED': Subject(application_name='bed-beats')}

    print(f"Confluence: Searching pages by label '{PAGE_LABEL_TO_SEARCH}' ..")
    pages = confluence.get_all_pages_by_label(label=PAGE_LABEL_TO_SEARCH, start=0, limit=100)
    print(f"Confluence: Found {len(pages)} pages:")

    tms = []
    for p in pages:
        try:
            tms.append(to_threat_modeling(p, space_to_application_map))
        except ValueError as e:
            print(f"WARNING: Skipping page [{p['title']}]({to_confluence_url(p['_links']['webui'])})", "because:", e)

    s = space_to_application_map['MR']
    file_count = 0
    model = ConductionOfSimpleThreatModelingOnTechnicalLevel(components=[t[1] for t in tms if t[0] == s])
    os.makedirs(f"{out_path}/{s.team_name}", exist_ok=True)
    output_filename = f"{out_path}/{s.team_name}/{s.application_name}_application.yaml"
    to_yaml_file(output_filename, model)
    file_count += 1

    print(f"YAML output written in path '{out_path}' to {file_count} file(s).")
    exit(file_count)
