#!/usr/bin/env python3
import datetime
import os
import re
from dataclasses import dataclass
from os import environ
from typing import List

from atlassian import Confluence
from dotenv import load_dotenv
from pydantic_yaml import to_yaml_file

from model import ThreatModeling, \
    Link, Activities, DSOMMapplication, Settings, ThreatModelingComponent

"""
This script finds Confluence wiki pages with specific labels,
and scrape portions of their:
* title
* body text
* space name

to collect meta-information for conducted threat modelings:
* Application
* Team
* Title
* Date
* Links

which is finally distributed as YAML output:
* in files (one file per application)
* within folders (one folder per team)

in order to be used by a DSOMM metric-analyzer.
"""


def configure_confluence():
    load_dotenv()

    confluence_url = environ.get("CONFLUENCE_URL")  # example: "https://example.atlassian.net/wiki"
    confluence_login = environ.get("CONFLUENCE_LOGIN")  # example "username@example.com"
    # create API tokens on https://id.atlassian.com/manage-profile/security/api-tokens
    confluence_password = environ.get("CONFLUENCE_PASSWORD")  # example api-token

    confluence = Confluence(
        url=confluence_url,
        username=confluence_login,
        password=confluence_password,
        timeout=185,
    )

    def to_confluence_url(path):
        return confluence_url + path

    confluence.to_url = to_confluence_url

    return confluence


# TODO: support localization of label and date format (English with ISO, German with dd.mm.yyyy)
ISO_DATE_PATTERN = r'(\d{4}-\d{2}-\d{2})'
LABELED_DATE_PATTERN = r'[Dd]ate:\s*' + ISO_DATE_PATTERN


def parse_threat_modeling(page):
    # alternative way to retrieve the page content:
    # get_page_by_id(page_id, expand="body.storage")["body"]["storage"]["value"]

    # should find an ISO-date with label like `Date: 2022-11-29`
    body_dates = confluence.scrap_regex_from_page(page['id'], LABELED_DATE_PATTERN)
    if body_dates is None or len(body_dates) == 0:
        title_dates = re.findall(ISO_DATE_PATTERN, page['title'])  # TODO: lenient parsing, accept also month `2023-12`
        if title_dates is None or len(title_dates) == 0:
            raise ValueError(f"Can not find *required threat-modeling date*, "
                             f"neither in _page body_ using regex `{LABELED_DATE_PATTERN}`, "
                             f"nor in _page title_ using regex `{ISO_DATE_PATTERN}`!")
        tm_date = title_dates[0]
    else:
        tm_date = re.findall(LABELED_DATE_PATTERN, body_dates[0])[0]

    space_name = page['_expandable']['space'].rsplit('/', 1)[1]  # space-name after last slash

    return {'title': page['title'],
            'url': confluence.to_url(page['_links']['webui']),
            'date': tm_date,
            'space': space_name}


def to_threat_modeling(page, space_mapping):
    meta = parse_threat_modeling(page)
    subject = space_mapping.get(meta['space'], Subject.unmapped_space(meta['space']))
    return ScrapedThreatModeling(subject,
                                 meta['title'],
                                 meta['date'],
                                 links=[Link(title=meta['title'], url=meta['url'])],
                                 source_url=meta['url'])


@dataclass(frozen=True)  # frozen to have a hash for key comparison in dicts
class Subject:
    """Subject for a threat-modeling, at least an application, which may be owned by a team."""
    application_name: str
    team_name: str = '_UNMAPPED_TEAM'

    @classmethod
    def unmapped(cls):
        return Subject(application_name='_UNMAPPED_APP', team_name='_UNMAPPED_TEAM')

    @classmethod
    def unmapped_space(cls, space: str):
        return Subject(application_name=f'_UNMAPPED_SPACE_{space}', team_name=f'_UNMAPPED_SPACE_{space}')

    def __repr__(self):
        if self == Subject.unmapped():
            return '*UNMAPPED* application/team'
        if self.team_name is None or self.team_name == Subject.unmapped().team_name:
            return f"application '{self.application_name}' by *UNMAPPED* team"
        return f"application '{self.application_name}' by team '{self.team_name}'"


@dataclass
class ScrapedThreatModeling:
    """Threat-modeling activity for an application conducted by a team includes:
    Subject ot the threat-modeling:
    1. application name
    2. team name
    The threat-modeling:
    3. title
    4. date
    5. links referencing the source page and supplementary information (like ticket/JIRA-issue, whiteboard/Miro-board)
    """

    subject: Subject
    title: str
    date: datetime.date
    links: List[Link]
    source_url: str

    def __repr__(self):
        return (f"{self.date}: {self.title}({self.source_url})"
                f", for {self.subject}")


def to_component(m: ScrapedThreatModeling):
    return ThreatModelingComponent(date=m.date, title=m.title, links=m.links)


def prepend_header(filename, comment_line):
    with open(filename, 'r') as original:
        data = original.read()
    with open(filename, 'w') as modified:
        modified.write(f"# {comment_line}\n" + data)


def write_yaml_file(folder, subject, modelings, log_verbose=False):
    output_filename = f"{folder}/{subject.team_name}/{subject.application_name}_application.yaml"
    if log_verbose:
        print(f"File I/O: Preparing folder/file `{output_filename}` for {len(modelings)} modeling(s) ..")
    os.makedirs(f"{folder}/{subject.team_name}", exist_ok=True)

    components = [ThreatModelingComponent(date=m.date, title=m.title, links=m.links) for m in modelings]
    c = ThreatModeling(components=components)
    a = Activities(
        threat_modeling=c)  # TODO make this attribute-name configurable, because orgs may have individual names
    s = Settings(team=subject.team_name, application=subject.application_name)
    model = DSOMMapplication(settings=s, activities=a)

    if log_verbose:
        print(f"File I/O: Writing file `{output_filename}` ..")
    to_yaml_file(output_filename, model)
    prepend_header(output_filename,
                   "Auto-generated by Confluence-Collector"
                   " (https://github.com/devsecopsmaturitymodel/collector-confluence)")


@dataclass
class CollectionResult:
    threat_modelings: List[ScrapedThreatModeling]
    errors: List[str]


def collect_threat_modelings(pages, application_map, log_verbose=False):
    collected = []
    errors = []
    for p in pages:
        try:
            tm = to_threat_modeling(p, application_map)
            if log_verbose:
                print(f"* {repr(tm)}")
            collected.append(tm)
        except ValueError as e:
            errors.append(f"Skipping page [{p['title']}]({confluence.to_url(p['_links']['webui'])}) because: {e}")

    return CollectionResult(collected, errors)


def per_app(threat_modelings):
    # group per app
    grouped = {}
    for t in threat_modelings:
        if t.subject not in grouped:
            grouped[t.subject] = []
        grouped[t.subject].append(t)

    return grouped


if __name__ == "__main__":
    confluence = configure_confluence()

    page_label_to_search = "threat-modeling"
    is_verbose = True
    out_path = 'out'
    # map confluence space to application-name or team-name,
    # example: space MR to MagicRecords (e.g. https://example.atlassian.net/wiki/spaces/MR/pages/3530358832)
    space_to_application_map = {'MR': Subject(application_name='magic-records', team_name='magic-team'),
                                'EK': Subject(application_name='elastic-kube', team_name='elastic-kubernauts'),
                                'BED': Subject(application_name='bed-beats')}

    if is_verbose:
        print(f"Confluence: Searching pages by label `{page_label_to_search}` ..")
    found_pages = confluence.get_all_pages_by_label(label=page_label_to_search, start=0, limit=100)
    print(f"Confluence: Found {len(found_pages)} pages.")

    if is_verbose:
        print(f"Scraping: Collecting threat-modelings ..")
    collection = collect_threat_modelings(found_pages, space_to_application_map, log_verbose=is_verbose)
    print(f"Scraping: Collected {len(collection.threat_modelings)} threat-modelings.")
    if len(collection.errors) > 0:
        print(f"Scraping: Collection failed with {len(collection.errors)} errors:\n* ", end="")
        print(*collection.errors, sep="\n* ")

    if is_verbose:
        print(f"Output: Writing files to path `{out_path}` ..")

    file_count = 0
    for app, values in per_app(collection.threat_modelings).items():
        write_yaml_file(out_path, app, values, log_verbose=is_verbose)
        file_count += 1

    print("--- COMPLETED --------------------------------------")
    print(f"Scraping: Exit-code shows number of errors: {len(collection.errors)}")
    print(f"Output: YAML file(s) written: {file_count}")

    exit(len(collection.errors))
