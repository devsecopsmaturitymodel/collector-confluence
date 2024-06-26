#!/usr/bin/env python3
import datetime
import os
import re
import base64
import shutil
from collections import defaultdict
from dataclasses import dataclass
from os import environ
from pathlib import Path
from typing import List

import ruamel.yaml
import typer
from atlassian import Confluence
from dotenv import load_dotenv
from pydantic_yaml import to_yaml_file
from git import Repo
from github import GithubIntegration
from github import Auth
from github import Github
from git import Actor

from model import ThreatModeling, \
    Link, Activities, DSOMMapplication, Settings, ThreatModelingComponent

DEFAULT_SEARCH_LABEL = 'threat-modeling'
DEFAULT_ACTIVITY_NAME = 'Threat Modeling'
DEFAULT_SUBFOLDER_NAME = 'activities/automated'

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

YAML_HEADER_AUTOGENERATED_BY = "Auto-generated by Confluence-Collector" \
                               " (https://github.com/devsecopsmaturitymodel/collector-confluence)"

# TODO: support localization of label and date format (English with ISO, German with dd.mm.yyyy)
ISO_DATE_PATTERN = r'(\d{4}-\d{2}-\d{2})'
LABELED_DATE_PATTERN = r'[Dd]ate:\s*' + ISO_DATE_PATTERN
LABELED_APPLICATION_NAME = r"ApplicationName:\s*"
LABELED_APPLICATION_NAME_PATTERN = (LABELED_APPLICATION_NAME +
                                    r"([A-Za-z0-9äöüÄÖÜß.+\-]+(?:\s+[A-Za-z0-9äöüÄÖÜß.+\-]+)*)")
LABELED_TEAM = r"Team:\s*"
LABELED_TEAM_PATTERN = LABELED_TEAM + r"([A-Za-z0-9äöüÄÖÜß.+\-]+(?:\s+[A-Za-z0-9äöüÄÖÜß.+\-]+)*)"

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
class ScrapingConfig:
    space_mapping: dict[str, Subject]
    search_label: str = DEFAULT_SEARCH_LABEL
    activity_name: str = DEFAULT_ACTIVITY_NAME
    subfolder_name: str = DEFAULT_SUBFOLDER_NAME


def load_config(yaml_file: Path = Path('config.yaml')):
    yaml = ruamel.yaml.YAML(typ='safe', pure=True)
    data = yaml.load(yaml_file)

    try:
        space_mapping = {k: Subject(**v) for k, v in data['space_mapping'].items()}
    except KeyError as e:
        missing_key = e.args[0]
        raise ValueError(f"YAML top-level key `{missing_key}` missing."
                         " The value is required to map spaces to applications/teams."
                         f" Valid Example: `{missing_key}:"
                         "{MR: {application_name: 'm-records', team_name: 'm-team'}}`.")
    except TypeError as e:  # Subject.__init__() got an unexpected keyword argument 'application_nam'
        error_cause = e.args[0]
        raise ValueError(f"YAML top-level key `{'space_mapping'}` contains invalid value(s)."
                         f" That caused an error: {error_cause}."
                         f" Valid Example: `{'space_mapping'}:"
                         "{MR: {application_name: 'm-records', team_name: 'm-team'}}`.")

    search_label = DEFAULT_SEARCH_LABEL
    activity_name = DEFAULT_ACTIVITY_NAME
    try:
        search_label = data['search_label']
    except KeyError as e:
        missing_key = e.args[0]
        print(f"WARNING: YAML top-level key `{missing_key}` missing. "
              f"The default label value `{DEFAULT_SEARCH_LABEL}` will be used to search pages.")
    try:
        activity_name = data['activity_name']
    except KeyError as e:
        missing_key = e.args[0]
        print(f"WARNING: YAML top-level key `{missing_key}` missing. "
              f"The default name `{DEFAULT_ACTIVITY_NAME}` will be used to search pages.")

    return ScrapingConfig(space_mapping, search_label, activity_name)


def require_file(config_path: Path):
    if config_path is None:
        raise ValueError("No config file specified.")
    if config_path.is_dir():
        raise ValueError(f"Config `{config_path}` is a directory, but must be a file.")
    elif not config_path.exists():
        raise ValueError(f"Config file `{config_path}` doesn't exist.")


def scrape_to_folder(scraping_config: ScrapingConfig, out_path: Path = Path('out'), log_verbose: bool = False):
    # provoke 404 when limit = True
    # > requests.exceptions.HTTPError: 404 Client Error: Not Found for url:
    # > ../wiki/rest/api/content/search?cql=type%3Dpage+AND+label%3D%22threat-modeling%22&limit=True
    collection = collect_from_confluence(scraping_config.search_label, scraping_config.space_mapping,
                                         # TODO: merge to context-param
                                         log_verbose=log_verbose)
    print(collection.result_as_markdown())

    repo = gitPullAndGetOrigin(out_path, log_verbose)
    files = write_output_files(collection.threat_modelings, out_path.__str__() + "/" + scraping_config.subfolder_name, scraping_config.activity_name, log_verbose)

    author = Actor("Bot Author", environ.get('git_user_mail'))
    committer = Actor("Bot Committer", environ.get('git_user_mail'))

    repo.git.add('--all')
    repo.index.commit("add files by collector-confluence", author=author, committer=committer)
    origin = repo.remote(name='origin')
    origin.push()

    print("--- COMPLETED --------------------------------------")
    print(f"Scraping: Exit-code shows number of errors: {len(collection.errors)}")
    print(f"Output: YAML file(s) written: {len(files)}")

    exit(len(collection.errors))


@dataclass
class ScrapedThreatModeling:
    """Threat-modeling activity for an application conducted by a team includes:
    Subject of the threat-modeling:
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
        return f"{self.date}: [{self.title}]({self.source_url}), for {self.subject}"


@dataclass
class CollectionResult:
    threat_modelings: List[ScrapedThreatModeling]
    errors: List[str]

    def result_as_markdown(self):
        markdown = f"Collected {len(self.threat_modelings)} threat-modelings.\n"
        if len(self.errors) > 0:
            markdown += f"Collection failed with {len(self.errors)} errors:\n"
            markdown += "* " + "\n* ".join(self.errors)
        return markdown


def collect_threat_modelings(pages, space_mapper_fn, confluence: Confluence, log_verbose=False):
    if log_verbose:
        print(f"Scraping: Collecting threat-modelings ..")

    collected = []
    errors = []
    for p in pages:
        try:
            meta = parse_threat_modeling(p, confluence)
            tm = to_threat_modeling(meta, space_mapper_fn)
            team = tm.subject.team_name
            application_name = tm.subject.application_name
            if meta['team'] != "":
                team = meta['team']
            if meta['application_name'] != "":
                application_name = meta['application_name']
            tm.subject = Subject(team_name=team, application_name=application_name)
            if log_verbose:
                print(f"* {repr(tm)}")
            collected.append(tm)
        except ValueError as e:
            errors.append(f"Skipping page [{p['title']}]({confluence.to_url(p['_links']['webui'])}) because: {e}")

    return CollectionResult(collected, errors)


def collect_from_confluence(label: str, space_map: dict, batch_page_count: int = 100,
                            log_verbose: bool = False):
    confluence = configure_confluence()

    if log_verbose:
        print(f"Confluence: Searching pages by label `{label}` ..")
    found_pages = confluence.get_all_pages_by_label(label, start=0, limit=batch_page_count)
    print(f"Confluence: Found {len(found_pages)} pages.")

    # map confluence space to application-name or team-name,
    # example: space MR to MagicRecords (e.g. https://example.atlassian.net/wiki/spaces/MR/pages/3530358832)
    def map_space(space_name):
        return space_map.get(space_name, Subject.unmapped_space(space_name))

    return collect_threat_modelings(found_pages, map_space, confluence, log_verbose=log_verbose)


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


def parse_threat_modeling(page, confluence: Confluence):
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
    application_names = confluence.scrap_regex_from_page(page['id'], LABELED_APPLICATION_NAME_PATTERN)
    application_name = ""
    if len(application_names) > 0:
        application_name = re.sub(LABELED_APPLICATION_NAME, "", application_names[0]).strip()
    teams = confluence.scrap_regex_from_page(page['id'], LABELED_TEAM_PATTERN)
    team = ""
    if len(teams) > 0:
        team = re.sub(LABELED_TEAM, "", teams[0]).strip()

    return {'title': page['title'],
            'url': confluence.to_url(page['_links']['webui']),
            'date': tm_date,
            'space': space_name,
            'application_name': application_name,
            'team': team}


def to_threat_modeling(meta: dict, space_mapper_fn):
    return ScrapedThreatModeling(space_mapper_fn(meta['space']),
                                 meta['title'],
                                 meta['date'],
                                 links=[Link(title=meta['title'], url=meta['url'])],
                                 source_url=meta['url'])


def write_output_files(threat_modelings: List[ScrapedThreatModeling], out_path: Path, activity_name: str, log_verbose: bool = False):
    if log_verbose:
        print(f"Output: Writing files to path `{out_path}` ..")

    target_files = []
    for app, values in group_per_app(threat_modelings).items():
        target_file = write_yaml_file(out_path, app, values, activity_name, log_verbose)
        target_files.append(target_file)
    return target_files


def group_per_app(threat_modelings: List[ScrapedThreatModeling]):
    grouped = defaultdict(list)
    for t in threat_modelings:
        grouped[t.subject].append(t)

    return grouped


def write_yaml_file(folder: Path, subject: Subject, threat_modelings: List[ThreatModeling],
                    activity_name: str, log_verbose: bool = False):
    output_filename = f"{folder}/{subject.team_name}/{subject.application_name}_application.yaml"
    log_prefix = "File I/O: "

    if log_verbose:
        print(f"{log_prefix}Preparing folder/file `{output_filename}` for {len(threat_modelings)} modeling(s) ..")

    target_dir = f"{folder}/{subject.team_name}"
    os.makedirs(target_dir, exist_ok=True)

    model = to_model(threat_modelings, subject)

    if log_verbose:
        print(f"{log_prefix} Writing file `{output_filename}` ..")
    to_yaml_file(output_filename, model)
    prepend_header(output_filename, YAML_HEADER_AUTOGENERATED_BY)

    if log_verbose:
        print(f"Replacing `threat_modeling` with `{activity_name}` ..")
    with open(output_filename, 'r') as file:
        filedata = file.read()
    filedata = filedata.replace("threat_modeling", activity_name)
    with open(output_filename, 'w') as file:
        file.write(filedata)
    return target_dir

def gitPullAndGetOrigin(folder: Path, log_verbose: bool = False):
    # try:
        if folder.exists():
            shutil.rmtree(folder)

        hostname = os.getenv("GIT_HUB_HOSTNAME")
        if hostname == None:
            hostname = "github.com"
        owner = os.getenv("GIT_HUB_OWNER")
        repo = os.getenv("GIT_HUB_REPO")
        if os.getenv("GIT_HUB_ACCESS_TOKEN") != "":
            token = os.getenv("GIT_HUB_ACCESS_TOKEN")
            auth = Auth.Token(os.getenv("GIT_HUB_ACCESS_TOKEN"))
            g = Github(base_url=f"https://{hostname}/api/v3", auth=auth)
            repo_url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"
            repo = Repo.clone_from(repo_url, folder)

        if os.getenv("GIT_HUB_USERNAME") != None:
            auth = Auth.Login(os.getenv("GIT_HUB_USERNAME"), os.getenv("GIT_HUB_PASSWORD"))
            g = Github(base_url=f"https://{hostname}/api/v3", auth=auth)
            login = g.get_user().login
            print(login)

        if (os.getenv("GIT_HUB_APP_ID") is not None) and (os.getenv("GIT_HUB_APP_ID") != ""):
            id = int(os.getenv("GIT_HUB_APP_ID"))
            private_key = base64.b64decode(os.getenv("GIT_HUB_APP_PRIVATE_KEY_BASE64"))
            token = getGitAppToken(id, repo, owner, private_key)
            repo_url = f"https://x-access-token:{token}@{hostname}/{owner}/{repo}.git"


        return repo
    # except:
    #     print('Some error occured while pushing the code to ' + repo_url)

def getGitAppToken(id: str, repo: str, owner: str, private_key: str):
    app = GithubIntegration(id, private_key)
    installation = app.get_installation(owner, repo)
    token = app.get_access_token(installation.id)
    return token

def to_model(modelings, subject):
    components = [ThreatModelingComponent(date=m.date, title=m.title, links=m.links) for m in modelings]
    c = ThreatModeling(components=components)
    # TODO make the attribute-name of Activities configurable,
    #  so organisations can use individual terms for `threat_modeling`
    a = Activities(threat_modeling=c)
    s = Settings(team=subject.team_name, application=subject.application_name)
    model = DSOMMapplication(settings=s, activities=a)
    return model


def prepend_header(filename, comment_line):
    with open(filename, 'r') as original:
        data = original.read()
    with open(filename, 'w') as modified:
        modified.write(f"# {comment_line}\n" + data)


def main(scraping_config: Path, out_path: Path = Path('/tmp/collector-confluence'), debug: bool = True):
    require_file(scraping_config)
    config = load_config(scraping_config)

    scrape_to_folder(scraping_config=config, out_path=out_path, log_verbose=debug)


if __name__ == "__main__":
    typer.run(main)
