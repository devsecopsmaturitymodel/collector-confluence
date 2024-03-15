# Collector for Confluence
Collects meta-information about conducted threat modeling activities from Confluence wiki pages.

## Meta-information about a DateTitleLink
The generic type DateTitleLink can be used to assess DSOMM activities like Conduction ofThreat Modeling or Conduction of Pentests.

In the OWASP Foundation community article (Nov 2023) [Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process#threat-model-information),
lists following meta-information for a threat model:

> Information identifying the threat model typically includes the following:
>
> 1. Application Name: The name of the application examined.
> 2. Application Version: The version of the application examined.
> 3. Description: A high level description of the application.
> 4. Document Owner: The owner of the threat modeling document.
> 5. Participants: The participants involved in the threat modeling process for this application.
> 6. Reviewer: The reviewer(s) of the threat model.

However, for the purpose of metric collection for DSOMM we adjusted our information demand to:

1. **Application Name**: The name of the application examined.
2. **Team Name**: The name of the team that owns/maintains the application.
3. **Title**: The title summarizing the scope or question of the threat modeling.
4. **Date**: The date when the threat modeling activity was conducted.
5. **Links**: The list of links to the _threat modeling document_ (main source) 
   and to supplementary reference material like:
   - recorded drawings or pictures from physical/virtual whiteboards (e.g. Miro boards)
   - resulting tickets (e.g. JIRA issues)

See also:

* Blog "Let's Talk About MedSec" (24 Apr 2022): [Threat Modeling Knowledge Bases and Templates](https://tmart234.github.io/threat-model-template/)
* GitHub Repository from [Izar Tarandach](https://owasp.org/www-board-candidates/2023/izar_tarandach): [izar/pytm](https://github.com/izar/pytm) :
  A Pythonic framework for threat modeling

## Quickstart
Prerequisite: Python 3 must be installed.

### Installation
Steps:

1. Clone the repository source-code
2. Make sure all required packages are installed

Example:
```shell
git clone https://github.com/devsecopsmaturitymodel/collector-confluence.git
cd collector-confluence
pip install -r requirements.txt
```

### Configuration
We recommend to prepare a `.env` file and specify the confluence URL, account and credentials there.

Example file `.env` (with anonymized data):
```
CONFLUENCE_URL='https://example.atlassian.net/wiki'  # change to your Confluence cloud URL
CONFLUENCE_LOGIN='username@example.com'  # change to your account name/email 
CONFLUENCE_PASSWORD=''  # fill in your API token from your Atlassian profile
```
However, you can also set those environment-variables separately.
In case both are present, the `.env` file and environment-variables, then the environment-variables are finally used. 

### Run
Run the Python executable script (e.g. on Linux and macOS):
```shell
./confluence_collector.py
```
