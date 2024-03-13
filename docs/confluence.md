# Atlassian Confluence

## REST API
We use the Atlassian Confluence REST API to search and access wiki pages. We want to:
* find pages by a specific label (optionally filter by a specific space)
* access each page to read and extract information from title and body
* optionally: read additional page properties (e.g. date of creation, author, owner, assigned wiki-space, last modified date)
* optionally: mark page as processed (e.g. by a specific property)

See Atlassian Developer Guide: [Confluence REST API examples: Read content, and expand the body](https://developer.atlassian.com/server/confluence/confluence-rest-api-examples/#read-content--and-expand-the-body)

## Libraries
A convenient library in Python is the [Atlassian Python REST API wrapper ](https://github.com/atlassian-api/atlassian-python-api/) to access and scrape the wiki pages.
It supports:
* search pages by label
* regex-extraction from body

See [examples](https://github.com/atlassian-api/atlassian-python-api/tree/master/examples/confluence).
WARNING: Instead of the project's MIT license this package is under "Apache-2.0 license" which is very similar and frequently used in OSS projects.

Alternatives with MIT license are:
* [pycontribs/confluence: Confluence Python API](https://github.com/pycontribs/confluence), which seems unmaintained since 6 years and does not support search by label
