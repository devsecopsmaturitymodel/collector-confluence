# YAML

We use YAML for storing and transmitting the collected information.

## Validation against a schema
A custom YAML/JSON schema can be generated from example data [quicktype.io - Instantly parse JSON in any language](https://app.quicktype.io/).
The YAML schema is validated and enforced by the collector executable with the [pyKwalify - YAML/JSON validation library](https://github.com/Grokzen/pykwalify).

## Model Generation
We can use [koxudaxi/datamodel-code-generator](https://github.com/koxudaxi/datamodel-code-generator) (MIT): Pydantic model and dataclasses.dataclass generator for easy conversion of JSON, OpenAPI, JSON Schema, and YAML data sources.
It is sponsored by JetBrains and used by many OSS projects by big IT companies like IBM, Netflix, AWS and DataDog.
It can also generate models from a URL schema definition. See [Advanced Uses](https://github.com/koxudaxi/datamodel-code-generator?tab=readme-ov-file#advanced-uses) example:
```shell
$ datamodel-codegen --url https://<INPUT FILE URL> --output model.py
```

### Warning
Tried to use [statham](https://github.com/jacksmith15/statham-schema) (MIT) to generate type-annotated models from JSON Schema documents.
It is a Python Model Parsing Library for JSON Schema. It includes tools for writing and generating extensible Python classes based on JSON Schema documents.

But, the model generation resulted in a known issue: [Infinite recursion when "$ref" at root. · Issue #92 · jacksmith15/statham-schema](https://github.com/jacksmith15/statham-schema/issues/92).

## YAML output, parsing and serialization
For basic and low-level YAML operations we could use [ruamel.yaml](https://pypi.org/project/ruamel.yaml/) (MIT) is a YAML 1.2 loader/dumper package for Python.
But when we want to dump a Pydantic model that was generated beforehand, then we should use [NowanIlfideme/pydantic-yaml](https://github.com/NowanIlfideme/pydantic-yaml): YAML support for Pydantic models.

Example output:
```yaml
# in folder <team-name>, filename <automated_threat-modeling>.yaml
apiVersion: v1
kind: application
settings:
  application: "MagicRecords" # e.g. from deployment
  team: "two towers"

ThreadModelling:
  components:
  - date: '2022-11-29'
    links:
    - title: Threat modeling MagicRecords
      url: https://example.atlassian.net/wiki/x/MABt0g
    title: Threat modeling MagicRecords
```

## See also

* Red Hat Developer (2020): [How to configure YAML schema to make editing files easier](https://developers.redhat.com/blog/2020/11/25/how-to-configure-yaml-schema-to-make-editing-files-easier#)
* [JSON Schema Store](https://www.schemastore.org/json/), example of schema-definitions for JSON and YAML
* [JSON Schema, Tools](https://json-schema.org/implementations#tools), validators, schema-generators and code-generators implemented in various languages
