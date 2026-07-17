# PathTriage Prototype

The `pathtriage` Python package implements the CLI (`scan`, `discover`, `rank`,
`detail`) that operates on the IAM attack graph.

## Layout
pathtriage/
├── cli/main.py           argparse dispatcher for the four commands
├── enumerators/
│   ├── aws.py            live IAM enumeration via boto3
│   └── fixture.py        offline inventory loader (JSON)
├── graph/builder.py      NetworkX DiGraph construction from inventory
├── discovery/bfs.py      BFS-based path enumeration from user nodes
├── scoring/
│   ├── rubric.py         v1 rubric implementation
│   └── rubric_v1_spec.md v1 weights + calibration status
└── fixtures/
└── aws_catalogue_sample.json  demo inventory modelling 3/8 verified paths

## Usage — live AWS

```bash
pathtriage scan     --provider aws --profile pathtriage-admin
pathtriage discover --provider aws --profile pathtriage-admin --output paths.json
pathtriage rank     --provider aws --profile pathtriage-admin --output scored.json --limit 10
pathtriage detail   --provider aws --profile pathtriage-admin --rank 1
```

## Usage — offline fixture (for demo / CI)

```bash
pathtriage discover --fixture pathtriage/fixtures/aws_catalogue_sample.json
pathtriage rank     --fixture pathtriage/fixtures/aws_catalogue_sample.json --limit 5
pathtriage detail   --fixture pathtriage/fixtures/aws_catalogue_sample.json --rank 1
```

## Tests

```bash
pytest tests/ -v
```

Coverage target: 50%+ on core modules (`discovery`, `scoring`, `graph`,
`enumerators.fixture`). Live AWS enumeration is not unit-tested; it is
integration-verified against the deployed attack labs (see `attacks/*/`).
