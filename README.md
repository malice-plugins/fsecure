# malice-fsecure

[![Circle CI](https://circleci.com/gh/malice-plugins/fsecure.png?style=shield)](https://circleci.com/gh/malice-plugins/fsecure) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/fsecure.svg)](https://hub.docker.com/r/malice/fsecure/) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/fsecure.svg)](https://hub.docker.com/r/malice/fsecure/) [![Docker Image](https://img.shields.io/badge/docker%20image-920MB-blue.svg)](https://hub.docker.com/r/malice/fsecure/)

> Malice [F-Secure](https://www.f-secure.com/en/web/business_global/downloads/linux-security/latest) AntiVirus Plugin

---

### Dependencies

- [ubuntu:bionic (_84.1 MB_\)](https://hub.docker.com/_/ubuntu/)

## Installation

1. Install [Docker](https://www.docker.io/).
2. Download [trusted build](https://hub.docker.com/r/malice/fsecure/) from public [DockerHub](https://hub.docker.com): `docker pull malice/fsecure`

## Usage

```
docker run --rm malice/fsecure EICAR
```

### Or link your own malware folder:

```bash
$ docker run --rm -v /path/to/malware:/malware:ro malice/fsecure FILE

Usage: f-secure [OPTIONS] COMMAND [arg...]

Malice F-Secure AntiVirus Plugin

Version: v0.1.0, BuildTime: 20180903

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --verbose, -V          verbose output
  --elasticsearch value  elasticsearch url for Malice to store results [$MALICE_ELASTICSEARCH_URL]
  --table, -t            output as Markdown table
  --callback, -c         POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x            proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --timeout value        malice plugin timeout (in seconds) (default: 60) [$MALICE_TIMEOUT]
  --help, -h             show help
  --version, -v          print the version

Commands:
  update  Update virus definitions
  web     Create a F-Secure scan web service
  help    Shows a list of commands or help for one command

Run 'f-secure COMMAND --help' for more information on a command.
```

This will output to stdout and POST to malice results API webhook endpoint.

## Sample Output

### [JSON](https://github.com/malice-plugins/fsecure/blob/master/docs/results.json)

```json
{
  "f-secure": {
    "infected": true,
    "results": {
      "fse": "EICAR_Test_File",
      "aquarius": "EICAR-Test-File (not a virus)"
    },
    "engine": "11.00 build 79",
    "database": "2016-09-19_01",
    "updated": "20170122"
  }
}
```

### [Markdown](https://github.com/malice-plugins/fsecure/blob/master/docs/SAMPLE.md)

---

#### F-Secure

| Infected | Result                        | Engine         | Updated  |
| -------- | ----------------------------- | -------------- | -------- |
| true     | EICAR-Test-File (not a virus) | 11.00 build 79 | 20170122 |

---

## Documentation

- [To write results to ElasticSearch](https://github.com/malice-plugins/fsecure/blob/master/docs/elasticsearch.md)
- [To create a fsecure scan micro-service](https://github.com/malice-plugins/fsecure/blob/master/docs/web.md)
- [To post results to a webhook](https://github.com/malice-plugins/fsecure/blob/master/docs/callback.md)
- [To update the AV definitions](https://github.com/malice-plugins/fsecure/blob/master/docs/update.md)

## Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/malice-plugins/fsecure/issues/new).

## CHANGELOG

See [`CHANGELOG.md`](https://github.com/malice-plugins/fsecure/blob/master/sophos/CHANGELOG.md)

## Contributing

[See all contributors on GitHub](https://github.com/malice-plugins/fsecure/graphs/contributors).

Please update the [CHANGELOG.md](https://github.com/malice-plugins/fsecure/blob/master/sophos/CHANGELOG.md) and submit a [Pull Request on GitHub](https://help.github.com/articles/using-pull-requests/).

## License

MIT Copyright (c) 2016 **blacktop**
