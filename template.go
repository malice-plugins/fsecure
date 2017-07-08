package main

const tpl = `#### F-Secure
{{- with .Results }}
| Infected      | Result      | Engine      | Updated      |
|:-------------:|:-----------:|:-----------:|:------------:|
| {{.Infected}} | {{.Engines.Aquarius}} | {{.Engine}} | {{.Updated}} |
{{ end -}}
`
