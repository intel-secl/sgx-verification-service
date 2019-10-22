# Certificate Management Service Dependency Report 2/20/19

```console
go list -m -u -f '{{ if not .Indirect }} {{ .Path }} {{.Version}} {{ if .Update}} Update Available {{.Update.Version}} {{end}} {{end}}'  all
```


# [Gorilla Toolkit](https://whitelisttool.amr.corp.intel.com/view.php?id=6177)  <span style="color:green">**WHITELISTED**</span>

## Source URLs
1. github.com/gorilla/mux v1.7.0  
2. github.com/gorilla/handlers v1.4.0

## License

**BSD 3-Clause "New or "Revised" License**

*A permissive license similar to the BSD 2-Clause License, but with a 3rd clause that prohibits others from using the name of the project or its contributors to promote derived products without written consent.*

# [Gorm](https://whitelisttool.amr.corp.intel.com/view.php?id=8989) <span style="color:green">**WHITELISTED**</span>

## Source URLs
1. github.com/jinzhu/gorm

## License

**MIT License**

*A short and simple permissive license with conditions only requiring preservation of copyright and license notices. Licensed works, modifications, and larger works may be distributed under different terms and without source code.*

# [Logrus](https://whitelisttool.amr.corp.intel.com/view.php?id=8145) <span style="color:gold">**CONDITIONAL**

## Source URLs
1. https://whitelisttool.amr.corp.intel.com/view.php?id=8145

## License

**MIT License**

*A short and simple permissive license with conditions only requiring preservation of copyright and license notices. Licensed works, modifications, and larger works may be distributed under different terms and without source code.*


# [Golang Crypto](https://whitelisttool.amr.corp.intel.com/view.php?id=8975)  <span style="color:green">**WHITELISTED**</span>

## Source URLs
1. [godoc.org/golang.org/x/crypto (Official golang package)](https://github.com/golang/crypto/)

## License

**Golang License**

*BSD-style + patent grant, same license as Golang itself*

# [Go Yaml](https://whitelisttool.amr.corp.intel.com/view.php?id=5396) **EXEMPT**

Part of Canonical's juju project

## Source URLs
1. https://github.com/go-yaml/yaml
   
## License

1. **Apache License Version 2.0**

2. **MIT License**

Go code licensed under Apache Version 2.0
Ported code from libyaml retains original license under original MIT license

# [Testify](https://whitelisttool.amr.corp.intel.com/view.php?id=8963) <span style="color:green">**WHITELISTED**</span> (Unit Test Only Dependency)

## Source URLs

1. github.com/stretchr/testify v1.3.0  

## License

**MIT License**

*A short and simple permissive license with conditions only requiring preservation of copyright and license notices. Licensed works, modifications, and larger works may be distributed under different terms and without source code.*


