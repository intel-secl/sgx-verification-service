module intel/isecl/sqvs/v4

go 1.18

require (
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.6.1
	gopkg.in/restruct.v1 v1.0.0-20190323193435-3c2afb705f3c
	gopkg.in/yaml.v2 v2.4.0
	intel/isecl/lib/clients/v4 v4.2.0
	intel/isecl/lib/common/v4 v4.2.0
)

require (
	github.com/Waterdrips/jwt-go v3.2.1-0.20200915121943-f6506928b72e+incompatible // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.0.0-20191026070338-33540a1f6037 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

replace (
	intel/isecl/lib/clients/v4 => github.com/intel-secl/clients/v4 v4.2.0-Beta
	intel/isecl/lib/common/v4 => github.com/intel-secl/common/v4 v4.2.0-Beta
)
