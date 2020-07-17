module intel/isecl/sqvs

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/jinzhu/gorm v1.9.12
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.5.0
	github.com/stretchr/testify v1.5.1
	golang.org/x/crypto master
	golang.org/x/time master
	gopkg.in/restruct.v1 v1.0.0-20190323193435-3c2afb705f3c
	gopkg.in/yaml.v2 v2.2.8
	intel/isecl/lib/clients/v2 v2.2.0
	intel/isecl/lib/common/v2 v2.2.0
)

replace intel/isecl/lib/common/v2 => github.com/intel-secl/common/v2 v2.2.0
replace intel/isecl/lib/clients/v2 => github.com/intel-secl/clients/v2 v2.2.0
