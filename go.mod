module intel/isecl/sqvs/v3

require (
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/jinzhu/gorm v1.9.12
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.5.0
	github.com/stretchr/testify v1.5.1
	gopkg.in/restruct.v1 v1.0.0-20190323193435-3c2afb705f3c
	gopkg.in/yaml.v2 v2.2.8
	intel/isecl/lib/clients/v3 v3.3.0
	intel/isecl/lib/common/v3 v3.3.0
)

replace intel/isecl/lib/common/v3 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v3 v3.3/develop

replace intel/isecl/lib/clients/v3 => gitlab.devtools.intel.com/sst/isecl/lib/clients.git/v3 v3.3/develop
