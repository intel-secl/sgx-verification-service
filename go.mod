module intel/isecl/sqvs/v5

require (
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.5.0
	github.com/stretchr/testify v1.5.1
	gopkg.in/restruct.v1 v1.0.0-20190323193435-3c2afb705f3c
	gopkg.in/yaml.v2 v2.4.0
	intel/isecl/lib/clients/v5 v5.0.0
	intel/isecl/lib/common/v5 v5.0.0
)

replace (
	intel/isecl/lib/common/v5 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v5 v5.0/develop
	intel/isecl/lib/clients/v5 => gitlab.devtools.intel.com/sst/isecl/lib/clients.git/v5 v5.0/develop
)