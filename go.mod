module intel/isecl/sqvs/v4

require (
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.6.1
	gopkg.in/restruct.v1 v1.0.0-20190323193435-3c2afb705f3c
	gopkg.in/yaml.v2 v2.4.0
	intel/isecl/lib/clients/v4 v4.1.2
	intel/isecl/lib/common/v4 v4.1.2
)

replace (
	intel/isecl/lib/common/v4 => github.com/intel-secl/common/v4 v4.1.2
	intel/isecl/lib/clients/v4 => github.com/intel-secl/clients/v4 v4.1.2
)
