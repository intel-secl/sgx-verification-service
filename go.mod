module intel/isecl/sqvs/v5

require (
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/intel-secl/intel-secl/v5 v5.1.0
	github.com/onsi/ginkgo/v2 v2.6.1
	github.com/onsi/gomega v1.24.2
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.7.0
	gopkg.in/restruct.v1 v1.0.0-20190323193435-3c2afb705f3c
	gopkg.in/yaml.v3 v3.0.1
	intel/isecl/lib/clients/v5 v5.1.0
	intel/isecl/lib/common/v5 v5.1.0
)

replace (
	intel/isecl/lib/clients/v5 => github.com/intel-secl/clients/v5 v5.1.0
	intel/isecl/lib/common/v5 => github.com/intel-secl/common/v5 v5.1.0
)
